"""
AWS Lambda Log Forwarder for ALB and WAF Logs

Processes AWS S3 log files and forwards them to CubeAPM.
"""

import boto3
import gzip
import os
import json
import urllib.parse
import requests
import time
import random
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# AWS clients
s3_client = boto3.client('s3')

# Configuration
LOG_ENDPOINT = os.environ.get("LOG_ENDPOINT")
if not LOG_ENDPOINT:
  raise ValueError("LOG_ENDPOINT environment variable is required")

CUBE_ENVIRONMENT_KEY = os.environ.get("CUBE_ENVIRONMENT_KEY", "cube.environment")
CUBE_ENVIRONMENT = os.environ.get("CUBE_ENVIRONMENT")
MAX_RETRIES = int(os.environ.get("MAX_RETRIES", "3"))
BASE_DELAY = float(os.environ.get("RETRY_BASE_DELAY", "1.0"))
REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "30"))

@dataclass
class LogProcessingResult:
  success: bool
  processed_count: int
  error_message: Optional[str] = None

class LogTypeDetector:
  @staticmethod
  def detect_log_type_from_key(s3_key: str) -> str:
    key_lower = s3_key.lower()
    
    # WAF logs typically have 'waf' in the path/filename
    if 'waf' in key_lower or 'webacllog' in key_lower:
      return "waf"
    
    # ELB Connection logs have 'connectionlogs' in path or 'conn_log' prefix
    if 'connectionlogs' in key_lower or 'conn_log' in key_lower:
      return "elb_connection"
    
    # ELB Access logs have 'elasticloadbalancing' but not connection indicators
    if 'alb' in key_lower or 'elasticloadbalancing' in key_lower or 'elb' in key_lower:
      return "elb_access"
    
    return "unknown"

class WAFLogProcessor:
  @staticmethod
  def _flatten_dict(obj: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
    """
    Flatten a nested dictionary into dot-notation keys.
    Special handling for name/value pairs like headers (Go-style approach).
    
    Args:
      obj: Dictionary to flatten
      parent_key: Current parent key for recursion
      sep: Separator for nested keys
    
    Returns:
      Flattened dictionary with dot-notation keys
    """
    items = []
    
    for key, value in obj.items():
      new_key = f"{parent_key}{sep}{key}" if parent_key else key
      
      if isinstance(value, dict):
        # Recursively flatten nested dictionaries
        items.extend(WAFLogProcessor._flatten_dict(value, new_key, sep=sep).items())
      elif isinstance(value, list):
        if len(value) == 0:
          # Empty array
          items.append((new_key, ''))
        elif (isinstance(value[0], dict) and len(value[0]) == 2 and 
              'name' in value[0] and 'value' in value[0]):
          # Special case: array of name/value pairs (like headers)
          # Convert to direct field access: headers.Host instead of headers.0.name
          for item in value:
            if isinstance(item, dict) and 'name' in item and 'value' in item:
              header_name = item['name']
              header_value = item['value']
              items.append((f"{new_key}.{header_name}", header_value))
        elif isinstance(value[0], dict):
          # Array of objects - flatten each with index
          for i, item in enumerate(value):
            if isinstance(item, dict):
              items.extend(WAFLogProcessor._flatten_dict(item, f"{new_key}.{i}", sep=sep).items())
            else:
              items.append((f"{new_key}.{i}", item))
        else:
          # Array of primitives - join as comma-separated string
          items.append((new_key, ','.join(str(v) for v in value) if value else ''))
      else:
        # Primitive value
        items.append((new_key, value))
    
    return dict(items)

  # WAF Logs (JSON format):
  # {"timestamp":1752758462381,"formatVersion":1,"webaclId":"arn:aws:wafv2:eu-west-2:971937583728:regional/webacl/CreatedByALB-lb-01/102e3f7b-6149-4113-ae99-72f52dfb4fd8","terminatingRuleId":"Default_Action","terminatingRuleType":"REGULAR","action":"ALLOW","httpRequest":{"clientIp":"103.100.219.14","country":"IN","uri":"/","httpMethod":"GET"}}
  @staticmethod
  def parse_waf_log(line: str) -> Optional[Dict[str, Any]]:
    try:
      waf_log = json.loads(line.strip())      
      flattened_waf = WAFLogProcessor._flatten_dict(waf_log)
      flattened_waf["event.domain"] = "aws.waf"
      if CUBE_ENVIRONMENT:
        flattened_waf[CUBE_ENVIRONMENT_KEY] = CUBE_ENVIRONMENT
      
      return flattened_waf
      
    except Exception as e:
      logger.error(f"Unexpected error parsing WAF log: {e}")
      return None

class ELBAccessLogProcessor:
  @staticmethod
  def _parse_alb_line(line: str) -> List[str]:
    """
    Parse ALB log line handling quoted fields properly.
    ALB logs can have quoted fields that contain spaces.
    """
    parts = []
    current_part = ""
    in_quotes = False
    i = 0
    
    while i < len(line):
      char = line[i]
      
      if char == '"':
        in_quotes = not in_quotes
      elif char == ' ' and not in_quotes:
        if current_part:
          parts.append(current_part)
          current_part = ""
      else:
        current_part += char
      
      i += 1
    
    # Add the last part
    if current_part:
      parts.append(current_part)
    
    return parts

  # ELB Access Logs (space-separated format, exactly 30 fields):
  # http 2025-07-18T12:25:31.520793Z app/lb-01/e3610968cb568663 152.32.168.24:30040 172.31.38.249:3000 0.008 0.001 0.000 404 404 62 395 "GET http://13.42.111.243:80/version HTTP/1.1" "-" - - arn:aws:elasticloadbalancing:eu-west-2:971937583728:targetgroup/tg-01/f7453679acf18aae "Root=1-687a3d3b-0e279def7df7c8f739199dd3" "-" "-" 0 2025-07-18T12:25:31.511000Z "waf,forward" "-" "-" "172.31.38.249:3000" "404" "-" "-" TID_2e8432b67236ef4597489a4947734c97
  @staticmethod
  def parse_elb_access_log(line: str) -> Optional[Dict[str, Any]]:
    try:
      # Parse ALB log format with proper handling of quoted fields
      parts = ELBAccessLogProcessor._parse_alb_line(line.strip())
      
      # Only support the new 30-field format
      if len(parts) < 30:
        logger.warning(f"Invalid ELB access log format - expected 30 fields, got {len(parts)}. Line: {line[:200]}...")
        return None
      
      # Parse client and target endpoints
      client_parts = parts[3].split(':')
      target_parts = parts[4].split(':')
      
      # New format ELB Access Log with all 30 fields
      elb_log = {
        "type": parts[0],
        "timestamp": parts[1],
        "elb": parts[2],
        "client_ip": client_parts[0],
        "client_port": client_parts[1],
        "target_ip": target_parts[0],
        "target_port": target_parts[1],
        "request_processing_time": parts[5],
        "target_processing_time": parts[6],
        "response_processing_time": parts[7],
        "elb_status_code": parts[8],
        "target_status_code": parts[9],
        "received_bytes": parts[10],
        "sent_bytes": parts[11],
        "request": parts[12],
        "user_agent": parts[13],
        "ssl_cipher": parts[14],
        "ssl_protocol": parts[15],
        "target_group_arn": parts[16],
        "trace_id": parts[17],
        "domain_name": parts[18],
        "chosen_cert_arn": parts[19],
        "matched_rule_priority": parts[20],
        "request_creation_time": parts[21],
        "actions_executed": parts[22],
        "redirect_url": parts[23],
        "error_reason": parts[24],
        "target_port_list": parts[25],
        "target_status_code_list": parts[26],
        "classification": parts[27],
        "classification_reason": parts[28],
        "tid": parts[29],
        "event.domain": "aws.elb.access",
        CUBE_ENVIRONMENT_KEY: CUBE_ENVIRONMENT
      }

      # Add any additional fields if present
      for i in range(30, len(parts)):
        elb_log[f"field_{i}"] = parts[i]
      
      return elb_log
    except Exception as e:
      logger.error(f"Unexpected error parsing ELB access log: {e}")
      return None

class ELBConnectionLogProcessor:
  # ELB Connection Logs (space-separated format, 12 fields):
  # 2025-07-18T12:51:25.299253Z 52.34.228.235 38910 80 - - - "-" - - - TID_3f9ddfa803beb546812b02872b46c30b
  @staticmethod
  def parse_elb_connection_log(line: str) -> Optional[Dict[str, Any]]:
    try:
      parts = ELBAccessLogProcessor._parse_alb_line(line.strip())
      
      if len(parts) < 12:
        logger.warning(f"Malformed ELB connection log line - insufficient fields: {len(parts)}")
        return None
      
      elb_log = {
        "timestamp": parts[0],
        "client_ip": parts[1],
        "client_port": parts[2],
        "target_port": parts[3],
        "connection_time": parts[4],
        "tls_handshake_time": parts[5],
        "received_bytes": parts[6],
        "sent_bytes": parts[7],
        "incoming_tls_alert": parts[8],
        "chosen_cipher": parts[9],
        "tls_protocol": parts[10],
        "trace_id": parts[11],
        "event.domain": "aws.elb.connection",
        CUBE_ENVIRONMENT_KEY: CUBE_ENVIRONMENT
      }
      
      # Add any additional fields if present
      for i in range(12, len(parts)):
        elb_log[f"field_{i}"] = parts[i]

      return elb_log
      
    except Exception as e:
      logger.error(f"Unexpected error parsing ELB connection log: {e}")
      return None

class LogShipper:
  def __init__(self, endpoint: str, max_retries: int = MAX_RETRIES, base_delay: float = BASE_DELAY):
    # Use clean endpoint, stream fields will be set via header
    self.endpoint = endpoint
    self.max_retries = max_retries
    self.base_delay = base_delay
  
  def ship_logs(self, log_entries: List[Dict[str, Any]]) -> bool:
    if not log_entries:
      logger.info("No log entries to ship")
      return True
    
    try:
      # Convert to JSON Lines format
      jsonlines = [json.dumps(entry) for entry in log_entries]
      jsonlines_payload = '\n'.join(jsonlines) + '\n'
      
      # Compress the payload
      gzipped_data = gzip.compress(jsonlines_payload.encode('utf-8'))
      
      headers = {
        'Content-Type': 'application/x-ndjson',
        'Content-Encoding': 'gzip',
        'Cube-Stream-Fields': 'event.domain',
        'Cube-Time-Field': 'timestamp'
      }
      
      logger.info(f"Shipping {len(log_entries)} log entries (compressed size: {len(gzipped_data)} bytes)")
      
      return self._post_with_retry(gzipped_data, headers)
      
    except Exception as e:
      logger.error(f"Failed to prepare logs for shipping: {e}")
      return False
  
  def _post_with_retry(self, payload: bytes, headers: Dict[str, str]) -> bool:
    attempt = 0
    while attempt < self.max_retries:
      try:
        response = requests.post(
          self.endpoint,
          data=payload,
          headers=headers,
          timeout=REQUEST_TIMEOUT
        )
        
        if 200 <= response.status_code < 300:
          logger.info(f"Successfully shipped logs (status: {response.status_code})")
          return True
        elif response.status_code in (429, 500, 502, 503, 504):
          # Retryable errors
          wait_time = self.base_delay * (2 ** attempt) + random.uniform(0, 0.5)
          logger.warning(f"Retryable error {response.status_code}, retrying in {wait_time:.2f}s (attempt {attempt + 1}/{self.max_retries})")
          time.sleep(wait_time)
          attempt += 1
        else:
          # Non-retryable errors
          logger.error(f"Non-retryable error {response.status_code}: {response.text}")
          return False
          
      except requests.exceptions.Timeout:
        wait_time = self.base_delay * (2 ** attempt) + random.uniform(0, 0.5)
        logger.warning(f"Request timeout, retrying in {wait_time:.2f}s (attempt {attempt + 1}/{self.max_retries})")
        time.sleep(wait_time)
        attempt += 1
      except requests.exceptions.RequestException as e:
        wait_time = self.base_delay * (2 ** attempt) + random.uniform(0, 0.5)
        logger.warning(f"Request exception: {e}, retrying in {wait_time:.2f}s (attempt {attempt + 1}/{self.max_retries})")
        time.sleep(wait_time)
        attempt += 1
    
    logger.error(f"Failed to ship logs after {self.max_retries} attempts")
    return False

class LogProcessor:
  def __init__(self):
    self.detector = LogTypeDetector()
    self.waf_processor = WAFLogProcessor()
    self.elb_access_processor = ELBAccessLogProcessor()
    self.elb_connection_processor = ELBConnectionLogProcessor()
    self.shipper = LogShipper(LOG_ENDPOINT)
  
  def process_log_file(self, bucket: str, key: str) -> LogProcessingResult:
    try:
      logger.info(f"Processing log file: s3://{bucket}/{key}")
      
      # Determine log type from S3 key (more efficient to do once per file)
      log_type = self.detector.detect_log_type_from_key(key)
      logger.info(f"Detected log type: {log_type} based on S3 key: {key}")
      
      # Download and decompress the file
      content = self._download_and_decompress(bucket, key)
      if content is None:
        return LogProcessingResult(success=False, processed_count=0, error_message="Failed to download file")
      
      # Process log lines
      log_entries = []
      lines = content.strip().split('\n')
      
      for line_num, line in enumerate(lines, 1):
        if not line.strip():
          continue
        
        try:
          parsed_entry = self._parse_log_line(line, log_type)
          if parsed_entry:
            log_entries.append(parsed_entry)
        except Exception as e:
          logger.warning(f"Failed to parse line {line_num}: {e}")
          continue
      
      # Ship the logs
      if log_entries:
        success = self.shipper.ship_logs(log_entries)
        if success:
          logger.info(f"Successfully processed {len(log_entries)} log entries from {key}")
          return LogProcessingResult(success=True, processed_count=len(log_entries))
        else:
          return LogProcessingResult(success=False, processed_count=len(log_entries), error_message="Failed to ship logs")
      else:
        logger.warning(f"No valid log entries found in {key}")
        return LogProcessingResult(success=True, processed_count=0)
        
    except Exception as e:
      logger.error(f"Unexpected error processing {key}: {e}")
      return LogProcessingResult(success=False, processed_count=0, error_message=str(e))
  
  def _download_and_decompress(self, bucket: str, key: str) -> Optional[str]:
    try:
      response = s3_client.get_object(Bucket=bucket, Key=key)
      content = gzip.decompress(response['Body'].read()).decode('utf-8')
      return content
    except Exception as e:
      logger.error(f"Failed to download/decompress s3://{bucket}/{key}: {e}")
      return None
  
  def _parse_log_line(self, line: str, log_type: str) -> Optional[Dict[str, Any]]:
    if log_type == "waf":
      return self.waf_processor.parse_waf_log(line)
    elif log_type == "elb_access":
      return self.elb_access_processor.parse_elb_access_log(line)
    elif log_type == "elb_connection":
      return self.elb_connection_processor.parse_elb_connection_log(line)
    else:
      logger.warning(f"Unknown log type '{log_type}' for S3 key - skipping line: {line[:100]}...")
      return None

def lambda_handler(event, context):
  processor = LogProcessor()
  results = []
  
  try:
    for record in event['Records']:
      bucket = record['s3']['bucket']['name']
      key = urllib.parse.unquote_plus(record['s3']['object']['key'])
      
      result = processor.process_log_file(bucket, key)
      results.append({
        'bucket': bucket,
        'key': key,
        'success': result.success,
        'processed_count': result.processed_count,
        'error_message': result.error_message
      })
  
  except Exception as e:
    logger.error(f"Critical error in lambda handler: {e}")
    raise
  
  # Log summary
  total_processed = sum(r['processed_count'] for r in results)
  successful_files = sum(1 for r in results if r['success'])
  
  logger.info(f"Processing complete: {successful_files}/{len(results)} files successful, {total_processed} total log entries processed")
  
  return {
    'statusCode': 200,
    'body': {
      'message': 'Log processing complete',
      'results': results,
      'summary': {
        'total_files': len(results),
        'successful_files': successful_files,
        'total_log_entries': total_processed
      }
    }
  } 