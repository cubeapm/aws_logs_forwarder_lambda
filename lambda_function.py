"""
AWS Lambda Log Forwarder for ALB, WAF, and NLB Logs

Processes AWS S3 log files and forwards them to CubeAPM.
"""

import boto3
import gzip
import os
import json
import urllib.parse
import urllib.request
import urllib.error
import socket
import time
import random
import logging
from typing import Dict, List, Optional, Any

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

def detect_log_type(s3_key: str) -> str:
  """Detect log type from S3 key"""
  key_lower = s3_key.lower()
  if 'waf' in key_lower or 'webacllog' in key_lower:
    return "waf"
  
  if 'connectionlogs' in key_lower or 'conn_log' in key_lower:
    return "elb_connection"
  
  if 'elasticloadbalancing' in key_lower and '_net.' in key_lower:
    return "nlb"
  
  if 'alb' in key_lower or 'elasticloadbalancing' in key_lower or 'elb' in key_lower:
    return "elb_access"
  
  return "unknown"

def download_and_decompress(bucket: str, key: str) -> Optional[str]:
  """Download and decompress S3 object"""
  try:
    response = s3_client.get_object(Bucket=bucket, Key=key)
    return gzip.decompress(response['Body'].read()).decode('utf-8')
  except Exception as e:
    logger.error(f"Failed to download/decompress s3://{bucket}/{key}: {e}")
    return None

def ship_logs(log_entries: List[str], file_path: str) -> bool:
  """Ship logs to CubeAPM endpoint - expects JSON lines format"""
  if not log_entries:
    logger.info("No log entries to ship")
    return True
  
  try:
    jsonlines_payload = '\n'.join(log_entries) + '\n'
    gzipped_data = gzip.compress(jsonlines_payload.encode('utf-8'))
    
    headers = {
      'Content-Type': 'application/x-ndjson',
      'Content-Encoding': 'gzip',
      'Cube-Stream-Fields': os.environ.get('CUBE_STREAM_FIELDS', 'event.domain'),
      'Cube-Time-Field': 'timestamp'
    }
    extra_fields = os.environ.get('CUBE_EXTRA_FIELDS', '')
    if extra_fields:
      headers['Cube-Extra-Fields'] = extra_fields  # key1:value1,key2:value2

    logger.info(f"Shipping {len(log_entries)} log entries (compressed size: {len(gzipped_data)} bytes) from {file_path}")
    return post_with_retry(gzipped_data, headers, file_path)
    
  except Exception as e:
    logger.error(f"Failed to prepare logs for shipping: {e}. File: {file_path}")
    return False

def post_with_retry(payload: bytes, headers: Dict[str, str], file_path: str) -> bool:
  """Post data with retry logic using urllib"""
  attempt = 0
  while attempt < MAX_RETRIES:
    try:
      request = urllib.request.Request(
        LOG_ENDPOINT,
        data=payload,
        headers=headers,
        method='POST'
      )
      
      with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
        status_code = response.status
        if 200 <= status_code < 300:
          logger.info(f"Successfully shipped logs (status: {status_code}) from {file_path}")
          return True
        elif status_code in (429, 500, 502, 503, 504):
          # Retryable errors
          wait_time = BASE_DELAY * (2 ** attempt) + random.uniform(0, 0.5)
          logger.warning(f"Retryable error {status_code} for {file_path}, retrying in {wait_time:.2f}s (attempt {attempt + 1}/{MAX_RETRIES})")
          time.sleep(wait_time)
          attempt += 1
        else:
          # Non-retryable errors
          response_text = response.read().decode('utf-8')
          logger.error(f"Non-retryable error {status_code} for {file_path}: {response_text}")
          return False
          
    except urllib.error.HTTPError as e:
      # HTTP errors (4xx, 5xx)
      status_code = e.code
      if status_code in (429, 500, 502, 503, 504):
        # Retryable HTTP errors
        wait_time = BASE_DELAY * (2 ** attempt) + random.uniform(0, 0.5)
        logger.warning(f"Retryable HTTP error {status_code} for {file_path}, retrying in {wait_time:.2f}s (attempt {attempt + 1}/{MAX_RETRIES})")
        time.sleep(wait_time)
        attempt += 1
      else:
        # Non-retryable HTTP errors
        error_text = e.read().decode('utf-8') if hasattr(e, 'read') else str(e)
        logger.error(f"Non-retryable HTTP error {status_code} for {file_path}: {error_text}")
        return False
        
    except (urllib.error.URLError, socket.timeout, OSError) as e:
      # Network errors, timeouts, connection issues
      wait_time = BASE_DELAY * (2 ** attempt) + random.uniform(0, 0.5)
      logger.warning(f"Network error for {file_path}: {e}, retrying in {wait_time:.2f}s (attempt {attempt + 1}/{MAX_RETRIES})")
      time.sleep(wait_time)
      attempt += 1
  
  logger.error(f"Failed to ship logs after {MAX_RETRIES} attempts for {file_path}")
  return False

# WAF Log Processing
def flatten_dict(obj: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
  """Flatten a nested dictionary into dot-notation keys"""
  result = {}
  
  for key, value in obj.items():
    new_key = f"{parent_key}{sep}{key}" if parent_key else key
    
    if isinstance(value, dict):
      result.update(flatten_dict(value, new_key, sep=sep))
    elif isinstance(value, list):
      if len(value) == 0:
        result[new_key] = ''
      elif (isinstance(value[0], dict) and len(value[0]) == 2 and 
            'name' in value[0] and 'value' in value[0]):
        # Special case: array of name/value pairs (like headers)
        for item in value:
          if isinstance(item, dict) and 'name' in item and 'value' in item:
            header_name = item['name']
            header_value = item['value']
            result[f"{new_key}.{header_name}"] = header_value
      elif isinstance(value[0], dict):
        # Array of objects - flatten each with index
        for i, item in enumerate(value):
          if isinstance(item, dict):
            result.update(flatten_dict(item, f"{new_key}.{i}", sep=sep))
          else:
            result[f"{new_key}.{i}"] = item
      else:
        # Array of primitives - join as comma-separated string
        result[new_key] = ','.join(str(v) for v in value) if value else ''
    else:
      result[new_key] = value
  
  return result

def process_waf_logs(content: str, file_path: str) -> List[str]:
  """Process WAF logs - returns JSON lines"""
  log_entries = []
  lines = content.strip().split('\n')
  
  logger.info(f"Processing {len(lines)} lines from WAF file: {file_path}")
  
  for line_num, line in enumerate(lines, 1):
    try:
      waf_log = json.loads(line.strip())
      flattened_waf = flatten_dict(waf_log)
      flattened_waf["event.domain"] = "aws.waf"
      if CUBE_ENVIRONMENT:
        flattened_waf[CUBE_ENVIRONMENT_KEY] = CUBE_ENVIRONMENT
      
      log_entries.append(json.dumps(flattened_waf))
    except Exception as e:
      logger.warning(f"Failed to parse WAF log line {line_num}: {e}. File: {file_path}. Line: {line[:200]}...")
      continue
  
  return log_entries

def parse_log_line(line: str) -> List[str]:
  """Parse log line handling quoted fields properly"""
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

def process_elb_access_logs(content: str, file_path: str) -> List[str]:
  """Process ELB access logs - returns JSON lines"""
  log_entries = []
  lines = content.strip().split('\n')
  
  logger.info(f"Processing {len(lines)} lines from ELB access file: {file_path}")
  
  for line_num, line in enumerate(lines, 1):
    try:
      parts = parse_log_line(line.strip())
      
      if len(parts) < 30:
        logger.warning(f"Invalid ELB access log format - expected 30 fields, got {len(parts)} at line {line_num}. File: {file_path}")
        continue
      
      # Parse client and target endpoints
      client_parts = parts[3].split(':')
      target_parts = parts[4].split(':')
      
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
      
      # Convert to JSON string immediately
      log_entries.append(json.dumps(elb_log))
    except Exception as e:
      logger.warning(f"Failed to parse ELB access log line {line_num}: {e}. File: {file_path}. Line: {line[:200]}...")
      continue
  
  return log_entries

def process_elb_connection_logs(content: str, file_path: str) -> List[str]:
  """Process ELB connection logs - returns JSON lines"""
  log_entries = []
  lines = content.strip().split('\n')
  
  logger.info(f"Processing {len(lines)} lines from ELB connection file: {file_path}")
  
  for line_num, line in enumerate(lines, 1):
    try:
      parts = parse_log_line(line)
      
      if len(parts) < 12:
        logger.warning(f"Malformed ELB connection log line - insufficient fields: {len(parts)} at line {line_num}. File: {file_path}")
        continue
      
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
      
      # Convert to JSON string immediately
      log_entries.append(json.dumps(elb_log))
    except Exception as e:
      logger.warning(f"Failed to parse ELB connection log line {line_num}: {e}. File: {file_path}. Line: {line[:200]}...")
      continue
  
  return log_entries

def process_nlb_logs(content: str, file_path: str) -> List[str]:
  """Process NLB logs - returns JSON lines"""
  log_entries = []
  lines = content.strip().split('\n')
  
  logger.info(f"Processing {len(lines)} lines from NLB file: {file_path}")
  
  for line_num, line in enumerate(lines, 1):
    try:
      parts = parse_log_line(line)
      
      if len(parts) < 21:
        logger.warning(f"Invalid NLB log format - expected 21 fields, got {len(parts)} at line {line_num}. File: {file_path}")
        continue
      
      # Parse client and destination endpoints
      client_parts = parts[5].split(':')
      destination_parts = parts[6].split(':')
      
      nlb_log = {
        "type": parts[0],
        "version": parts[1],
        "time": parts[2],
        "elb": parts[3],
        "listener": parts[4],
        "client_ip": client_parts[0],
        "client_port": client_parts[1] if len(client_parts) > 1 else "-",
        "destination_ip": destination_parts[0],
        "destination_port": destination_parts[1] if len(destination_parts) > 1 else "-",
        "connection_time": parts[7],
        "tls_handshake_time": parts[8],
        "received_bytes": parts[9],
        "sent_bytes": parts[10],
        "incoming_tls_alert": parts[11],
        "chosen_cert_arn": parts[12],
        "chosen_cert_serial": parts[13],
        "tls_cipher": parts[14],
        "tls_protocol_version": parts[15],
        "tls_named_group": parts[16],
        "domain_name": parts[17],
        "alpn_fe_protocol": parts[18],
        "alpn_be_protocol": parts[19],
        "alpn_client_preference_list": parts[20],
        "tls_connection_creation_time": parts[21] if len(parts) > 21 else "-",
        "event.domain": "aws.nlb",
        CUBE_ENVIRONMENT_KEY: CUBE_ENVIRONMENT
      }
      
      # Add any additional fields if present
      for i in range(22, len(parts)):
        nlb_log[f"field_{i}"] = parts[i]
      
      # Convert to JSON string immediately
      log_entries.append(json.dumps(nlb_log))
    except Exception as e:
      logger.warning(f"Failed to parse NLB log line {line_num}: {e}. File: {file_path}. Line: {line[:200]}...")
      continue
  
  return log_entries

def lambda_handler(event, context):
  """Main Lambda handler"""
  results = []
  current_file_path = "unknown"  # Initialize for error handling
  
  try:
    for record in event['Records']:
      bucket = record['s3']['bucket']['name']
      key = urllib.parse.unquote_plus(record['s3']['object']['key'])
      file_path = f"s3://{bucket}/{key}"
      current_file_path = file_path
      
      logger.info(f"Processing log file: {file_path}")
      
      log_type = detect_log_type(key)
      logger.info(f"Detected log type: {log_type} for file: {file_path}")
      
      if log_type == "unknown":
        error_msg = f"Unknown log type for file {file_path}"
        logger.error(error_msg)
        results.append({
          'bucket': bucket,
          'key': key,
          'success': False,
          'processed_count': 0,
          'error_message': error_msg
        })
        continue
      
      # Download and decompress the file
      content = download_and_decompress(bucket, key)
      if content is None:
        results.append({
          'bucket': bucket,
          'key': key,
          'success': False,
          'processed_count': 0,
          'error_message': f"Failed to download file: {file_path}"
        })
        continue
      
      # Process logs based on detected type
      log_entries = []
      try:
        if log_type == "waf":
          log_entries = process_waf_logs(content, file_path)
        elif log_type == "elb_access":
          log_entries = process_elb_access_logs(content, file_path)
        elif log_type == "elb_connection":
          log_entries = process_elb_connection_logs(content, file_path)
        elif log_type == "nlb":
          log_entries = process_nlb_logs(content, file_path)
      except Exception as e:
        error_msg = f"Error processing {log_type} logs from {file_path}: {e}"
        logger.error(error_msg)
        results.append({
          'bucket': bucket,
          'key': key,
          'success': False,
          'processed_count': 0,
          'error_message': error_msg
        })
        continue
      
      # Ship the logs
      if log_entries:
        success = ship_logs(log_entries, file_path)
        if success:
          logger.info(f"Successfully processed {len(log_entries)} log entries from {file_path}")
          results.append({
            'bucket': bucket,
            'key': key,
            'success': True,
            'processed_count': len(log_entries),
            'error_message': None
          })
        else:
          results.append({
            'bucket': bucket,
            'key': key,
            'success': False,
            'processed_count': len(log_entries),
            'error_message': f"Failed to ship logs from {file_path}"
          })
      else:
        logger.warning(f"No valid log entries found in {file_path}")
        results.append({
          'bucket': bucket,
          'key': key,
          'success': True,
          'processed_count': 0,
          'error_message': None
        })
  
  except Exception as e:
    logger.error(f"Critical error in lambda handler while processing {current_file_path}: {e}")
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