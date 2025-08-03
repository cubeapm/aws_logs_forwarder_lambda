# AWS Logs Forwarder Lambda

AWS Lambda function that processes ALB, ELB, and WAF logs from S3 and forwards them to a log ingestion endpoint in JSON Lines format.

## Features

- **Multi-format support**: ALB access logs, ELB connection logs, and WAF logs
- **Automatic detection**: Log type detection from S3 key patterns
- **Retry logic**: HTTP requests with exponential backoff
- **Environment metadata**: Optional `cube.environment` field support

## Environment Variables

- `LOG_ENDPOINT` - **Required** log ingestion endpoint URL
- `CUBE_ENVIRONMENT` - Optional environment identifier (e.g., "production", "staging")
- `MAX_RETRIES` - Retry attempts (default: 3)
- `REQUEST_TIMEOUT` - HTTP timeout in seconds (default: 30)

## Quick Deploy

```bash
# Create deployment package
./create_deployment_package.sh

# Upload lambda-deployment.zip to AWS Lambda
```

## Lambda Configuration

- **Runtime**: Python 3.9+
- **Handler**: `lambda_function.lambda_handler`
- **Memory**: 512 MB
- **Timeout**: 5 minutes
- **Trigger**: S3 event on `.log` or `.gz` files

## Required IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "s3:GetObject"
      ],
      "Resource": "*"
    }
  ]
}
```
