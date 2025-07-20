#!/bin/bash

# Create AWS Lambda deployment package for ALB Logs Forwarder

echo "Creating AWS Lambda deployment package for ALB Logs Forwarder..."

# Clean up any existing deployment files
echo "Cleaning up existing deployment files..."
rm -rf lambda-deployment.zip
rm -rf package/
mkdir -p package

# Install dependencies to package directory
echo "Installing Python dependencies..."
pip install -r requirements.txt -t package/

# Copy Lambda function code
echo "Copying Lambda function code..."
cp lambda_function.py package/

# Create the deployment package
echo "Creating deployment zip..."
cd package
zip -r ../lambda-deployment.zip . -x "*.pyc" "*__pycache__*" "*.DS_Store*"
cd ..

# Clean up package directory
rm -rf package/

# Check if zip was created successfully
if [ -f "lambda-deployment.zip" ]; then
    echo "✅ Deployment package created successfully: lambda-deployment.zip"
    echo "📦 Package size: $(du -h lambda-deployment.zip | cut -f1)"
    echo ""
    echo "🚀 You can now upload this zip file to AWS Lambda:"
    echo "   1. Go to AWS Lambda Console"
    echo "   2. Create a new function or update existing one"
    echo "   3. Upload lambda-deployment.zip"
    echo "   4. Set handler to: lambda_function.lambda_handler"
    echo "   5. Set runtime to: Python 3.9 or later"
    echo "   6. Configure environment variable: OTEL_COLLECTOR_ENDPOINT"
    echo "   7. Set up S3 trigger for ALB log files"
    echo ""
    echo "📋 Recommended Lambda configuration:"
    echo "   • Memory: 512 MB"
    echo "   • Timeout: 5 minutes"
    echo "   • IAM Role: Lambda execution role with S3 GetObject permissions"
else
    echo "❌ Failed to create deployment package"
    exit 1
fi 