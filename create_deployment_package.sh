#!/bin/bash

# Create AWS Lambda deployment package for Log Forwarder (Fully Optimized)

echo "Creating fully optimized AWS Lambda deployment package..."

# Clean up any existing deployment files
echo "Cleaning up existing deployment files..."
rm -rf lambda-deployment.zip
rm -rf package/

# Check if requirements.txt has any actual dependencies
echo "Checking dependencies..."
if grep -v '^#' requirements.txt | grep -v '^$' | wc -l | grep -q '^0$'; then
    echo "✅ No external dependencies found - creating minimal package (uses Python standard library only)"
    
    # Create minimal package with just the Lambda function
    echo "Creating minimal deployment package..."
    zip lambda-deployment.zip lambda_function.py
    
else
    echo "📦 External dependencies found - creating package with dependencies..."
    mkdir -p package
    
    # Install only actual dependencies (excluding comments and empty lines)
    pip install -r requirements.txt -t package/
    
    # Copy Lambda function code
    cp lambda_function.py package/
    
    # Create the deployment package, excluding unnecessary files
    cd package
    zip -r ../lambda-deployment.zip . \
        -x "*.pyc" \
        -x "*__pycache__*" \
        -x "*.DS_Store*" \
        -x "*.git*" \
        -x "*.pytest_cache*" \
        -x "*test*" \
        -x "*.egg-info*" \
        -x "*dist-info*" \
        -x "*.whl" \
        -x "*.tar.gz"
    cd ..
    
    # Clean up package directory
    rm -rf package/
fi

# Check if zip was created successfully
if [ -f "lambda-deployment.zip" ]; then
    echo "✅ Deployment package created successfully: lambda-deployment.zip"
    echo "📦 Package size: $(du -h lambda-deployment.zip | cut -f1)"
    
    # Show contents for verification
    echo ""
    echo "📋 Package contents:"
    unzip -l lambda-deployment.zip
    
else
    echo "❌ Failed to create deployment package"
    exit 1
fi 