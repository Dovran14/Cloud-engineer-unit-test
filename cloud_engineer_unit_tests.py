import pytest
import boto3
import json
from unittest.mock import patch, MagicMock
import requests
from botocore.exceptions import ClientError

# ======================================================
# 1. Testing AWS S3 Operations
# ======================================================

class TestS3Operations:
    @patch('boto3.client')
    def test_create_s3_bucket_success(self, mock_boto_client):
        """Test successful S3 bucket creation"""
        # Arrange
        mock_s3 = MagicMock()
        mock_boto_client.return_value = mock_s3
        bucket_name = "test-bucket"
        region = "us-east-1"
        
        # Act
        def create_s3_bucket(bucket_name, region):
            s3_client = boto3.client('s3', region_name=region)
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': region}
            )
            return True
            
        result = create_s3_bucket(bucket_name, region)
        
        # Assert
        mock_boto_client.assert_called_once_with('s3', region_name=region)
        mock_s3.create_bucket.assert_called_once()
        assert result is True

    @patch('boto3.client')
    def test_create_s3_bucket_already_exists(self, mock_boto_client):
        """Test handling of bucket already exists error"""
        # Arrange
        mock_s3 = MagicMock()
        mock_boto_client.return_value = mock_s3
        
        error_response = {'Error': {'Code': 'BucketAlreadyExists'}}
        mock_s3.create_bucket.side_effect = ClientError(error_response, 'CreateBucket')
        
        # Act
        def create_s3_bucket_with_error_handling(bucket_name, region):
            try:
                s3_client = boto3.client('s3', region_name=region)
                s3_client.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={'LocationConstraint': region}
                )
                return True
            except ClientError as e:
                if e.response['Error']['Code'] == 'BucketAlreadyExists':
                    return False
                raise
        
        result = create_s3_bucket_with_error_handling("existing-bucket", "us-east-1")
        
        # Assert
        assert result is False

# ======================================================
# 2. Testing Cloud Configuration Validation
# ======================================================

class TestCloudConfiguration:
    def test_validate_ec2_security_group_config(self):
        """Test validation of EC2 security group configuration"""
        # Arrange
        security_group_config = {
            "GroupName": "web-server-sg",
            "Description": "Security group for web servers",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                }
            ]
        }
        
        # Act
        def validate_security_group(config):
            # Check for required fields
            required_fields = ["GroupName", "Description", "IpPermissions"]
            for field in required_fields:
                if field not in config:
                    return False
                    
            # Check for open ports to the world
            for permission in config["IpPermissions"]:
                for ip_range in permission.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        return False
                        
            return True
        
        result = validate_security_group(security_group_config)
        
        # Assert
        assert result is False, "Should detect security issue with open port to the world"
        
    def test_validate_iam_policy(self):
        """Test validation of IAM policy for least privilege"""
        # Arrange
        iam_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }
        
        # Act
        def validate_iam_policy_least_privilege(policy):
            for statement in policy.get("Statement", []):
                # Check for wildcard actions
                if statement.get("Effect") == "Allow" and "*" in statement.get("Action", []):
                    return False
                # Check for wildcard resources with permissive actions
                if statement.get("Effect") == "Allow" and "*" in statement.get("Resource", []):
                    return False
            return True
            
        result = validate_iam_policy_least_privilege(iam_policy)
        
        # Assert
        assert result is False, "Should detect overly permissive IAM policy"

# ======================================================
# 3. Testing API Response Handling
# ======================================================

class TestCloudAPIResponses:
    @patch('requests.get')
    def test_aws_api_status_check(self, mock_get):
        """Test AWS service health API check"""
        # Arrange
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "services": {
                "EC2": {"status": "operational"},
                "S3": {"status": "operational"},
                "Lambda": {"status": "issue"}
            }
        }
        mock_get.return_value = mock_response
        
        # Act
        def check_aws_services_health():
            response = requests.get("https://status.aws.amazon.com/healthcheck")
            if response.status_code != 200:
                return False
                
            data = response.json()
            services = data.get("services", {})
            
            # Check if any service has issues
            for service, details in services.items():
                if details.get("status") != "operational":
                    return False
                    
            return True
        
        result = check_aws_services_health()
        
        # Assert
        assert result is False, "Should detect service issue"
        mock_get.assert_called_once_with("https://status.aws.amazon.com/healthcheck")

    @patch('boto3.client')
    def test_ec2_instance_pagination(self, mock_boto_client):
        """Test pagination handling for EC2 instance listing"""
        # Arrange
        mock_ec2 = MagicMock()
        mock_boto_client.return_value = mock_ec2
        
        # Set up pagination with NextToken
        first_response = {
            'Instances': [{'InstanceId': 'i-123'}, {'InstanceId': 'i-456'}],
            'NextToken': 'page2token'
        }
        second_response = {
            'Instances': [{'InstanceId': 'i-789'}]
        }
        
        mock_ec2.describe_instances.side_effect = [first_response, second_response]
        
        # Act
        def get_all_ec2_instances():
            ec2_client = boto3.client('ec2')
            instances = []
            response = ec2_client.describe_instances()
            
            instances.extend(response.get('Instances', []))
            
            # Handle pagination
            while 'NextToken' in response:
                response = ec2_client.describe_instances(NextToken=response['NextToken'])
                instances.extend(response.get('Instances', []))
                
            return instances
        
        result = get_all_ec2_instances()
        
        # Assert
        assert len(result) == 3
        assert mock_ec2.describe_instances.call_count == 2

# ======================================================
# 4. Testing Infrastructure as Code
# ======================================================

class TestCloudFormationTemplate:
    def test_validate_cloudformation_template(self):
        """Test validation of a CloudFormation template structure"""
        # Arrange
        cf_template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "MyEC2Instance": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {
                        "ImageId": "ami-12345678",
                        "InstanceType": "t2.micro"
                    }
                }
            }
        }
        
        # Act
        def validate_cf_template(template):
            # Check required top-level sections
            if "Resources" not in template:
                return False
                
            # Resources section must not be empty
            if not template["Resources"]:
                return False
                
            # Check each resource has Type and Properties
            for resource_id, resource in template["Resources"].items():
                if "Type" not in resource:
                    return False
                if "Properties" not in resource:
                    return False
                    
            return True
            
        result = validate_cf_template(cf_template)
        
        # Assert
        assert result is True

    def test_detect_security_issues_in_template(self):
        """Test detection of security issues in CloudFormation template"""
        # Arrange
        cf_template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "MyS3Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": "my-website-logs",
                        "AccessControl": "PublicRead"
                    }
                }
            }
        }
        
        # Act
        def check_s3_security(template):
            # Look for S3 buckets with public access
            for resource_id, resource in template.get("Resources", {}).items():
                if resource.get("Type") == "AWS::S3::Bucket":
                    properties = resource.get("Properties", {})
                    # Check for public access control settings
                    if properties.get("AccessControl") in ["PublicRead", "PublicReadWrite"]:
                        return False
            return True
            
        result = check_s3_security(cf_template)
        
        # Assert
        assert result is False, "Should detect insecure S3 bucket configuration"

# ======================================================
# 5. Testing Cloud Resource Tagging Compliance
# ======================================================

class TestResourceTagging:
    @patch('boto3.client')
    def test_check_required_tags(self, mock_boto_client):
        """Test validation of required resource tags"""
        # Arrange
        mock_ec2 = MagicMock()
        mock_boto_client.return_value = mock_ec2
        
        mock_ec2.describe_tags.return_value = {
            'Tags': [
                {'Key': 'Environment', 'Value': 'Production'},
                {'Key': 'Owner', 'Value': 'CloudTeam'}
                # Missing 'Project' tag
            ]
        }
        
        # Act
        def validate_instance_tags(instance_id, required_tags):
            ec2_client = boto3.client('ec2')
            response = ec2_client.describe_tags(
                Filters=[{'Name': 'resource-id', 'Values': [instance_id]}]
            )
            
            existing_tags = {tag['Key']: tag['Value'] for tag in response.get('Tags', [])}
            
            # Check if all required tags exist
            for tag in required_tags:
                if tag not in existing_tags:
                    return False
            
            return True
            
        result = validate_instance_tags(
            'i-1234567890abcdef0', 
            ['Environment', 'Owner', 'Project']
        )
        
        # Assert
        assert result is False, "Should detect missing required tag"
