#!/usr/bin/env python3
# AWS deployment script for CyberShield

import json
import subprocess
import sys
from pathlib import Path

import boto3


def check_prerequisites():
    """Check if required tools are installed"""
    print("🔍 Checking prerequisites...")

    required_tools = {"aws": "AWS CLI", "cdk": "AWS CDK", "docker": "Docker"}

    missing_tools = []

    for tool, description in required_tools.items():
        try:
            subprocess.run([tool, "--version"], capture_output=True, check=True)
            print(f"✅ {description} is installed")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"❌ {description} is not installed")
            missing_tools.append(tool)

    if missing_tools:
        print(f"\nPlease install missing tools: {', '.join(missing_tools)}")
        return False

    return True


def verify_aws_credentials():
    """Verify AWS credentials are configured"""
    print("🔐 Verifying AWS credentials...")

    try:
        sts = boto3.client("sts")
        identity = sts.get_caller_identity()

        print("✅ AWS credentials verified")
        print(f"   Account: {identity['Account']}")
        print(f"   User: {identity['Arn']}")

        return identity["Account"]

    except Exception as e:
        print(f"❌ AWS credentials not configured: {e}")
        print("Please run: aws configure")
        return None


def bootstrap_cdk(account_id: str, region: str):
    """Bootstrap CDK in the AWS account"""
    print(f"🚀 Bootstrapping CDK in account {account_id}, region {region}...")

    try:
        subprocess.run(["cdk", "bootstrap", f"aws://{account_id}/{region}"], check=True)

        print("✅ CDK bootstrap completed")
        return True

    except subprocess.CalledProcessError as e:
        print(f"❌ CDK bootstrap failed: {e}")
        return False


def build_docker_image():
    """Build Docker image for ECS"""
    print("🐳 Building Docker image...")

    try:
        subprocess.run(
            [
                "docker",
                "build",
                "-f",
                "deployment/Dockerfile.aws",
                "-t",
                "cybershield:latest",
                ".",
            ],
            check=True,
        )

        print("✅ Docker image built successfully")
        return True

    except subprocess.CalledProcessError as e:
        print(f"❌ Docker build failed: {e}")
        return False


def deploy_infrastructure(account_id: str, region: str):
    """Deploy infrastructure using CDK"""
    print("☁️ Deploying AWS infrastructure...")

    # Update CDK stack with account and region
    cdk_file = Path("infrastructure/aws_cdk_stack.py")
    if cdk_file.exists():
        content = cdk_file.read_text()
        content = content.replace('account="123456789012"', f'account="{account_id}"')
        content = content.replace('region="us-east-1"', f'region="{region}"')
        cdk_file.write_text(content)

    try:
        # Deploy the stack
        subprocess.run(
            [
                "cdk",
                "deploy",
                "--require-approval",
                "never",
                "--app",
                "python infrastructure/aws_cdk_stack.py",
            ],
            check=True,
        )

        print("✅ Infrastructure deployment completed")
        return True

    except subprocess.CalledProcessError as e:
        print(f"❌ Infrastructure deployment failed: {e}")
        return False


def get_stack_outputs():
    """Get CloudFormation stack outputs"""
    print("📋 Getting deployment outputs...")

    try:
        cf = boto3.client("cloudformation")
        response = cf.describe_stacks(StackName="CyberShieldStack")

        if response["Stacks"]:
            outputs = response["Stacks"][0].get("Outputs", [])

            print("\n🎯 Deployment Information:")
            for output in outputs:
                print(f"   {output['Description']}: {output['OutputValue']}")

            return {output["OutputKey"]: output["OutputValue"] for output in outputs}

    except Exception as e:
        print(f"❌ Failed to get stack outputs: {e}")
        return {}


def setup_secrets(outputs: dict):
    """Setup secrets in AWS Secrets Manager"""
    print("🔐 Setting up secrets...")

    try:
        secrets = boto3.client("secretsmanager")

        # Update API keys secret
        api_keys = {
            "virustotal": input("Enter VirusTotal API key (or press Enter to skip): ")
            or "REPLACE_ME",
            "shodan": input("Enter Shodan API key (or press Enter to skip): ")
            or "REPLACE_ME",
            "abuseipdb": input("Enter AbuseIPDB API key (or press Enter to skip): ")
            or "REPLACE_ME",
        }

        try:
            secrets.update_secret(
                SecretId="cybershield/api-keys", SecretString=json.dumps(api_keys)
            )
            print("✅ API keys updated in Secrets Manager")
        except secrets.exceptions.ResourceNotFoundException:
            print("⚠️ Secrets not found - they will be created by CDK")

    except Exception as e:
        print(f"❌ Failed to setup secrets: {e}")


def post_deployment_setup(outputs: dict):
    """Perform post-deployment setup"""
    print("⚙️ Performing post-deployment setup...")

    # Setup OpenSearch index
    if "OpenSearchEndpoint" in outputs:
        opensearch_endpoint = outputs["OpenSearchEndpoint"]
        print(f"📊 Setting up OpenSearch at {opensearch_endpoint}")

        try:
            subprocess.run(
                ["python", "scripts/setup_opensearch.py", "aws", opensearch_endpoint],
                check=True,
            )
            print("✅ OpenSearch setup completed")
        except subprocess.CalledProcessError as e:
            print(f"⚠️ OpenSearch setup failed: {e}")

    # Migrate data if needed
    print(
        "📦 Data migration available via: python scripts/migrate_vector_data.py migrate"
    )


def main():
    """Main deployment function"""
    print("🛡️ CyberShield AWS Deployment")
    print("=" * 50)

    # Check prerequisites
    if not check_prerequisites():
        sys.exit(1)

    # Verify AWS credentials
    account_id = verify_aws_credentials()
    if not account_id:
        sys.exit(1)

    # Get deployment region
    region = input("Enter AWS region [us-east-1]: ") or "us-east-1"

    # Confirm deployment
    print("\n📋 Deployment Summary:")
    print(f"   Account: {account_id}")
    print(f"   Region: {region}")
    print("   Stack: CyberShieldStack")

    confirm = input("\nProceed with deployment? [y/N]: ")
    if confirm.lower() != "y":
        print("Deployment cancelled")
        sys.exit(0)

    # Bootstrap CDK
    if not bootstrap_cdk(account_id, region):
        sys.exit(1)

    # Build Docker image
    if not build_docker_image():
        sys.exit(1)

    # Deploy infrastructure
    if not deploy_infrastructure(account_id, region):
        sys.exit(1)

    # Get outputs
    outputs = get_stack_outputs()

    # Setup secrets
    setup_secrets(outputs)

    # Post-deployment setup
    post_deployment_setup(outputs)

    print("\n🎉 Deployment completed successfully!")
    print("\n📋 Next steps:")
    print("1. Update API keys in AWS Secrets Manager")
    print("2. Configure custom domain (optional)")
    print("3. Setup monitoring and alerts")
    print("4. Migrate existing data if needed")

    if "CloudFrontDomain" in outputs:
        print("\n🌐 Your application is available at:")
        print(f"   https://{outputs['CloudFrontDomain']}")


if __name__ == "__main__":
    main()
