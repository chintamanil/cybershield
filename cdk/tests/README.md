# CDK Tests

Unit tests for CyberShield AWS CDK infrastructure.

## Running Tests

### Run All Tests

```bash
# From the cdk directory
pytest

# With coverage
pytest --cov=stacks --cov=config --cov=constructs

# With verbose output
pytest -v

# Run specific test file
pytest tests/test_network_stack.py

# Run specific test
pytest tests/test_config.py::test_development_config
```

## Test Structure

### Configuration Tests (`test_config.py`)
Tests for environment configurations and constants:
- Environment-specific settings (dev/staging/prod)
- Configuration validation
- Default values
- Tag generation
- Cost optimization flags

### Network Stack Tests (`test_network_stack.py`)
Tests for network infrastructure:
- VPC creation
- Subnet configuration (4 types)
- Security group rules
- NAT Gateway presence
- Internet Gateway
- Resource tagging

### Compute Stack Tests (`test_compute_stack.py`)
Tests for compute infrastructure:
- ECS cluster creation
- ECR repository configuration
- Task definition settings
- Service configuration
- Auto-scaling setup
- IAM role assignment
- CloudWatch log groups

## Test Fixtures

### `set_test_environment` (conftest.py)
Automatically sets required environment variables:
- `AWS_ACCOUNT_ID`: Test AWS account
- `AWS_REGION`: Test AWS region
- `ENVIRONMENT`: Test environment (dev)

## Writing New Tests

### Example Test Structure

```python
import aws_cdk as cdk
import aws_cdk.assertions as assertions
from stacks.your_stack import YourStack
from config.environments import DevelopmentConfig

def test_your_resource_created() -> None:
    """Test that your resource is created correctly."""
    # Arrange
    app = cdk.App()
    config = DevelopmentConfig()

    # Act
    stack = YourStack(
        app,
        "TestStack",
        config=config,
        env=cdk.Environment(account="123456789012", region="us-east-1"),
    )

    # Assert
    template = assertions.Template.from_stack(stack)
    template.has_resource_properties(
        "AWS::Service::Resource",
        {
            "Property": "ExpectedValue",
        },
    )
```

### Assertion Patterns

```python
# Check resource count
template.resource_count_is("AWS::EC2::VPC", 1)

# Check resource properties
template.has_resource_properties(
    "AWS::ECS::Cluster",
    {"ClusterName": "cybershield-dev"}
)

# Check property with partial match
template.has_resource_properties(
    "AWS::EC2::VPC",
    {
        "Tags": assertions.Match.array_with([
            {"Key": "Project", "Value": "cybershield"}
        ])
    }
)

# Check any value
template.has_resource_properties(
    "AWS::ECS::TaskDefinition",
    {"ExecutionRoleArn": assertions.Match.any_value()}
)
```

## Test Coverage

Current test coverage:
- ✅ Configuration system (100%)
- ✅ Network stack (core functionality)
- ✅ Compute stack (core functionality)
- ⏳ IAM stack (to be added)
- ⏳ Data stack (to be added)
- ⏳ Load Balancer stack (to be added)
- ⏳ Monitoring stack (to be added)

## Continuous Integration

### GitHub Actions Example

```yaml
name: CDK Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: pytest --cov --cov-report=xml
      - uses: codecov/codecov-action@v3
```

## Best Practices

1. **Test One Thing** - Each test should verify one specific behavior
2. **Use Descriptive Names** - Test names should describe what they test
3. **Arrange-Act-Assert** - Follow the AAA pattern
4. **Don't Test AWS** - Test your infrastructure code, not AWS services
5. **Mock External Dependencies** - Use fixtures for external services
6. **Keep Tests Fast** - Avoid actual AWS API calls
7. **Test Edge Cases** - Include tests for error conditions

## Resources

- [AWS CDK Testing](https://docs.aws.amazon.com/cdk/v2/guide/testing.html)
- [CDK Assertions](https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.assertions-readme.html)
- [Pytest Documentation](https://docs.pytest.org/)
