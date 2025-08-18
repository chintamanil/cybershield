# LLM Factory for OpenAI and Bedrock integration
import os
from typing import Optional, Any
from utils.logging_config import get_security_logger
from utils.environment_config import config

logger = get_security_logger("llm_factory")


def create_llm(model: str = None, temperature: float = 0) -> Any:
    """
    Create LLM client based on environment configuration

    Args:
        model: Optional model override
        temperature: Temperature setting for model

    Returns:
        LangChain LLM instance (ChatOpenAI or ChatBedrock)
    """
    try:
        # Determine provider and model from environment
        if config.detector.is_aws():
            provider = "bedrock"
            default_model = (
                "anthropic.claude-3-5-sonnet-20241022-v2:0"  # Claude 3.5 Sonnet v2
            )
        else:
            provider = "openai"
            default_model = "gpt-4"

        # Use provided model or default
        model_name = model or os.getenv("LLM_MODEL", default_model)

        logger.info(
            "Creating LLM client",
            provider=provider,
            model=model_name,
            temperature=temperature,
        )

        if provider == "bedrock":
            return create_bedrock_llm(model_name, temperature)
        else:
            return create_openai_llm(model_name, temperature)

    except Exception as e:
        logger.error("Failed to create LLM client", error=str(e))
        # Fallback to OpenAI if available
        return create_openai_llm(model or "gpt-4", temperature)


def create_bedrock_llm(model: str, temperature: float) -> Any:
    """Create Bedrock LLM client using LangChain"""
    try:
        from langchain_aws import ChatBedrock
        import boto3

        # Get AWS session with proper region
        session = boto3.Session(region_name=os.getenv("AWS_REGION", "us-east-1"))

        # Create Bedrock client
        llm = ChatBedrock(
            model_id=model,
            region_name=session.region_name,
            credentials_profile_name=None,  # Use default credentials
            model_kwargs={"temperature": temperature, "max_tokens": 4096, "top_p": 0.9},
        )

        logger.info(
            "Bedrock LLM created successfully", model=model, region=session.region_name
        )

        return llm

    except ImportError as e:
        logger.error("Bedrock dependencies not available", error=str(e))
        logger.info("Install with: pip install langchain-aws boto3")
        raise
    except Exception as e:
        logger.error("Failed to create Bedrock LLM", model=model, error=str(e))
        raise


def create_openai_llm(model: str, temperature: float) -> Any:
    """Create OpenAI LLM client using LangChain"""
    try:
        from langchain_openai import ChatOpenAI

        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY not found in environment")

        llm = ChatOpenAI(model=model, temperature=temperature, api_key=api_key)

        logger.info("OpenAI LLM created successfully", model=model)
        return llm

    except ImportError as e:
        logger.error("OpenAI dependencies not available", error=str(e))
        raise
    except Exception as e:
        logger.error("Failed to create OpenAI LLM", model=model, error=str(e))
        raise


def test_llm_connection(llm: Any) -> bool:
    """Test LLM connection with a simple query"""
    try:
        from langchain_core.messages import HumanMessage

        # Simple test message
        test_message = HumanMessage(content="Hello, please respond with 'OK'")
        response = llm.invoke([test_message])

        # Check if we got a response
        if hasattr(response, "content") and response.content:
            logger.info(
                "LLM connection test successful", response_preview=response.content[:50]
            )
            return True
        else:
            logger.warning("LLM connection test failed - no content in response")
            return False

    except Exception as e:
        logger.error("LLM connection test failed", error=str(e))
        return False


# Backwards compatibility
def get_llm(model: str = None, temperature: float = 0) -> Any:
    """Alias for create_llm for backwards compatibility"""
    return create_llm(model, temperature)
