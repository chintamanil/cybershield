# FastAPI server with Vision AI and ReAct workflow support - Async Version
import asyncio
import os
import time
from contextlib import asynccontextmanager
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# CRITICAL: Load .env files FIRST before any other imports
# This ensures environment variables are available for all subsequent imports
load_dotenv('.env.local', override=True)  # Local overrides
load_dotenv('.env', override=True)  # Main config file (CHANGED: override=True)

# Load environment-specific configuration AFTER env vars are loaded
from utils.environment_config import config

# Load environment-specific .env files
if not config.detector.is_local():
    load_dotenv('.env.aws', override=True)

# Import our agents and components
from agents.supervisor import SupervisorAgent
from memory.redis_stm import RedisSTM

# Import the new tool classes
from tools.abuseipdb import AbuseIPDBClient
from tools.regex_checker import RegexChecker
from tools.shodan import ShodanClient
from tools.virustotal import VirusTotalClient

# Configure structured logging
from utils.logging_config import get_logger, setup_from_env
from vectorstore.milvus_client import CyberShieldVectorStore

# Import SLA tracking components
from server.middleware import setup_sla_middleware
from server.middleware.sla_middleware import SLAMiddleware
from server.monitoring.sla_tracker import SLATracker
from server.endpoints import sla_router, set_sla_tracker

# Setup logging from environment
setup_from_env()
logger = get_logger(__name__, component='server')

# Test debug logging is working
import logging as stdlib_logging

current_level = stdlib_logging.getLogger().getEffectiveLevel()
debug_enabled = current_level <= stdlib_logging.DEBUG

logger.info(
    'Logging configuration initialized',
    log_level=stdlib_logging.getLevelName(current_level),
    debug_enabled=debug_enabled,
    environment_vars={
        'LOG_LEVEL': os.getenv('LOG_LEVEL', 'not_set'),
        'LOG_FILE': os.getenv('LOG_FILE', 'not_set'),
        'DEBUG': os.getenv('DEBUG', 'not_set'),
    },
)

# Force a reconfigure if DEBUG is set but not working
if os.getenv('LOG_LEVEL', '').upper() == 'DEBUG' and not debug_enabled:
    logger.warning('DEBUG level requested but not active - reconfiguring logging')
    setup_from_env()  # Reconfigure logging
    current_level = stdlib_logging.getLogger().getEffectiveLevel()
    logger.info(
        'Logging reconfigured', new_level=stdlib_logging.getLevelName(current_level)
    )


# Global variables for async components
memory = None
vectorstore = None
agent = None
abuseipdb_client = None
shodan_client = None
virustotal_client = None
regex_checker = None
sla_tracker = None


async def initialize_component(name: str, coro):
    """Initialize a single component with timing and error handling"""
    start_time = time.time()
    try:
        result = await coro
        duration = time.time() - start_time
        logger.info(f'{name} initialized', duration_ms=f'{duration * 1000:.1f}')
        return result, None
    except Exception as e:
        duration = time.time() - start_time
        logger.error(
            f'{name} initialization failed',
            error=str(e),
            duration_ms=f'{duration * 1000:.1f}',
        )
        return None, e


async def parallel_initialization():
    """Initialize all components in parallel for faster startup"""
    logger.info('Starting parallel component initialization')

    # Create all initialization tasks
    # Note: For Redis, we test connectivity but will create a fresh RedisSTM instance later
    redis_stm = RedisSTM()
    tasks = {
        'redis': initialize_component('Redis', redis_stm._get_redis()),
        'vectorstore': initialize_component(
            'VectorStore', CyberShieldVectorStore('cybersecurity_attacks').connect()
        ),
        'abuseipdb': initialize_component(
            'AbuseIPDB', asyncio.create_task(asyncio.to_thread(AbuseIPDBClient))
        ),
        'shodan': initialize_component(
            'Shodan', asyncio.create_task(asyncio.to_thread(ShodanClient))
        ),
        'virustotal': initialize_component(
            'VirusTotal', asyncio.create_task(asyncio.to_thread(VirusTotalClient))
        ),
        'regex': initialize_component(
            'RegexChecker', asyncio.create_task(asyncio.to_thread(RegexChecker))
        ),
    }

    # Execute all initialization tasks concurrently
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)

    # Process results
    components = {}
    errors = []
    for (name, task), result in zip(tasks.items(), results, strict=False):
        if isinstance(result, Exception):
            errors.append(f'{name}: {result}')
            components[name] = (None, result)
        else:
            components[name] = result

    if errors:
        logger.warning('Some components failed to initialize', errors=errors)

    return components


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Optimized async startup and shutdown for FastAPI app"""
    # Startup
    global \
        memory, \
        vectorstore, \
        agent, \
        abuseipdb_client, \
        shodan_client, \
        virustotal_client, \
        regex_checker, \
        sla_tracker

    startup_start = time.time()

    try:
        # Initialize all components in parallel
        components = await parallel_initialization()

        # Extract initialized components
        memory_result, memory_error = components.get('redis', (None, None))
        vectorstore_result, vs_error = components.get('vectorstore', (None, None))
        abuseipdb_result, ab_error = components.get('abuseipdb', (None, None))
        shodan_result, sh_error = components.get('shodan', (None, None))
        virustotal_result, vt_error = components.get('virustotal', (None, None))
        regex_result, rx_error = components.get('regex', (None, None))

        # Set up components (prioritize successful ones)
        # IMPORTANT: Always create a fresh RedisSTM instance (memory_result is just the raw Redis client for connectivity check)
        if not memory_error:
            memory = RedisSTM()  # Create fresh wrapper instance
        else:
            memory = None

        if vectorstore_result is None and not vs_error:
            vectorstore = CyberShieldVectorStore('cybersecurity_attacks')
        else:
            vectorstore = None if vs_error else vectorstore_result

        # Handle client results properly - they return (result, error) tuples
        abuseipdb_client = (
            None
            if ab_error
            else (
                abuseipdb_result
                if isinstance(abuseipdb_result, tuple) and abuseipdb_result[0]
                else AbuseIPDBClient()
            )
        )
        shodan_client = (
            None
            if sh_error
            else (
                shodan_result
                if isinstance(shodan_result, tuple) and shodan_result[0]
                else ShodanClient()
            )
        )
        virustotal_client = (
            None
            if vt_error
            else (
                virustotal_result
                if isinstance(virustotal_result, tuple) and virustotal_result[0]
                else VirusTotalClient()
            )
        )
        regex_checker = (
            None
            if rx_error
            else (
                regex_result
                if isinstance(regex_result, tuple) and regex_result[0]
                else RegexChecker()
            )
        )

        # Initialize SupervisorAgent with available components
        logger.info('Initializing SupervisorAgent with available components')
        agent = SupervisorAgent(
            memory,
            vectorstore,
            use_react_workflow=True,
            abuseipdb_client=abuseipdb_client,
            shodan_client=shodan_client,
            virustotal_client=virustotal_client,
        )

        # Initialize agent clients if available
        if hasattr(agent, 'initialize_clients'):
            try:
                await agent.initialize_clients()
                logger.info('SupervisorAgent clients initialized')
            except Exception as e:
                logger.warning('Agent client initialization failed', error=str(e))

        startup_duration = time.time() - startup_start
        successful_components = sum(
            1 for name, (result, error) in components.items() if not error
        )
        total_components = len(components)

        # Connect SLA tracker to Redis (middleware already added at module level)
        try:
            if sla_tracker:
                await sla_tracker.connect()
                logger.info(
                    'SLA tracker connected',
                    redis_host=sla_tracker.redis_host,
                    redis_port=sla_tracker.redis_port,
                )
        except Exception as sla_error:
            logger.warning('SLA tracker connection failed', error=str(sla_error))

        logger.info(
            'CyberShield startup complete',
            startup_time_ms=f'{startup_duration * 1000:.1f}',
            components_ready=f'{successful_components}/{total_components}',
            react_enabled=(
                agent.react_agent is not None
                if hasattr(agent, 'react_agent')
                else False
            ),
            sla_tracking=(sla_tracker is not None),
        )
    except Exception as e:
        logger.error(
            'Component initialization failed', error=str(e), fallback_mode=True
        )
        logger.debug(
            'Creating fallback SupervisorAgent without ReAct workflow', exc_info=True
        )
        # Create fallback without external dependencies
        agent = SupervisorAgent(None, None, use_react_workflow=False)
        abuseipdb_client = None
        shodan_client = None
        virustotal_client = None
        regex_checker = None

    yield

    # Shutdown
    try:
        if memory:
            await memory.close()
        if abuseipdb_client:
            await abuseipdb_client.close()
        if shodan_client:
            await shodan_client.close()
        if virustotal_client:
            await virustotal_client.close()
        if sla_tracker:
            await sla_tracker.close()
        logger.info('CyberShield shutdown complete', status='success')
    except Exception as e:
        logger.error('Shutdown error', error=str(e))


# Initialize FastAPI app with async lifespan
app = FastAPI(
    title='CyberShield AI Security System',
    description='Async multi-agent AI system for cybersecurity analysis with Vision AI and ReAct workflow',
    version='2.0.0',
    lifespan=lifespan,
)

# Initialize SLA tracker at module level (connection happens during lifespan startup)
redis_host = os.getenv('REDIS_HOST', 'localhost')
redis_port = int(os.getenv('REDIS_PORT', '6379'))
sla_tracker = SLATracker(redis_host=redis_host, redis_port=redis_port)
set_sla_tracker(sla_tracker)

# Add SLA middleware BEFORE app starts
app.add_middleware(SLAMiddleware, sla_tracker=sla_tracker)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        'http://localhost:8501',
        'http://127.0.0.1:8501',
    ],  # Streamlit frontend
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

# Include SLA monitoring router
app.include_router(sla_router)


# Pydantic models for request/response
class AnalysisRequest(BaseModel):
    text: str
    use_react_workflow: bool | None = True
    include_vision: bool | None = False
    session_id: str | None = None  # NEW: For context preservation


class BatchAnalysisRequest(BaseModel):
    inputs: list[str]
    use_react_workflow: bool | None = True
    session_id: str | None = None  # NEW: For context preservation


class AnalysisResponse(BaseModel):
    status: str
    result: dict[str, Any]
    processing_time: float | None = None


# Helper functions for safe async API calls
async def _safe_abuseipdb_check(ip: str) -> dict[str, Any]:
    """Safely perform AbuseIPDB check with error handling"""
    try:
        result = await abuseipdb_client.check_ip(ip)
        return {'abuseipdb': result}
    except Exception as e:
        logger.error(f'AbuseIPDB check failed for {ip}: {e}')
        return {'abuseipdb': {'error': str(e)}}


async def _safe_shodan_lookup(ip: str) -> dict[str, Any]:
    """Safely perform Shodan lookup with error handling"""
    try:
        result = await shodan_client.lookup_ip(ip)
        return {'shodan': result}
    except Exception as e:
        logger.error(f'Shodan lookup failed for {ip}: {e}')
        return {'shodan': {'error': str(e)}}


async def _safe_virustotal_lookup(ip: str) -> dict[str, Any]:
    """Safely perform VirusTotal IP lookup with error handling"""
    try:
        result = await virustotal_client.lookup_ip(ip)
        return {'virustotal': result}
    except Exception as e:
        logger.error(f'VirusTotal IP lookup failed for {ip}: {e}')
        return {'virustotal': {'error': str(e)}}


async def _safe_domain_lookup(domain: str) -> dict[str, Any]:
    """Safely perform VirusTotal domain lookup with error handling"""
    try:
        result = await virustotal_client.lookup_domain(domain)
        return {domain: result}
    except Exception as e:
        logger.error(f'Domain lookup failed for {domain}: {e}')
        return {domain: {'error': str(e)}}


async def _safe_hash_lookup(hash_value: str) -> dict[str, Any]:
    """Safely perform VirusTotal hash lookup with error handling"""
    try:
        result = await virustotal_client.lookup_file_hash(hash_value)
        return {hash_value: result}
    except Exception as e:
        logger.error(f'Hash lookup failed for {hash_value}: {e}')
        return {hash_value: {'error': str(e)}}


@app.get('/')
async def root():
    """API root endpoint with basic information"""
    return {
        'message': 'CyberShield AI Security System',
        'version': '2.0.0',
        'description': 'Multi-agent AI system for cybersecurity analysis with Vision AI and ReAct workflow',
        'frontend': 'Streamlit UI available at http://localhost:8501',
        'docs': 'Interactive API documentation at /docs',
        'status': 'GET /status for system information',
    }


@app.post('/analyze', response_model=AnalysisResponse)
async def analyze_text(request: AnalysisRequest):
    """
    Analyze text input for security threats, PII, and IOCs
    """
    start_time = time.time()
    request_logger = logger.bind(
        endpoint='analyze', react_workflow=request.use_react_workflow
    )

    try:
        request_logger.info('Analysis request started', text_length=len(request.text))

        # Configure agent workflow
        if hasattr(agent, 'use_react_workflow'):
            agent.use_react_workflow = request.use_react_workflow

        # Perform analysis with agent (with session_id for context preservation)
        result = await agent.analyze(request.text, session_id=request.session_id)

        # Check if ReAct workflow was used and returned comprehensive results
        react_workflow_used = (
            request.use_react_workflow
            and isinstance(result, dict)
            and 'processing_method' in result
            and result.get('processing_method') == 'react_workflow'
        )

        # Only run additional tool analysis if ReAct workflow didn't provide comprehensive results
        tool_results = {}
        if not react_workflow_used:
            # Extract IOCs using regex checker
            if regex_checker:
                try:
                    iocs = regex_checker.extract_all_iocs(request.text)
                    tool_results['ioc_extraction'] = iocs

                    # Perform threat intelligence lookups for extracted IPs
                    if 'public_ipv4' in iocs:
                        threat_intel = {}
                        for ip in iocs['public_ipv4'][:3]:  # Limit to first 3 IPs
                            ip_results = {}

                            # Concurrent async lookups for better performance
                            lookup_tasks = []

                            # AbuseIPDB check
                            if abuseipdb_client:
                                lookup_tasks.append(_safe_abuseipdb_check(ip))

                            # Shodan lookup
                            if shodan_client:
                                lookup_tasks.append(_safe_shodan_lookup(ip))

                            # VirusTotal lookup
                            if virustotal_client:
                                lookup_tasks.append(_safe_virustotal_lookup(ip))

                            # Execute all lookups concurrently
                            if lookup_tasks:
                                lookup_results = await asyncio.gather(
                                    *lookup_tasks, return_exceptions=True
                                )
                                for result in lookup_results:
                                    if isinstance(result, dict):
                                        ip_results.update(result)
                                    elif isinstance(result, Exception):
                                        logger.error(f'Lookup failed: {result}')

                            threat_intel[ip] = ip_results

                        tool_results['threat_intelligence'] = threat_intel

                    # Check domains
                    if 'domain' in iocs:
                        domain_results = {}
                        # Concurrent domain lookups
                        domain_tasks = []
                        for domain in iocs['domain'][:3]:  # Limit to first 3 domains
                            if virustotal_client:
                                domain_tasks.append(_safe_domain_lookup(domain))

                        if domain_tasks:
                            domain_lookup_results = await asyncio.gather(
                                *domain_tasks, return_exceptions=True
                            )
                            for result in domain_lookup_results:
                                if isinstance(result, dict):
                                    domain_results.update(result)
                                elif isinstance(result, Exception):
                                    logger.error(f'Domain lookup failed: {result}')

                        tool_results['domain_analysis'] = domain_results

                    # Check hashes
                    if any(
                        hash_type in iocs for hash_type in ['md5', 'sha1', 'sha256']
                    ):
                        hash_results = {}
                        for hash_type in ['md5', 'sha1', 'sha256']:
                            if hash_type in iocs:
                                # Concurrent hash lookups
                                hash_tasks = []
                                for hash_value in iocs[hash_type][
                                    :2
                                ]:  # Limit to first 2 hashes
                                    if virustotal_client:
                                        hash_tasks.append(_safe_hash_lookup(hash_value))

                                if hash_tasks:
                                    hash_lookup_results = await asyncio.gather(
                                        *hash_tasks, return_exceptions=True
                                    )
                                    for result in hash_lookup_results:
                                        if isinstance(result, dict):
                                            hash_results.update(result)
                                        elif isinstance(result, Exception):
                                            logger.error(
                                                f'Hash lookup failed: {result}'
                                            )

                        tool_results['hash_analysis'] = hash_results

                except Exception as e:
                    logger.error(f'Tool analysis failed: {e}')
                    tool_results['error'] = str(e)

        # Merge tool results with agent results (only if ReAct didn't provide comprehensive results)
        if tool_results and not react_workflow_used:
            result['tool_analysis'] = tool_results
        elif react_workflow_used:
            # Log that we're using ReAct workflow results instead of server tool analysis
            request_logger.info(
                'Using ReAct workflow comprehensive results',
                react_components=(
                    list(result.keys()) if isinstance(result, dict) else []
                ),
            )

        processing_time = time.time() - start_time

        # Log the final result being sent to frontend
        request_logger.debug('Final result sent to frontend', final_result=result)

        request_logger.debug(
            'Analysis request completed',
            status='success',
            processing_time_ms=round(processing_time * 1000, 2),
            react_workflow_used=react_workflow_used,
            tool_analysis_included=(
                bool(tool_results) if not react_workflow_used else 'react_comprehensive'
            ),
        )

        return AnalysisResponse(
            status='success', result=result, processing_time=processing_time
        )

    except Exception as e:
        processing_time = time.time() - start_time
        request_logger.error(
            'Analysis request failed',
            error=str(e),
            processing_time_ms=round(processing_time * 1000, 2),
        )
        raise HTTPException(status_code=500, detail=str(e))


@app.post('/analyze-with-image')
async def analyze_with_image(
    text: str = Form(...),
    image: UploadFile = File(...),
    use_react_workflow: bool = Form(True),
    session_id: str | None = Form(None),  # NEW: For context preservation
):
    """
    Analyze text and image content for security risks with optional session context
    """
    try:
        start_time = time.time()

        # Read image data
        image_data = await image.read()

        # Configure agent workflow
        if hasattr(agent, 'use_react_workflow'):
            agent.use_react_workflow = use_react_workflow

        # Perform analysis with image (with session_id for context preservation)
        result = await agent.analyze(text, image_data, session_id=session_id)

        processing_time = time.time() - start_time

        return JSONResponse(
            content={
                'status': 'success',
                'result': result,
                'processing_time': processing_time,
                'image_info': {
                    'filename': image.filename,
                    'content_type': image.content_type,
                    'size': len(image_data),
                },
            }
        )

    except Exception as e:
        logger.error(f'Image analysis failed: {e}')
        raise HTTPException(status_code=500, detail=str(e))


@app.post('/batch-analyze')
async def batch_analyze(request: BatchAnalysisRequest):
    """
    Analyze multiple text inputs in batch with optional session context
    """
    try:
        start_time = time.time()

        # Configure agent workflow
        if hasattr(agent, 'use_react_workflow'):
            agent.use_react_workflow = request.use_react_workflow

        # Perform batch analysis (with session_id for context preservation)
        results = await agent.analyze_batch(
            request.inputs, session_id=request.session_id
        )

        processing_time = time.time() - start_time

        return JSONResponse(
            content={
                'status': 'success',
                'results': results,
                'processing_time': processing_time,
                'batch_size': len(request.inputs),
            }
        )

    except Exception as e:
        logger.error(f'Batch analysis failed: {e}')
        raise HTTPException(status_code=500, detail=str(e))


@app.get('/status')
async def get_status():
    """
    Get system status and agent information with environment details
    """
    try:
        from utils.app_initializer import app_initializer

        agent_status = agent.get_agent_status()
        environment_info = app_initializer.get_environment_info()
        health_status = app_initializer.get_health_status()

        # Check tool availability
        tools_status = {
            'abuseipdb': abuseipdb_client is not None,
            'shodan': shodan_client is not None,
            'virustotal': virustotal_client is not None,
            'regex_checker': regex_checker is not None,
        }

        return JSONResponse(
            content={
                'status': 'online',
                'version': '2.0.0',
                'environment': environment_info,
                'health': health_status,
                'features': [
                    'Vision AI',
                    'ReAct Workflow',
                    'Multi-Agent Analysis',
                    'PII Detection',
                    'Threat Intelligence',
                    'IOC Extraction',
                    'Tool Classes',
                    'Dual Environment Support',
                ],
                'agents': agent_status,
                'tools': tools_status,
                'endpoints': {
                    'analyze': 'POST /analyze',
                    'analyze_with_image': 'POST /analyze-with-image',
                    'batch_analyze': 'POST /batch-analyze',
                    'status': 'GET /status',
                    'health': 'GET /health',
                    'environment': 'GET /environment',
                    'tools': {
                        'abuseipdb_check': 'POST /tools/abuseipdb/check',
                        'shodan_lookup': 'POST /tools/shodan/lookup',
                        'virustotal_lookup': 'POST /tools/virustotal/lookup',
                        'regex_extract': 'POST /tools/regex/extract',
                        'regex_validate': 'POST /tools/regex/validate',
                    },
                },
            }
        )

    except Exception as e:
        logger.error(f'Status check failed: {e}')
        return JSONResponse(
            status_code=500, content={'status': 'error', 'error': str(e)}
        )


@app.post('/upload-image')
async def upload_image_only(image: UploadFile = File(...)):
    """
    Analyze image only for security risks and extract text
    """
    try:
        start_time = time.time()

        # Read image data
        image_data = await image.read()

        # Perform vision analysis only
        result = await agent.vision_agent.process_image(image_data)

        processing_time = time.time() - start_time

        return JSONResponse(
            content={
                'status': 'success',
                'result': result,
                'processing_time': processing_time,
                'image_info': {
                    'filename': image.filename,
                    'content_type': image.content_type,
                    'size': len(image_data),
                },
            }
        )

    except Exception as e:
        logger.error(f'Image-only analysis failed: {e}')
        raise HTTPException(status_code=500, detail=str(e))


@app.get('/health')
async def health_check():
    """Simple health check endpoint"""
    from utils.app_initializer import app_initializer

    health_status = app_initializer.get_health_status()

    overall_status = (
        'healthy'
        if all(
            health_status.get(service, False)
            for service in ['redis', 'postgres', 'llm']
        )
        else 'degraded'
    )

    return {
        'status': overall_status,
        'version': '2.0.0',
        'environment': config.detector.environment,
        'services': health_status,
    }


@app.get('/environment')
async def get_environment():
    """Get detailed environment configuration"""
    from utils.app_initializer import app_initializer

    return app_initializer.get_environment_info()


# Tool-specific endpoints using the new classes
@app.post('/tools/abuseipdb/check')
async def check_ip_abuseipdb(ip_address: str):
    """Check IP address using AbuseIPDB"""
    try:
        if not abuseipdb_client:
            raise HTTPException(
                status_code=503, detail='AbuseIPDB client not available'
            )

        result = await abuseipdb_client.check_ip(ip_address)
        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f'AbuseIPDB check failed: {e}')
        raise HTTPException(status_code=500, detail=str(e))


@app.post('/tools/shodan/lookup')
async def lookup_ip_shodan(ip_address: str):
    """Lookup IP address using Shodan"""
    try:
        if not shodan_client:
            raise HTTPException(status_code=503, detail='Shodan client not available')

        result = await shodan_client.lookup_ip(ip_address)
        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f'Shodan lookup failed: {e}')
        raise HTTPException(status_code=500, detail=str(e))


@app.post('/tools/virustotal/lookup')
async def lookup_resource_virustotal(resource: str, resource_type: str = 'ip'):
    """Lookup resource using VirusTotal"""
    try:
        if not virustotal_client:
            raise HTTPException(
                status_code=503, detail='VirusTotal client not available'
            )

        if resource_type == 'ip':
            result = await virustotal_client.lookup_ip(resource)
        elif resource_type == 'domain':
            result = await virustotal_client.lookup_domain(resource)
        elif resource_type == 'hash':
            result = await virustotal_client.lookup_file_hash(resource)
        else:
            result = await virustotal_client.search(resource)

        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f'VirusTotal lookup failed: {e}')
        raise HTTPException(status_code=500, detail=str(e))


@app.post('/tools/regex/extract')
async def extract_iocs_regex(text: str):
    """Extract IOCs from text using regex patterns"""
    try:
        if not regex_checker:
            raise HTTPException(status_code=503, detail='Regex checker not available')

        result = regex_checker.extract_all_iocs(text)
        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f'Regex extraction failed: {e}')
        raise HTTPException(status_code=500, detail=str(e))


@app.post('/tools/regex/validate')
async def validate_pattern_regex(text: str, pattern_type: str):
    """Validate specific pattern type in text"""
    try:
        if not regex_checker:
            raise HTTPException(status_code=503, detail='Regex checker not available')

        if pattern_type == 'ip':
            result = regex_checker.validate_ip(text)
        elif pattern_type == 'domain':
            result = regex_checker.validate_domain(text)
        elif pattern_type == 'hash':
            result = regex_checker.validate_hash(text)
        elif pattern_type == 'url':
            result = regex_checker.analyze_url(text)
        else:
            result = {'error': f'Unknown pattern type: {pattern_type}'}

        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f'Regex validation failed: {e}')
        raise HTTPException(status_code=500, detail=str(e))


# Error handlers
@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(
        status_code=404,
        content={'error': 'Endpoint not found', 'path': str(request.url.path)},
    )


@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    logger.error(f'Internal server error: {exc}')
    return JSONResponse(
        status_code=500, content={'error': 'Internal server error', 'detail': str(exc)}
    )


if __name__ == '__main__':
    import uvicorn

    uvicorn.run(
        'main:app',
        host='0.0.0.0',
        port=8000,
        reload=True,
        log_level=os.getenv('LOG_LEVEL', 'info').lower(),
    )
