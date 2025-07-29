# FastAPI server with Vision AI and ReAct workflow support - Async Version
from fastapi import FastAPI, File, UploadFile, Request, HTTPException, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any
import asyncio
import time
import os
from contextlib import asynccontextmanager
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Import our agents and components
from agents.supervisor import SupervisorAgent
from memory.redis_stm import RedisSTM
from vectorstore.milvus_client import init_milvus

# Import the new tool classes
from tools.abuseipdb import AbuseIPDBClient
from tools.shodan import ShodanClient
from tools.virustotal import VirusTotalClient
from tools.regex_checker import RegexChecker

# Configure structured logging
from utils.logging_config import setup_from_env, get_logger

# Setup logging from environment
setup_from_env()
logger = get_logger(__name__, component="server")


# Global variables for async components
memory = None
vectorstore = None
agent = None
abuseipdb_client = None
shodan_client = None
virustotal_client = None
regex_checker = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Async startup and shutdown for FastAPI app"""
    # Startup
    global memory, vectorstore, agent, abuseipdb_client, shodan_client, virustotal_client, regex_checker

    try:
        # Initialize async components
        memory = RedisSTM()
        await memory._get_redis()  # Initialize Redis connection

        vectorstore = init_milvus()

        # Initialize async tool clients first
        abuseipdb_client = AbuseIPDBClient()
        shodan_client = ShodanClient()
        virustotal_client = VirusTotalClient()
        regex_checker = RegexChecker()

        # Initialize agent with client instances
        logger.info("Initializing CyberShield components", react_workflow=True)
        agent = SupervisorAgent(memory, vectorstore, use_react_workflow=True,
                               abuseipdb_client=abuseipdb_client,
                               shodan_client=shodan_client,
                               virustotal_client=virustotal_client)
        logger.info("SupervisorAgent created", react_agent_enabled=agent.react_agent is not None)
        await agent.initialize_clients()

        logger.info("CyberShield initialization complete", components=["memory", "vectorstore", "agents", "tools"])
    except Exception as e:
        logger.error("Component initialization failed", error=str(e), fallback_mode=True)
        logger.debug("Creating fallback SupervisorAgent without ReAct workflow", exc_info=True)
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
        logger.info("CyberShield shutdown complete", status="success")
    except Exception as e:
        logger.error("Shutdown error", error=str(e))

# Initialize FastAPI app with async lifespan
app = FastAPI(
    title="CyberShield AI Security System",
    description="Async multi-agent AI system for cybersecurity analysis with Vision AI and ReAct workflow",
    version="2.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501"],  # Streamlit frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models for request/response
class AnalysisRequest(BaseModel):
    text: str
    use_react_workflow: Optional[bool] = True
    include_vision: Optional[bool] = False

class BatchAnalysisRequest(BaseModel):
    inputs: list[str]
    use_react_workflow: Optional[bool] = True

class AnalysisResponse(BaseModel):
    status: str
    result: Dict[str, Any]
    processing_time: Optional[float] = None

# Helper functions for safe async API calls
async def _safe_abuseipdb_check(ip: str) -> Dict[str, Any]:
    """Safely perform AbuseIPDB check with error handling"""
    try:
        result = await abuseipdb_client.check_ip(ip)
        return {"abuseipdb": result}
    except Exception as e:
        logger.error(f"AbuseIPDB check failed for {ip}: {e}")
        return {"abuseipdb": {"error": str(e)}}

async def _safe_shodan_lookup(ip: str) -> Dict[str, Any]:
    """Safely perform Shodan lookup with error handling"""
    try:
        result = await shodan_client.lookup_ip(ip)
        return {"shodan": result}
    except Exception as e:
        logger.error(f"Shodan lookup failed for {ip}: {e}")
        return {"shodan": {"error": str(e)}}

async def _safe_virustotal_lookup(ip: str) -> Dict[str, Any]:
    """Safely perform VirusTotal IP lookup with error handling"""
    try:
        result = await virustotal_client.lookup_ip(ip)
        return {"virustotal": result}
    except Exception as e:
        logger.error(f"VirusTotal IP lookup failed for {ip}: {e}")
        return {"virustotal": {"error": str(e)}}

async def _safe_domain_lookup(domain: str) -> Dict[str, Any]:
    """Safely perform VirusTotal domain lookup with error handling"""
    try:
        result = await virustotal_client.lookup_domain(domain)
        return {domain: result}
    except Exception as e:
        logger.error(f"Domain lookup failed for {domain}: {e}")
        return {domain: {"error": str(e)}}

async def _safe_hash_lookup(hash_value: str) -> Dict[str, Any]:
    """Safely perform VirusTotal hash lookup with error handling"""
    try:
        result = await virustotal_client.lookup_file_hash(hash_value)
        return {hash_value: result}
    except Exception as e:
        logger.error(f"Hash lookup failed for {hash_value}: {e}")
        return {hash_value: {"error": str(e)}}

@app.get("/")
async def root():
    """API root endpoint with basic information"""
    return {
        "message": "CyberShield AI Security System",
        "version": "2.0.0",
        "description": "Multi-agent AI system for cybersecurity analysis with Vision AI and ReAct workflow",
        "frontend": "Streamlit UI available at http://localhost:8501",
        "docs": "Interactive API documentation at /docs",
        "status": "GET /status for system information"
    }

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_text(request: AnalysisRequest):
    """
    Analyze text input for security threats, PII, and IOCs
    """
    start_time = time.time()
    request_logger = logger.bind(endpoint="analyze", react_workflow=request.use_react_workflow)

    try:
        request_logger.info("Analysis request started", text_length=len(request.text))

        # Configure agent workflow
        if hasattr(agent, 'use_react_workflow'):
            agent.use_react_workflow = request.use_react_workflow

        # Perform analysis with agent
        result = await agent.analyze(request.text)

        # analysis with tool classes if available
        tool_results = {}

        # Extract IOCs using regex checker
        if regex_checker:
            try:
                iocs = regex_checker.extract_all_iocs(request.text)
                tool_results["ioc_extraction"] = iocs

                # Perform threat intelligence lookups for extracted IPs
                if "public_ipv4" in iocs:
                    threat_intel = {}
                    for ip in iocs["public_ipv4"][:3]:  # Limit to first 3 IPs
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
                            lookup_results = await asyncio.gather(*lookup_tasks, return_exceptions=True)
                            for result in lookup_results:
                                if isinstance(result, dict):
                                    ip_results.update(result)
                                elif isinstance(result, Exception):
                                    logger.error(f"Lookup failed: {result}")

                        threat_intel[ip] = ip_results

                    tool_results["threat_intelligence"] = threat_intel

                # Check domains
                if "domain" in iocs:
                    domain_results = {}
                    # Concurrent domain lookups
                    domain_tasks = []
                    for domain in iocs["domain"][:3]:  # Limit to first 3 domains
                        if virustotal_client:
                            domain_tasks.append(_safe_domain_lookup(domain))

                    if domain_tasks:
                        domain_lookup_results = await asyncio.gather(*domain_tasks, return_exceptions=True)
                        for result in domain_lookup_results:
                            if isinstance(result, dict):
                                domain_results.update(result)
                            elif isinstance(result, Exception):
                                logger.error(f"Domain lookup failed: {result}")

                    tool_results["domain_analysis"] = domain_results

                # Check hashes
                if any(hash_type in iocs for hash_type in ["md5", "sha1", "sha256"]):
                    hash_results = {}
                    for hash_type in ["md5", "sha1", "sha256"]:
                        if hash_type in iocs:
                            # Concurrent hash lookups
                            hash_tasks = []
                            for hash_value in iocs[hash_type][:2]:  # Limit to first 2 hashes
                                if virustotal_client:
                                    hash_tasks.append(_safe_hash_lookup(hash_value))

                            if hash_tasks:
                                hash_lookup_results = await asyncio.gather(*hash_tasks, return_exceptions=True)
                                for result in hash_lookup_results:
                                    if isinstance(result, dict):
                                        hash_results.update(result)
                                    elif isinstance(result, Exception):
                                        logger.error(f"Hash lookup failed: {result}")

                    tool_results["hash_analysis"] = hash_results

            except Exception as e:
                logger.error(f"Tool analysis failed: {e}")
                tool_results["error"] = str(e)

        # Merge tool results with agent results
        if tool_results:
            result["tool_analysis"] = tool_results

        processing_time = time.time() - start_time

        request_logger.info(
            "Analysis request completed",
            status="success",
            processing_time_ms=round(processing_time * 1000, 2),
            tool_analysis_included=bool(tool_results)
        )

        return AnalysisResponse(
            status="success",
            result=result,
            processing_time=processing_time
        )

    except Exception as e:
        processing_time = time.time() - start_time
        request_logger.error(
            "Analysis request failed",
            error=str(e),
            processing_time_ms=round(processing_time * 1000, 2)
        )
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze-with-image")
async def analyze_with_image(
    text: str = Form(...),
    image: UploadFile = File(...),
    use_react_workflow: bool = Form(True)
):
    """
    Analyze text and image content for security risks
    """
    try:
        start_time = time.time()

        # Read image data
        image_data = await image.read()

        # Configure agent workflow
        if hasattr(agent, 'use_react_workflow'):
            agent.use_react_workflow = use_react_workflow

        # Perform analysis with image
        result = await agent.analyze(text, image_data)

        processing_time = time.time() - start_time

        return JSONResponse(content={
            "status": "success",
            "result": result,
            "processing_time": processing_time,
            "image_info": {
                "filename": image.filename,
                "content_type": image.content_type,
                "size": len(image_data)
            }
        })

    except Exception as e:
        logger.error(f"Image analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/batch-analyze")
async def batch_analyze(request: BatchAnalysisRequest):
    """
    Analyze multiple text inputs in batch
    """
    try:
        start_time = time.time()

        # Configure agent workflow
        if hasattr(agent, 'use_react_workflow'):
            agent.use_react_workflow = request.use_react_workflow

        # Perform batch analysis
        results = await agent.analyze_batch(request.inputs)

        processing_time = time.time() - start_time

        return JSONResponse(content={
            "status": "success",
            "results": results,
            "processing_time": processing_time,
            "batch_size": len(request.inputs)
        })

    except Exception as e:
        logger.error(f"Batch analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/status")
async def get_status():
    """
    Get system status and agent information
    """
    try:
        agent_status = agent.get_agent_status()

        # Check tool availability
        tools_status = {
            "abuseipdb": abuseipdb_client is not None,
            "shodan": shodan_client is not None,
            "virustotal": virustotal_client is not None,
            "regex_checker": regex_checker is not None
        }

        return JSONResponse(content={
            "status": "online",
            "version": "2.0.0",
            "features": [
                "Vision AI",
                "ReAct Workflow",
                "Multi-Agent Analysis",
                "PII Detection",
                "Threat Intelligence",
                "IOC Extraction",
                "Tool Classes"
            ],
            "agents": agent_status,
            "tools": tools_status,
            "endpoints": {
                "analyze": "POST /analyze",
                "analyze_with_image": "POST /analyze-with-image",
                "batch_analyze": "POST /batch-analyze",
                "status": "GET /status",
                "tools": {
                    "abuseipdb_check": "POST /tools/abuseipdb/check",
                    "shodan_lookup": "POST /tools/shodan/lookup",
                    "virustotal_lookup": "POST /tools/virustotal/lookup",
                    "regex_extract": "POST /tools/regex/extract",
                    "regex_validate": "POST /tools/regex/validate"
                }
            }
        })

    except Exception as e:
        logger.error(f"Status check failed: {e}")
        return JSONResponse(
            status_code=500,
            content={"status": "error", "error": str(e)}
        )

@app.post("/upload-image")
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

        return JSONResponse(content={
            "status": "success",
            "result": result,
            "processing_time": processing_time,
            "image_info": {
                "filename": image.filename,
                "content_type": image.content_type,
                "size": len(image_data)
            }
        })

    except Exception as e:
        logger.error(f"Image-only analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Simple health check endpoint"""
    return {"status": "healthy", "version": "2.0.0"}

# Tool-specific endpoints using the new classes
@app.post("/tools/abuseipdb/check")
async def check_ip_abuseipdb(ip_address: str):
    """Check IP address using AbuseIPDB"""
    try:
        if not abuseipdb_client:
            raise HTTPException(status_code=503, detail="AbuseIPDB client not available")

        result = await abuseipdb_client.check_ip(ip_address)
        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f"AbuseIPDB check failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tools/shodan/lookup")
async def lookup_ip_shodan(ip_address: str):
    """Lookup IP address using Shodan"""
    try:
        if not shodan_client:
            raise HTTPException(status_code=503, detail="Shodan client not available")

        result = await shodan_client.lookup_ip(ip_address)
        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f"Shodan lookup failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tools/virustotal/lookup")
async def lookup_resource_virustotal(resource: str, resource_type: str = "ip"):
    """Lookup resource using VirusTotal"""
    try:
        if not virustotal_client:
            raise HTTPException(status_code=503, detail="VirusTotal client not available")

        if resource_type == "ip":
            result = await virustotal_client.lookup_ip(resource)
        elif resource_type == "domain":
            result = await virustotal_client.lookup_domain(resource)
        elif resource_type == "hash":
            result = await virustotal_client.lookup_file_hash(resource)
        else:
            result = await virustotal_client.search(resource)

        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f"VirusTotal lookup failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tools/regex/extract")
async def extract_iocs_regex(text: str):
    """Extract IOCs from text using regex patterns"""
    try:
        if not regex_checker:
            raise HTTPException(status_code=503, detail="Regex checker not available")

        result = regex_checker.extract_all_iocs(text)
        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f"Regex extraction failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tools/regex/validate")
async def validate_pattern_regex(text: str, pattern_type: str):
    """Validate specific pattern type in text"""
    try:
        if not regex_checker:
            raise HTTPException(status_code=503, detail="Regex checker not available")

        if pattern_type == "ip":
            result = regex_checker.validate_ip(text)
        elif pattern_type == "domain":
            result = regex_checker.validate_domain(text)
        elif pattern_type == "hash":
            result = regex_checker.validate_hash(text)
        elif pattern_type == "url":
            result = regex_checker.analyze_url(text)
        else:
            result = {"error": f"Unknown pattern type: {pattern_type}"}

        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f"Regex validation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Error handlers
@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(
        status_code=404,
        content={"error": "Endpoint not found", "path": str(request.url.path)}
    )

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    logger.error(f"Internal server error: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc)}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level=os.getenv("LOG_LEVEL", "info").lower()
    )