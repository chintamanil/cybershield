# ReAct workflow using LangGraph for CyberShield
#
# Debug Logging:
# To enable detailed debug logging of final reports, set environment variable:
#   LOG_LEVEL=DEBUG
#
# For JSON format debug output, also set:
#   REACT_LOG_FORMAT=json
#
from typing import Dict, List, Optional, Any, TypedDict, Annotated
import os
import asyncio
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from utils.logging_config import get_security_logger
from utils.device_config import create_performance_config

logger = get_security_logger("react_workflow")

# Placeholder: LangGraph DAG execution model for ReAct agent flow
# Define StateGraph and wire up SupervisorAgent -> PII -> LogParser -> ThreatAgent -> Summary


def threat_results_reducer(existing: List[Dict], new: List[Dict]) -> List[Dict]:
    """Reducer to aggregate threat intelligence results"""
    if not existing:
        return new
    return existing + new


def messages_reducer(existing: List[Any], new: List[Any]) -> List[Any]:
    """Reducer to handle message updates"""
    if not existing:
        return new
    return existing + new


def input_text_reducer(existing: str, new: str) -> str:
    """Reducer to handle input_text updates - keep the original"""
    return existing if existing else new


def routing_decision_reducer(
    existing: Optional[str], new: Optional[str]
) -> Optional[str]:
    """Reducer to handle routing_decision updates"""
    return new if new is not None else existing


def selected_tools_reducer(
    existing: Optional[List[str]], new: Optional[List[str]]
) -> Optional[List[str]]:
    """Reducer to handle selected_threat_tools updates"""
    return new if new is not None else existing


def input_image_reducer(
    existing: Optional[bytes], new: Optional[bytes]
) -> Optional[bytes]:
    """Reducer to handle input_image updates"""
    return new if new is not None else existing


def extracted_iocs_reducer(
    existing: Optional[Dict], new: Optional[Dict]
) -> Optional[Dict]:
    """Reducer to handle extracted_iocs updates"""
    return new if new is not None else existing


class CyberShieldState(TypedDict):
    """State schema for CyberShield ReAct workflow"""

    messages: Annotated[List[Any], messages_reducer]
    input_text: Annotated[str, input_text_reducer]
    input_image: Annotated[Optional[bytes], input_image_reducer]
    pii_masked_text: Optional[str]
    pii_mapping: Optional[Dict]
    extracted_iocs: Annotated[Optional[Dict], extracted_iocs_reducer]
    threat_analysis: Optional[Dict]
    vision_analysis: Optional[Dict]
    final_report: Optional[Dict]
    next_action: Optional[str]
    tool_calls: List[Dict]
    agent_scratchpad: str
    iteration_count: int
    # Parallel tool results with reducer for fan-in
    threat_results: Annotated[List[Dict], threat_results_reducer]
    dynamic_tool_results: Optional[Dict]
    routing_decision: Annotated[Optional[str], routing_decision_reducer]
    selected_threat_tools: Annotated[Optional[List[str]], selected_tools_reducer]


class CyberShieldReActAgent:
    """ReAct agent using LangGraph for cybersecurity analysis"""

    def __init__(
        self,
        memory=None,
        vectorstore=None,
        llm_model="gpt-4o",
        abuseipdb_client=None,
        shodan_client=None,
        virustotal_client=None,
    ):
        self.memory = memory
        self.vectorstore = vectorstore
        self.abuseipdb_client = abuseipdb_client
        self.shodan_client = shodan_client
        self.virustotal_client = virustotal_client

        # Get performance configuration for M4 optimization
        self.perf_config = create_performance_config()

        logger.info(
            "Initializing ReAct workflow with M4 optimization",
            llm_model=llm_model,
            device=self.perf_config["device"],
            batch_size=self.perf_config["batch_size"],
            memory_optimization=self.perf_config["memory_optimization"],
        )

        # Import agents here to avoid circular imports
        from agents.pii_agent import PIIAgent
        from agents.log_parser import LogParserAgent
        from agents.threat_agent import ThreatAgent
        from agents.vision_agent import VisionAgent
        from tools.regex_checker import RegexChecker

        self.pii_agent = PIIAgent(memory)
        self.log_parser = LogParserAgent()
        self.threat_agent = ThreatAgent(memory)

        # Initialize RegexChecker for IOC extraction
        self.regex_checker = RegexChecker()

        # Initialize threat agent with client instances if available
        if abuseipdb_client:
            self.threat_agent.abuseipdb_client = abuseipdb_client
        if shodan_client:
            self.threat_agent.shodan_client = shodan_client
        if virustotal_client:
            self.threat_agent.virustotal_client = virustotal_client
        self.vision_agent = VisionAgent(memory)

        # Initialize LLM
        self.llm = ChatOpenAI(model=llm_model, temperature=0)

        # Create the workflow graph
        self.workflow = self._create_workflow()

    async def _generate_cache_key(self, operation: str, input_text: str) -> str:
        """Generate consistent cache key for operations"""
        import hashlib

        # Create hash of input text for consistent caching
        text_hash = hashlib.md5(input_text.encode()).hexdigest()[:16]
        return f"cybershield:{operation}:{text_hash}"

    def _create_workflow(self) -> StateGraph:
        """Create the hybrid LangGraph workflow using proper fan-out/fan-in pattern"""
        builder = StateGraph(CyberShieldState)

        # Add nodes
        builder.add_node("Supervisor", self._supervisor_step)
        builder.add_node("ThreatIntel", self._threat_intel_step)
        builder.add_node("VirusScanner", self._virustotal_step)
        builder.add_node("AbuseIPDB", self._abuseipdb_step)
        builder.add_node("Shodan", self._shodan_step)
        builder.add_node("MilvusSearch", self._milvus_search_step)
        builder.add_node("RegexChecker", self._regex_checker_step)
        builder.add_node("ToolExecutorNode", self._dynamic_tool_executor)
        builder.add_node("synthesize", self._synthesize_step)

        # Set entry point
        builder.set_entry_point("Supervisor")

        # Main routing from supervisor
        builder.add_conditional_edges(
            "Supervisor",
            self._route_from_supervisor,
            {
                "ThreatIntel": "ThreatIntel",
                "ToolExecutorNode": "ToolExecutorNode",
                "synthesize": "synthesize",
            },
        )

        # ThreatIntel fan-out: route to LLM-selected threat intelligence tools
        builder.add_conditional_edges(
            "ThreatIntel",
            self._route_threat_intel_tools,
            {
                "VirusScanner": "VirusScanner",
                "AbuseIPDB": "AbuseIPDB",
                "Shodan": "Shodan",
                "MilvusSearch": "MilvusSearch",
                "RegexChecker": "RegexChecker",
            },
        )

        # Fan-in: All parallel tools go to synthesis (aggregation happens via reducer)
        builder.add_edge("VirusScanner", "synthesize")
        builder.add_edge("AbuseIPDB", "synthesize")
        builder.add_edge("Shodan", "synthesize")
        builder.add_edge("MilvusSearch", "synthesize")
        builder.add_edge("RegexChecker", "synthesize")

        # Dynamic tool executor for LLM-chosen tools using asyncio.gather
        builder.add_edge("ToolExecutorNode", "synthesize")

        # End at synthesis
        builder.add_edge("synthesize", END)

        return builder.compile()

    async def _supervisor_step(self, state: CyberShieldState) -> CyberShieldState:
        """Supervisor step - analyze input and decide on tool routing with caching"""
        iteration = state.get("iteration_count", 0)
        logger.info(
            f"Supervisor reasoning step {iteration}",
            scratchpad_length=len(state.get("agent_scratchpad", "")),
        )
        try:
            input_text = state.get("input_text", "")
            cache_key = await self._generate_cache_key("routing_decision", input_text)

            # Check cache first
            if self.memory:
                try:
                    cached_routing = await self.memory.get(cache_key)
                    if cached_routing:
                        logger.info(
                            f"Retrieved cached routing decision: {cached_routing}"
                        )
                        state["routing_decision"] = cached_routing
                        state["iteration_count"] = iteration + 1
                        return state
                except Exception as e:
                    logger.warning(f"Cache retrieval failed: {e}")

            # Use LLM to analyze input and determine routing
            routing_decision = await self._analyze_for_routing(state)
            state["routing_decision"] = routing_decision
            state["iteration_count"] = iteration + 1

            # Cache the routing decision
            if self.memory:
                try:
                    await self.memory.set(
                        cache_key, routing_decision, ttl=1800
                    )  # 30 minutes
                    logger.info(f"Cached routing decision: {routing_decision}")
                except Exception as e:
                    logger.warning(f"Cache storage failed: {e}")

            logger.info(
                f"Supervisor routing decision: {routing_decision}",
                iteration=iteration,
                input_analysis=self._get_input_analysis(state),
                cached=False,
            )

            return state

        except Exception as e:
            logger.error(f"Supervisor step failed: {e}")
            state["routing_decision"] = "synthesize"
            state["final_report"] = {"error": str(e)}
            return state

    async def _analyze_for_routing(self, state: CyberShieldState) -> str:
        """Use LLM to analyze input and determine optimal tool routing strategy"""
        input_text = state.get("input_text", "")
        has_image = state.get("input_image") is not None

        # Use LLM to make intelligent routing decision
        routing_prompt = f"""Analyze this cybersecurity input and determine the best processing approach:

Input: {input_text[:1000]}...
Has Image: {has_image}

Routing Options:
1. "ThreatIntel" - For inputs with clear IOCs (IPs, domains, hashes) that need parallel threat intelligence analysis
2. "ToolExecutorNode" - For complex inputs requiring dynamic tool selection and comprehensive analysis
3. "synthesize" - For simple inputs that don't require extensive tool analysis

Consider:
- Presence of IP addresses, domains, file hashes
- Complexity and length of input
- Whether image analysis is needed
- Security relevance and threat indicators

Respond with only one word: ThreatIntel, ToolExecutorNode, or synthesize"""

        try:
            response = await self.llm.ainvoke([HumanMessage(content=routing_prompt)])
            routing_decision = response.content.strip()

            # Validate routing decision
            valid_routes = ["ThreatIntel", "ToolExecutorNode", "synthesize"]
            if routing_decision not in valid_routes:
                logger.warning(
                    f"Invalid routing decision: {routing_decision}, defaulting to ToolExecutorNode"
                )
                return "ToolExecutorNode"

            return routing_decision

        except Exception as e:
            logger.error(f"LLM routing failed: {e}, defaulting to ToolExecutorNode")
            return "ToolExecutorNode"

    def _get_input_analysis(self, state: CyberShieldState) -> Dict:
        """Get analysis of input for logging"""
        input_text = state.get("input_text", "")
        return {
            "text_length": len(input_text),
            "has_image": state.get("input_image") is not None,
            "has_ips": bool(
                __import__("re").search(
                    r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", input_text
                )
            ),
            "has_domains": bool(
                __import__("re").search(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", input_text)
            ),
            "has_hashes": bool(
                __import__("re").search(r"\b[a-fA-F0-9]{32,}\b", input_text)
            ),
        }

    async def _threat_intel_step(self, state: CyberShieldState) -> CyberShieldState:
        """Threat intelligence coordination step - uses LLM to select appropriate tools with caching"""
        logger.info(
            "ThreatIntel coordination step", iteration=state.get("iteration_count", 0)
        )

        input_text = state.get("input_text", "")
        cache_key = await self._generate_cache_key("tool_selection", input_text)

        # Check cache for tool selection
        if self.memory:
            try:
                cached_selection = await self.memory.get(cache_key)
                if cached_selection:
                    logger.info(f"Retrieved cached tool selection: {cached_selection}")
                    # Extract IOCs for the cached tools
                    ips = __import__("re").findall(
                        r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", input_text
                    )
                    domains = __import__("re").findall(
                        r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", input_text
                    )
                    hashes = __import__("re").findall(
                        r"\b[a-fA-F0-9]{32,}\b", input_text
                    )

                    state["extracted_iocs"] = {
                        "ips": list(set(ips)),
                        "domains": list(set(domains)),
                        "hashes": list(set(hashes)),
                    }
                    state["selected_threat_tools"] = cached_selection
                    return state
            except Exception as e:
                logger.warning(f"Cache retrieval failed: {e}")

        # Use LLM to determine which threat intelligence tools to use
        tool_selection_prompt = f"""Analyze this cybersecurity input and select the most appropriate threat intelligence tools:

Input: {input_text[:800]}...

Available Tools:
- VirusTotal: Best for IP addresses, domains, and file hashes
- AbuseIPDB: Specialized for IP reputation and abuse reports  
- Shodan: Network reconnaissance and open port analysis for IPs
- MilvusSearch: Historical attack pattern analysis using 120,000 cybersecurity records
- RegexChecker: Comprehensive IOC extraction using 25+ cybersecurity patterns

Based on the input content, which tools should be used? Consider:
- What types of IOCs are present (IPs, domains, hashes)
- The context and nature of the security incident
- Tool capabilities and API limitations

Respond with a JSON array of tool names to use:
["VirusTotal", "AbuseIPDB", "Shodan", "MilvusSearch", "RegexChecker"]

If no threat intelligence tools are needed, respond with: []"""

        try:
            response = await self.llm.ainvoke(
                [HumanMessage(content=tool_selection_prompt)]
            )

            # Parse tool selection from LLM response
            import json
            import re

            json_match = re.search(r"\[.*?\]", response.content, re.DOTALL)
            if json_match:
                selected_tools = json.loads(json_match.group())
            else:
                # Fallback: extract IOCs and use all tools if IOCs found
                ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", input_text)
                domains = re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", input_text)
                hashes = re.findall(r"\b[a-fA-F0-9]{32,}\b", input_text)

                if ips or domains or hashes:
                    selected_tools = [
                        "VirusTotal",
                        "AbuseIPDB",
                        "Shodan",
                        "MilvusSearch",
                        "RegexChecker",
                    ]
                else:
                    selected_tools = [
                        "RegexChecker"
                    ]  # Always use RegexChecker for IOC extraction

            # Extract IOCs for selected tools
            ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", input_text)
            domains = re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", input_text)
            hashes = re.findall(r"\b[a-fA-F0-9]{32,}\b", input_text)

            state["extracted_iocs"] = {
                "ips": list(set(ips)),
                "domains": list(set(domains)),
                "hashes": list(set(hashes)),
            }
            state["selected_threat_tools"] = selected_tools

            # Cache the tool selection
            if self.memory:
                try:
                    await self.memory.set(
                        cache_key, selected_tools, ttl=1800
                    )  # 30 minutes
                    logger.info(f"Cached tool selection: {selected_tools}")
                except Exception as e:
                    logger.warning(f"Cache storage failed: {e}")

            logger.info(
                "LLM selected threat intelligence tools",
                selected_tools=selected_tools,
                ips_count=len(ips),
                domains_count=len(domains),
                hashes_count=len(hashes),
                cached=False,
            )

            return state

        except Exception as e:
            logger.error(f"LLM tool selection failed: {e}")
            # Fallback to all tools
            ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", input_text)
            domains = re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", input_text)
            hashes = re.findall(r"\b[a-fA-F0-9]{32,}\b", input_text)

            state["extracted_iocs"] = {
                "ips": list(set(ips)),
                "domains": list(set(domains)),
                "hashes": list(set(hashes)),
            }
            state["selected_threat_tools"] = (
                ["VirusTotal", "AbuseIPDB", "Shodan", "MilvusSearch", "RegexChecker"]
                if (ips or domains or hashes)
                else ["RegexChecker"]
            )

            return state

    async def _virustotal_step(self, state: CyberShieldState) -> CyberShieldState:
        """VirusTotal analysis step with caching"""
        logger.info("VirusTotal analysis step")

        try:
            if not self.virustotal_client:
                return {
                    **state,
                    "threat_results": [
                        {
                            "tool": "VirusTotal",
                            "error": "VirusTotal client not available",
                        }
                    ],
                }

            iocs = state.get("extracted_iocs", {})
            input_text = state.get("input_text", "")
            cache_key = await self._generate_cache_key("virustotal", input_text)

            # Check cache first
            if self.memory:
                try:
                    cached_result = await self.memory.get(cache_key)
                    if cached_result:
                        logger.info("Retrieved cached VirusTotal results")
                        return {**state, "threat_results": [cached_result]}
                except Exception as e:
                    logger.warning(f"VirusTotal cache retrieval failed: {e}")

            results = []

            # Process IPs
            for ip in iocs.get("ips", [])[:5]:  # Limit to 5 for rate limiting
                try:
                    result = await self.virustotal_client.lookup_ip(ip)
                    results.append({"type": "ip", "value": ip, "result": result})
                except Exception as e:
                    results.append({"type": "ip", "value": ip, "error": str(e)})

            # Process domains
            for domain in iocs.get("domains", [])[:5]:
                try:
                    result = await self.virustotal_client.lookup_domain(domain)
                    results.append(
                        {"type": "domain", "value": domain, "result": result}
                    )
                except Exception as e:
                    results.append({"type": "domain", "value": domain, "error": str(e)})

            # Prepare result for caching and return
            vt_result = {"tool": "VirusTotal", "analysis": results, "status": "success"}

            # Cache the result
            if self.memory:
                try:
                    await self.memory.set(cache_key, vt_result, ttl=3600)  # 1 hour
                    logger.info("Cached VirusTotal results")
                except Exception as e:
                    logger.warning(f"VirusTotal cache storage failed: {e}")

            return {**state, "threat_results": [vt_result]}

        except Exception as e:
            logger.error(f"VirusTotal step failed: {e}")
            return {
                **state,
                "threat_results": [{"tool": "VirusTotal", "error": str(e)}],
            }

    async def _abuseipdb_step(self, state: CyberShieldState) -> CyberShieldState:
        """AbuseIPDB analysis step with caching"""
        logger.info("AbuseIPDB analysis step")

        try:
            if not self.abuseipdb_client:
                return {
                    **state,
                    "threat_results": [
                        {"tool": "AbuseIPDB", "error": "AbuseIPDB client not available"}
                    ],
                }

            iocs = state.get("extracted_iocs", {})
            input_text = state.get("input_text", "")
            cache_key = await self._generate_cache_key("abuseipdb", input_text)

            # Check cache first
            if self.memory:
                try:
                    cached_result = await self.memory.get(cache_key)
                    if cached_result:
                        logger.info("Retrieved cached AbuseIPDB results")
                        return {**state, "threat_results": [cached_result]}
                except Exception as e:
                    logger.warning(f"AbuseIPDB cache retrieval failed: {e}")

            results = []

            # Process IPs only (AbuseIPDB is IP-focused)
            for ip in iocs.get("ips", [])[:10]:  # Higher limit for AbuseIPDB
                try:
                    result = await self.abuseipdb_client.check_ip(ip)
                    results.append({"type": "ip", "value": ip, "result": result})
                except Exception as e:
                    results.append({"type": "ip", "value": ip, "error": str(e)})

            # Prepare result for caching and return
            abuse_result = {
                "tool": "AbuseIPDB",
                "analysis": results,
                "status": "success",
            }

            # Cache the result
            if self.memory:
                try:
                    await self.memory.set(cache_key, abuse_result, ttl=3600)  # 1 hour
                    logger.info("Cached AbuseIPDB results")
                except Exception as e:
                    logger.warning(f"AbuseIPDB cache storage failed: {e}")

            return {**state, "threat_results": [abuse_result]}

        except Exception as e:
            logger.error(f"AbuseIPDB step failed: {e}")
            return {**state, "threat_results": [{"tool": "AbuseIPDB", "error": str(e)}]}

    async def _shodan_step(self, state: CyberShieldState) -> CyberShieldState:
        """Shodan analysis step with caching"""
        logger.info("Shodan analysis step")

        try:
            if not self.shodan_client:
                return {
                    **state,
                    "threat_results": [
                        {"tool": "Shodan", "error": "Shodan client not available"}
                    ],
                }

            iocs = state.get("extracted_iocs", {})
            input_text = state.get("input_text", "")
            cache_key = await self._generate_cache_key("shodan", input_text)

            # Check cache first
            if self.memory:
                try:
                    cached_result = await self.memory.get(cache_key)
                    if cached_result:
                        logger.info("Retrieved cached Shodan results")
                        return {**state, "threat_results": [cached_result]}
                except Exception as e:
                    logger.warning(f"Shodan cache retrieval failed: {e}")

            results = []

            # Process IPs
            for ip in iocs.get("ips", [])[:5]:  # Conservative limit for Shodan
                try:
                    result = await self.shodan_client.lookup_ip(ip)
                    results.append({"type": "ip", "value": ip, "result": result})
                except Exception as e:
                    results.append({"type": "ip", "value": ip, "error": str(e)})

            # Prepare result for caching and return
            shodan_result = {"tool": "Shodan", "analysis": results, "status": "success"}

            # Cache the result
            if self.memory:
                try:
                    await self.memory.set(cache_key, shodan_result, ttl=3600)  # 1 hour
                    logger.info("Cached Shodan results")
                except Exception as e:
                    logger.warning(f"Shodan cache storage failed: {e}")

            return {**state, "threat_results": [shodan_result]}

        except Exception as e:
            logger.error(f"Shodan step failed: {e}")
            return {**state, "threat_results": [{"tool": "Shodan", "error": str(e)}]}

    async def _milvus_search_step(self, state: CyberShieldState) -> CyberShieldState:
        """Milvus vector search step for historical attack data"""
        logger.info("Milvus vector search step")

        try:
            if not self.vectorstore:
                return {
                    **state,
                    "threat_results": [
                        {
                            "tool": "MilvusSearch",
                            "error": "Milvus vectorstore not available",
                        }
                    ],
                }

            input_text = state.get("input_text", "")
            iocs = state.get("extracted_iocs", {})
            results = []

            # Search for similar attack patterns
            if input_text:
                try:
                    # Search for similar attacks using the input text
                    search_results = await self.vectorstore.search_similar_attacks(
                        input_text, limit=5
                    )
                    results.append(
                        {
                            "type": "similar_attacks",
                            "query": input_text[:100] + "...",
                            "results": search_results,
                        }
                    )
                except Exception as e:
                    results.append(
                        {
                            "type": "similar_attacks",
                            "query": input_text[:100] + "...",
                            "error": str(e),
                        }
                    )

            # Search for specific IOCs in historical data
            for ip in iocs.get("ips", [])[:3]:  # Limit to 3 IPs
                try:
                    ip_results = await self.vectorstore.search_by_ioc("ip", ip)
                    results.append(
                        {"type": "ip_history", "value": ip, "results": ip_results}
                    )
                except Exception as e:
                    results.append({"type": "ip_history", "value": ip, "error": str(e)})

            return {
                **state,
                "threat_results": [
                    {"tool": "MilvusSearch", "analysis": results, "status": "success"}
                ],
            }

        except Exception as e:
            logger.error(f"Milvus search step failed: {e}")
            return {
                **state,
                "threat_results": [{"tool": "MilvusSearch", "error": str(e)}],
            }

    async def _regex_checker_step(self, state: CyberShieldState) -> CyberShieldState:
        """RegexChecker IOC extraction and validation step"""
        logger.info("RegexChecker IOC extraction step")

        try:
            input_text = state.get("input_text", "")
            if not input_text:
                return {
                    **state,
                    "threat_results": [
                        {"tool": "RegexChecker", "error": "No input text provided"}
                    ],
                }

            # Extract all IOCs using comprehensive regex patterns
            ioc_results = self.regex_checker.extract_all_iocs(input_text)

            # Validate specific IOC types
            validation_results = []

            # Validate IPs if found
            for ip in ioc_results.get("ipv4", []):
                validation = self.regex_checker.validate_ip(ip)
                validation_results.append(
                    {"type": "ip_validation", "value": ip, "validation": validation}
                )

            # Validate domains if found
            for domain in ioc_results.get("domain", []):
                validation = self.regex_checker.validate_domain(domain)
                validation_results.append(
                    {
                        "type": "domain_validation",
                        "value": domain,
                        "validation": validation,
                    }
                )

            # Validate hashes if found
            for hash_type in ["md5", "sha1", "sha256"]:
                for hash_value in ioc_results.get(hash_type, []):
                    validation = self.regex_checker.validate_hash(hash_value)
                    validation_results.append(
                        {
                            "type": "hash_validation",
                            "value": hash_value,
                            "hash_type": hash_type,
                            "validation": validation,
                        }
                    )

            results = {
                "extracted_iocs": ioc_results,
                "validations": validation_results,
                "summary": {
                    "total_iocs": sum(
                        len(v) if isinstance(v, list) else 0
                        for v in ioc_results.values()
                    ),
                    "ioc_types_found": list(ioc_results.keys()),
                    "validations_performed": len(validation_results),
                },
            }

            return {
                **state,
                "threat_results": [
                    {"tool": "RegexChecker", "analysis": results, "status": "success"}
                ],
            }

        except Exception as e:
            logger.error(f"RegexChecker step failed: {e}")
            return {
                **state,
                "threat_results": [{"tool": "RegexChecker", "error": str(e)}],
            }

    async def _dynamic_tool_executor(self, state: CyberShieldState) -> CyberShieldState:
        """Dynamic tool executor using asyncio.gather for LLM-chosen tools"""
        logger.info(
            "Dynamic tool executor step", iteration=state.get("iteration_count", 0)
        )

        try:
            # Use LLM to determine which tools to use dynamically
            tool_selection = await self._select_dynamic_tools(state)

            if not tool_selection:
                state["dynamic_tool_results"] = {"message": "No dynamic tools needed"}
                return state

            import time

            start_time = time.time()

            logger.info(
                f"🚀 Executing {len(tool_selection)} dynamic tools with asyncio.gather",
                tools=[tool["name"] for tool in tool_selection],
            )

            # Create tasks for dynamic tool execution
            async def execute_dynamic_tool(tool_spec):
                tool_name = tool_spec["name"]
                tool_input = tool_spec["input"]

                logger.info(f"🔧 Dynamic Action: {tool_name}", action_input=tool_input)

                result = await self._execute_tool(tool_name, tool_input, state)
                return tool_name, tool_input, result

            # Execute all dynamic tools concurrently using asyncio.gather
            concurrent_tasks = [
                execute_dynamic_tool(tool_spec) for tool_spec in tool_selection
            ]
            tool_results = await asyncio.gather(
                *concurrent_tasks, return_exceptions=True
            )

            # Process and aggregate results
            aggregated_results = {}
            for i, result in enumerate(tool_results):
                if isinstance(result, Exception):
                    tool_name = tool_selection[i]["name"]
                    logger.error(f"Dynamic tool {tool_name} failed: {result}")
                    aggregated_results[tool_name] = {"error": str(result)}
                    continue

                tool_name, tool_input, tool_result = result
                aggregated_results[tool_name] = tool_result

                logger.info(
                    f"👁️ Dynamic Observation: {tool_name}",
                    success="error" not in str(tool_result),
                    result_summary=(
                        str(tool_result)[:200] + "..."
                        if len(str(tool_result)) > 200
                        else str(tool_result)
                    ),
                )

            execution_time = time.time() - start_time
            state["dynamic_tool_results"] = {
                "results": aggregated_results,
                "execution_time": execution_time,
                "tools_executed": len(tool_selection),
            }

            logger.info(
                f"✅ Completed {len(tool_selection)} dynamic tools",
                success_count=len(
                    [r for r in tool_results if not isinstance(r, Exception)]
                ),
                execution_time_seconds=round(execution_time, 2),
            )

            return state

        except Exception as e:
            logger.error(f"Dynamic tool execution failed: {e}")
            state["dynamic_tool_results"] = {"error": str(e)}
            return state

    def _route_from_supervisor(self, state: CyberShieldState) -> str:
        """Route from supervisor based on analysis"""
        return state.get("routing_decision", "synthesize")

    def _route_threat_intel_tools(self, state: CyberShieldState) -> List[str]:
        """Fan-out routing based on LLM-selected threat intelligence tools"""
        selected_tools = state.get("selected_threat_tools", [])

        # Map tool names to node names
        tool_mapping = {
            "VirusTotal": "VirusScanner",
            "AbuseIPDB": "AbuseIPDB",
            "Shodan": "Shodan",
            "MilvusSearch": "MilvusSearch",
        }

        # Convert selected tools to node names
        selected_nodes = [
            tool_mapping.get(tool) for tool in selected_tools if tool in tool_mapping
        ]

        # If no tools selected or mapping failed, fallback to all tools
        if not selected_nodes:
            logger.warning(
                "No valid threat intelligence tools selected, using all tools"
            )
            return [
                "VirusScanner",
                "AbuseIPDB",
                "Shodan",
                "MilvusSearch",
                "RegexChecker",
            ]

        logger.info(f"Routing to selected threat intel tools: {selected_nodes}")
        return selected_nodes

    async def _select_dynamic_tools(self, state: CyberShieldState) -> List[Dict]:
        """Use LLM to dynamically select tools based on input analysis"""
        input_text = state.get("input_text", "")
        has_image = state.get("input_image") is not None

        # Build prompt for tool selection
        tool_selection_prompt = f"""Analyze the following input and select appropriate tools for security analysis:

Input: {input_text[:500]}...
Has Image: {has_image}

Available Tools:
- pii_detection_tool: For detecting personally identifiable information
- ioc_extraction_tool: For extracting indicators of compromise
- vision_analysis_tool: For analyzing images (if image present)
- regex_pattern_tool: For pattern matching
- vector_search_tool: For searching historical attack data

Respond with a JSON list of tools to execute:
[{{"name": "tool_name", "input": {{"key": "value"}}}}]

If no special tools are needed, respond with: []"""

        try:
            response = await self.llm.ainvoke(
                [HumanMessage(content=tool_selection_prompt)]
            )

            # Parse JSON response
            import json
            import re

            json_match = re.search(r"\[.*\]", response.content, re.DOTALL)
            if json_match:
                tool_selection = json.loads(json_match.group())
                return tool_selection
            else:
                return []

        except Exception as e:
            logger.error(f"Dynamic tool selection failed: {e}")
            # Fallback to basic tool selection
            basic_tools = []
            if len(input_text) > 100:
                basic_tools.append(
                    {"name": "pii_detection_tool", "input": {"text": input_text}}
                )
                basic_tools.append(
                    {"name": "ioc_extraction_tool", "input": {"text": input_text}}
                )
            if has_image:
                basic_tools.append(
                    {
                        "name": "vision_analysis_tool",
                        "input": {"image_data": state.get("input_image")},
                    }
                )
            return basic_tools

    async def _execute_tool(
        self, tool_name: str, tool_input: Dict, state: CyberShieldState
    ) -> Dict:
        """Execute individual tools"""
        logger.info(
            f"Executing tool: {tool_name}",
            tool_input=tool_input,
            iteration=state.get("iteration_count", 0),
        )
        try:
            if tool_name == "pii_detection_tool":
                text = tool_input.get("text", state.get("input_text", ""))
                masked_text, pii_map = await self.pii_agent.mask_pii(text)
                state["pii_masked_text"] = masked_text
                state["pii_mapping"] = pii_map
                return {
                    "masked_text": masked_text,
                    "pii_mapping": pii_map,
                    "status": "success",
                }

            elif tool_name == "ioc_extraction_tool":
                text = tool_input.get(
                    "text", state.get("pii_masked_text", state.get("input_text", ""))
                )
                iocs = await self.log_parser.extract_iocs(text)
                state["extracted_iocs"] = iocs
                return {"iocs": iocs, "status": "success"}

            elif tool_name == "threat_analysis_tool":
                iocs = tool_input.get("iocs", state.get("extracted_iocs", []))
                threat_report = await self.threat_agent.evaluate(iocs)
                state["threat_analysis"] = threat_report
                return {"threat_report": threat_report, "status": "success"}

            elif tool_name == "vision_analysis_tool":
                image_data = tool_input.get("image_data", state.get("input_image"))
                if image_data:
                    analysis = await self.vision_agent.process_image(image_data)
                    state["vision_analysis"] = analysis
                    return analysis
                else:
                    return {"error": "No image data provided", "status": "error"}

            elif tool_name == "regex_pattern_tool":
                from tools.regex_checker import RegexChecker

                pattern = tool_input.get("pattern", "")
                text = tool_input.get("text", state.get("input_text", ""))
                regex_checker = RegexChecker()
                matches = regex_checker.check_pattern(text, pattern)
                return {"matches": matches, "status": "success"}

            elif tool_name == "shodan_lookup_tool":
                if not self.shodan_client:
                    return {"error": "Shodan client not available", "status": "error"}
                ip = tool_input.get("ip", "")
                result = await self.shodan_client.lookup_ip(ip)
                return {"shodan_result": result, "status": "success"}

            elif tool_name == "virustotal_lookup_tool":
                if not self.virustotal_client:
                    return {
                        "error": "VirusTotal client not available",
                        "status": "error",
                    }
                # Accept both 'resource' and 'ip' parameters for flexibility
                resource = tool_input.get("resource", "") or tool_input.get("ip", "")
                result = await self.virustotal_client.lookup_ip(resource)
                return {"virustotal_result": result, "status": "success"}

            elif tool_name == "abuseipdb_lookup_tool":
                if not self.abuseipdb_client:
                    return {
                        "error": "AbuseIPDB client not available",
                        "status": "error",
                    }
                ip = tool_input.get("ip", "")
                result = await self.abuseipdb_client.check_ip(ip)
                return {"abuseipdb_result": result, "status": "success"}

            elif tool_name == "vector_search_tool":
                if not self.vectorstore:
                    return {"error": "Vector store not available", "status": "error"}

                query_ips = tool_input.get("ips", [])
                if isinstance(query_ips, str):
                    query_ips = [query_ips]  # Convert single IP to list

                search_results = []
                for ip in query_ips:
                    try:
                        # Search for similar attacks involving this IP
                        results = await self.vectorstore.search_by_ip(ip, limit=10)
                        search_results.append(
                            {
                                "ip": ip,
                                "matches": results,
                                "match_count": len(results) if results else 0,
                            }
                        )
                    except Exception as e:
                        search_results.append(
                            {"ip": ip, "error": str(e), "matches": [], "match_count": 0}
                        )

                return {
                    "vector_search_results": search_results,
                    "total_ips_searched": len(query_ips),
                    "status": "success",
                }

            else:
                return {"error": f"Unknown tool: {tool_name}", "status": "error"}

        except Exception as e:
            return {"error": str(e), "status": "error"}

    def _synthesize_step(self, state: CyberShieldState) -> CyberShieldState:
        """Final synthesis and report generation"""
        logger.info(
            "Synthesizing final report",
            iterations=state.get("iteration_count", 0),
            tools_used=len(state.get("tool_calls", [])),
        )

        logger.debug(
            "🐛 SYNTHESIS DEBUG: Starting final report generation",
            debug_mode_active=True,
            state_keys=list(state.keys()),
            log_level_env=os.getenv("LOG_LEVEL", "not_set"),
        )
        try:
            # Compile comprehensive report
            final_report = {
                "input_analysis": {
                    "original_text": state.get("input_text", ""),
                    "has_image": state.get("input_image") is not None,
                },
                "pii_analysis": {
                    "masked_text": state.get("pii_masked_text"),
                    "pii_mapping": state.get("pii_mapping"),
                },
                "ioc_analysis": {"extracted_iocs": state.get("extracted_iocs", [])},
                "threat_analysis": self._aggregate_threat_analysis(
                    state.get("threat_results", [])
                ),
                "vision_analysis": state.get("vision_analysis", {}),
                "parallel_tool_results": self._format_parallel_results(
                    state.get("threat_results", [])
                ),
                "dynamic_tool_results": state.get("dynamic_tool_results", {}),
                "recommendations": self._generate_recommendations(state),
                "processing_summary": {
                    "iterations": state.get("iteration_count", 0),
                    "routing_decision": state.get("routing_decision", "unknown"),
                    "parallel_tools_executed": len(state.get("threat_results", [])) > 0,
                    "dynamic_tools_executed": bool(state.get("dynamic_tool_results")),
                    "tools_used": self._extract_workflow_tools_used(state),
                },
            }

            state["final_report"] = final_report

            # Debug logging for final report
            logger.debug(
                "Final report synthesis completed",
                report_structure={
                    "input_analysis_keys": list(final_report["input_analysis"].keys()),
                    "pii_analysis_available": bool(final_report["pii_analysis"]),
                    "ioc_count": (
                        len(final_report["ioc_analysis"]["extracted_iocs"])
                        if final_report["ioc_analysis"]["extracted_iocs"]
                        else 0
                    ),
                    "threat_analysis_available": bool(final_report["threat_analysis"]),
                    "vision_analysis_available": bool(final_report["vision_analysis"]),
                    "recommendations_count": len(final_report["recommendations"]),
                    "processing_iterations": final_report["processing_summary"][
                        "iterations"
                    ],
                    "tools_used_count": len(
                        final_report["processing_summary"]["tools_used"]
                    ),
                },
            )

            # Detailed debug logging of report contents
            logger.debug(
                "Final report detailed contents",
                input_text_length=len(final_report["input_analysis"]["original_text"]),
                has_image=final_report["input_analysis"]["has_image"],
                pii_masked_text_available=bool(
                    final_report["pii_analysis"]["masked_text"]
                ),
                pii_mapping_count=(
                    len(final_report["pii_analysis"]["pii_mapping"])
                    if final_report["pii_analysis"]["pii_mapping"]
                    else 0
                ),
                extracted_iocs=final_report["ioc_analysis"]["extracted_iocs"],
                threat_analysis_keys=(
                    list(final_report["threat_analysis"].keys())
                    if isinstance(final_report["threat_analysis"], dict)
                    else []
                ),
                vision_analysis_keys=(
                    list(final_report["vision_analysis"].keys())
                    if isinstance(final_report["vision_analysis"], dict)
                    else []
                ),
                recommendations=final_report["recommendations"],
                tools_used=final_report["processing_summary"]["tools_used"],
            )

            # JSON format debug output if requested
            json_format = os.getenv("REACT_LOG_FORMAT", "").lower() == "json"
            if json_format:
                import json

                logger.debug(
                    json.dumps(
                        {
                            "type": "final_report",
                            "iteration": state.get("iteration_count", 0),
                            "report_summary": {
                                "status": "success",
                                "components_generated": [
                                    k for k, v in final_report.items() if v
                                ],
                                "total_size": len(str(final_report)),
                                "processing_time": state.get(
                                    "processing_time", "unknown"
                                ),
                            },
                            "detailed_report": final_report,
                        }
                    )
                )

            return state

        except Exception as e:
            logger.error(f"Synthesis step failed: {e}")

            # Debug logging for synthesis failure
            logger.debug(
                "Synthesis failure analysis",
                error_type=type(e).__name__,
                error_message=str(e),
                state_keys=list(state.keys()),
                iteration_count=state.get("iteration_count", 0),
                agent_scratchpad_length=len(state.get("agent_scratchpad", "")),
                available_data={
                    "pii_masked_text": bool(state.get("pii_masked_text")),
                    "pii_mapping": bool(state.get("pii_mapping")),
                    "extracted_iocs": bool(state.get("extracted_iocs")),
                    "threat_analysis": bool(state.get("threat_analysis")),
                    "vision_analysis": bool(state.get("vision_analysis")),
                },
            )

            state["final_report"] = {"error": str(e), "synthesis_failure": True}
            return state

    def _log_agent_reasoning(self, response_content: str, iteration: int) -> None:
        """Parse and log agent reasoning in ReAct format"""
        lines = response_content.strip().split("\n")

        current_thought = ""
        current_action = ""
        current_action_input = ""

        # Check if JSON format is requested via environment variable
        json_format = os.getenv("REACT_LOG_FORMAT", "").lower() == "json"

        for line in lines:
            line = line.strip()
            if line.startswith("Thought:"):
                current_thought = line.replace("Thought:", "").strip()
                if current_thought:
                    if json_format:
                        import json

                        logger.info(
                            json.dumps(
                                {
                                    "type": "thought",
                                    "iteration": iteration,
                                    "content": current_thought,
                                }
                            )
                        )
                    else:
                        logger.info(
                            f"💭 Thought", iteration=iteration, thought=current_thought
                        )

            elif line.startswith("Action:"):
                current_action = line.replace("Action:", "").strip()
                if current_action:
                    if json_format:
                        import json

                        logger.info(
                            json.dumps(
                                {
                                    "type": "action",
                                    "iteration": iteration,
                                    "action": current_action,
                                }
                            )
                        )
                    else:
                        logger.info(
                            f"🔧 Action", iteration=iteration, action=current_action
                        )

            elif line.startswith("Action Input:"):
                current_action_input = line.replace("Action Input:", "").strip()
                if current_action_input:
                    if json_format:
                        import json

                        try:
                            parsed_input = json.loads(current_action_input)
                        except:
                            parsed_input = current_action_input
                        logger.info(
                            json.dumps(
                                {
                                    "type": "action_input",
                                    "iteration": iteration,
                                    "input": parsed_input,
                                }
                            )
                        )
                    else:
                        logger.info(
                            f"📥 Action Input",
                            iteration=iteration,
                            action_input=current_action_input,
                        )

            elif line.startswith("Final Answer:"):
                final_answer = line.replace("Final Answer:", "").strip()
                if final_answer:
                    if json_format:
                        import json

                        logger.info(
                            json.dumps(
                                {
                                    "type": "final_answer",
                                    "iteration": iteration,
                                    "answer": final_answer,
                                }
                            )
                        )
                    else:
                        logger.info(
                            f"✅ Final Answer",
                            iteration=iteration,
                            final_answer=(
                                final_answer[:300] + "..."
                                if len(final_answer) > 300
                                else final_answer
                            ),
                        )

        # If no structured format found, log the raw content
        if not any(
            keyword in response_content
            for keyword in ["Thought:", "Action:", "Final Answer:"]
        ):
            if json_format:
                import json

                logger.info(
                    json.dumps(
                        {
                            "type": "agent_response",
                            "iteration": iteration,
                            "response": (
                                response_content[:500] + "..."
                                if len(response_content) > 500
                                else response_content
                            ),
                        }
                    )
                )
            else:
                logger.info(
                    f"🤔 Agent Response",
                    iteration=iteration,
                    response=(
                        response_content[:500] + "..."
                        if len(response_content) > 500
                        else response_content
                    ),
                )

    def _should_continue(self, state: CyberShieldState) -> str:
        """Decide whether to use tools or synthesize after agent step"""
        if state.get("next_action") == "finish" or state.get("final_report"):
            return "synthesize"  # Go directly to synthesis
        elif state.get("tool_calls"):
            return "tools"  # Execute tools
        elif state.get("iteration_count", 0) > 10:  # Prevent infinite loops
            return "synthesize"  # Force completion
        else:
            return "tools"  # Default to tools if unclear

    def _should_continue_after_tools(self, state: CyberShieldState) -> str:
        """Decide whether to continue reasoning or synthesize after tool execution"""
        iteration = state.get("iteration_count", 0)
        scratchpad = state.get("agent_scratchpad", "")

        # Count successful tool executions
        successful_observations = scratchpad.count("Observation:") - scratchpad.count(
            '"error"'
        )

        # If we have multiple successful tool results, go straight to synthesis
        if successful_observations >= 2 or iteration >= 1:
            logger.info(
                "Moving to synthesis after tools",
                successful_observations=successful_observations,
                iteration=iteration,
                reason="sufficient_data",
            )
            return "synthesize"
        elif iteration > 5:  # Hard limit to prevent loops
            logger.info("Forcing synthesis due to iteration limit", iteration=iteration)
            return "synthesize"
        else:
            logger.info("Continuing to agent for more reasoning", iteration=iteration)
            return "agent"

    def _build_agent_prompt(self, state: CyberShieldState) -> List:
        """Build the prompt for the agent with optimized single-pass analysis"""
        iteration = state.get("iteration_count", 0)

        if iteration == 0:
            # First iteration: comprehensive analysis in one pass
            system_prompt = """You are CyberShield, an advanced AI security analyst. Analyze the input efficiently and comprehensively in a single pass.

Available Tools:
- pii_detection_tool: Detect and mask PII in text
- ioc_extraction_tool: Extract indicators of compromise
- threat_analysis_tool: Analyze threats using external APIs
- vision_analysis_tool: Analyze images for security risks
- regex_pattern_tool: Check regex patterns
- shodan_lookup_tool: Lookup IP information on Shodan
- virustotal_lookup_tool: Check resources on VirusTotal
- abuseipdb_lookup_tool: Check IP reputation on AbuseIPDB
- vector_search_tool: Search vector database for historical attack data and similar threat patterns

CRITICAL: For IP investigations, you MUST use vector_search_tool to check historical attack data first, then complement with external API lookups (AbuseIPDB, Shodan, VirusTotal).

IMPORTANT: For efficiency, plan ALL needed tool calls in your first response. Use this format:

Thought: [Analyze what needs to be done - identify all required tools including vector_search_tool for IPs]
Action: tool_name_1
Action Input: {"key": "value"}
Action: tool_name_2
Action Input: {"key": "value"}
Action: tool_name_3
Action Input: {"key": "value"}

After tools execute, provide your Final Answer based on all results."""
        else:
            # Subsequent iterations: focus on synthesis
            system_prompt = """You are CyberShield. You have tool results. Provide your final security analysis.

Based on the tool results in your scratchpad, provide a comprehensive Final Answer with:
1. Risk assessment
2. Key findings
3. Recommendations

Format: Final Answer: [your comprehensive analysis]"""

        messages = [SystemMessage(content=system_prompt)]

        # Add input information
        input_text = state.get("input_text", "")
        has_image = state.get("input_image") is not None

        user_message = (
            f"Please analyze the following for security risks:\n\nText: {input_text}"
        )
        if has_image:
            user_message += "\n\nNote: An image has also been provided for analysis."

        messages.append(HumanMessage(content=user_message))

        # Add conversation history (keep only recent messages to avoid token limit)
        recent_messages = state.get("messages", [])[-2:]  # Keep only last 2 messages
        messages.extend(recent_messages)

        # Add current scratchpad (truncate if too long)
        if state.get("agent_scratchpad"):
            scratchpad = state["agent_scratchpad"]
            # Truncate scratchpad if it's too long (keep last 2000 chars)
            if len(scratchpad) > 2000:
                scratchpad = "...\n" + scratchpad[-2000:]
            messages.append(HumanMessage(content=f"Current progress:\n{scratchpad}"))

        return messages

    def _parse_agent_response(self, response: str, state: CyberShieldState) -> Dict:
        """Parse agent response for tool calls or final answer"""
        lines = response.strip().split("\n")

        tool_calls = []
        final_answer = None

        i = 0
        while i < len(lines):
            line = lines[i].strip()

            if line.startswith("Action:"):
                tool_name = line.replace("Action:", "").strip()

                # Look for Action Input on next line
                if i + 1 < len(lines) and lines[i + 1].strip().startswith(
                    "Action Input:"
                ):
                    tool_input_str = lines[i + 1].replace("Action Input:", "").strip()

                    # Try to parse as JSON, fallback to string
                    try:
                        import json

                        tool_input = json.loads(tool_input_str)
                    except:
                        # Try to extract key-value pairs
                        if ":" in tool_input_str:
                            tool_input = {"input": tool_input_str}
                        else:
                            tool_input = {"text": tool_input_str}

                    tool_calls.append({"tool": tool_name, "input": tool_input})
                    i += 2
                else:
                    i += 1

            elif line.startswith("Final Answer:"):
                final_answer = line.replace("Final Answer:", "").strip()
                # Include remaining lines
                if i + 1 < len(lines):
                    final_answer += "\n" + "\n".join(lines[i + 1 :])
                break

            else:
                i += 1

        return {"tool_calls": tool_calls, "final_answer": final_answer}

    def _generate_recommendations(self, state: CyberShieldState) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []

        # PII recommendations
        if state.get("pii_mapping"):
            recommendations.append(
                "PII detected - ensure proper handling and compliance"
            )

        # IOC recommendations
        iocs = state.get("extracted_iocs", [])
        if iocs:
            recommendations.append(
                f"Found {len(iocs)} indicators of compromise - investigate further"
            )

        # Threat recommendations
        threat_analysis = state.get("threat_analysis", {})
        if threat_analysis and threat_analysis.get("high_risk_indicators"):
            recommendations.append(
                "High-risk threats detected - immediate attention required"
            )

        # Vision recommendations
        vision_analysis = state.get("vision_analysis", {})
        if vision_analysis and vision_analysis.get("recommendations"):
            recommendations.extend(vision_analysis["recommendations"])

        if not recommendations:
            recommendations.append("No immediate security concerns identified")

        return recommendations

    def _extract_tools_used(self, scratchpad: str) -> List[str]:
        """Extract list of tools used from scratchpad"""
        tools_used = []
        lines = scratchpad.split("\n")

        for line in lines:
            if line.strip().startswith("Action:"):
                tool_name = line.replace("Action:", "").strip()
                if tool_name not in tools_used:
                    tools_used.append(tool_name)

        return tools_used

    def _extract_workflow_tools_used(self, state: CyberShieldState) -> List[str]:
        """Extract list of tools used from workflow state"""
        tools_used = []

        # Check threat results from parallel tools
        threat_results = state.get("threat_results", [])
        for result in threat_results:
            if "tool" in result:
                tools_used.append(result["tool"])

        # Check dynamic tool results
        dynamic_results = state.get("dynamic_tool_results", {})
        if isinstance(dynamic_results, dict) and "results" in dynamic_results:
            tools_used.extend(dynamic_results["results"].keys())

        # Add any other detected tools from state
        if state.get("pii_masked_text"):
            tools_used.append("PII Detection")
        if state.get("vision_analysis"):
            tools_used.append("Vision Analysis")

        return list(set(tools_used))  # Remove duplicates

    def _aggregate_threat_analysis(self, threat_results: List[Dict]) -> Dict:
        """Aggregate threat analysis from parallel tool results"""
        aggregated = {
            "parallel_execution": True,
            "tools_executed": len(threat_results),
            "results": {},
        }

        for result in threat_results:
            tool_name = result.get("tool", "unknown")
            aggregated["results"][tool_name.lower()] = result

        return aggregated

    def _format_parallel_results(self, threat_results: List[Dict]) -> Dict:
        """Format parallel tool results for final report"""
        formatted = {}

        for result in threat_results:
            tool_name = result.get("tool", "unknown")
            formatted[tool_name.lower()] = {
                "status": result.get("status", "unknown"),
                "analysis": result.get("analysis", []),
                "error": result.get("error"),
            }

        return formatted

    async def process(
        self, input_text: str, input_image: Optional[bytes] = None
    ) -> Dict:
        """Process input through the ReAct workflow"""
        logger.info(
            "Starting ReAct workflow",
            input_length=len(input_text),
            has_image=input_image is not None,
        )

        # Test debug logging is working - try both debug and info to see which works
        import logging as stdlib_logging

        current_level = stdlib_logging.getLogger(
            "cybershield.react_workflow"
        ).getEffectiveLevel()

        logger.info(
            "🔍 DEBUG STATUS CHECK",
            current_log_level=stdlib_logging.getLevelName(current_level),
            debug_enabled=current_level <= stdlib_logging.DEBUG,
            environment_variables={
                "LOG_LEVEL": os.getenv("LOG_LEVEL", "not_set"),
                "REACT_LOG_FORMAT": os.getenv("REACT_LOG_FORMAT", "not_set"),
                "LOG_FILE": os.getenv("LOG_FILE", "not_set"),
            },
        )

        logger.debug(
            "🐛 DEBUG MODE: ReAct workflow debug logging is enabled",
            debug_test=True,
            logger_level=current_level,
            debug_level=stdlib_logging.DEBUG,
        )
        try:
            # Initialize state
            initial_state = CyberShieldState(
                messages=[],
                input_text=input_text,
                input_image=input_image,
                pii_masked_text=None,
                pii_mapping=None,
                extracted_iocs=None,
                threat_analysis=None,
                vision_analysis=None,
                final_report=None,
                next_action=None,
                tool_calls=[],
                agent_scratchpad="",
                iteration_count=0,
                # New hybrid workflow state with reducer
                threat_results=[],
                dynamic_tool_results=None,
                routing_decision=None,
            )

            # Run workflow
            final_state = await self.workflow.ainvoke(
                initial_state, config={"verbose": True}
            )

            final_report = final_state.get(
                "final_report", {"error": "No final report generated"}
            )

            # Enhanced completion logging
            success = "error" not in final_report
            logger.info(
                "ReAct workflow completed",
                total_iterations=final_state.get("iteration_count", 0),
                success=success,
                report_keys=(
                    list(final_report.keys()) if isinstance(final_report, dict) else []
                ),
            )

            # Debug logging for final workflow state and report
            logger.debug(
                "Final workflow state analysis",
                state_keys=list(final_state.keys()),
                final_state_size=len(str(final_state)),
                agent_scratchpad_length=len(final_state.get("agent_scratchpad", "")),
                messages_count=len(final_state.get("messages", [])),
                tool_calls_remaining=len(final_state.get("tool_calls", [])),
            )

            if success and isinstance(final_report, dict):
                logger.debug(
                    "Final report validation and metrics",
                    report_size_bytes=len(str(final_report)),
                    components_present={
                        "input_analysis": "input_analysis" in final_report,
                        "pii_analysis": "pii_analysis" in final_report,
                        "ioc_analysis": "ioc_analysis" in final_report,
                        "threat_analysis": "threat_analysis" in final_report,
                        "vision_analysis": "vision_analysis" in final_report,
                        "recommendations": "recommendations" in final_report,
                        "processing_summary": "processing_summary" in final_report,
                    },
                    data_quality_metrics={
                        "has_recommendations": bool(
                            final_report.get("recommendations")
                        ),
                        "recommendations_count": len(
                            final_report.get("recommendations", [])
                        ),
                        "ioc_extraction_successful": bool(
                            final_report.get("ioc_analysis", {}).get("extracted_iocs")
                        ),
                        "threat_analysis_successful": bool(
                            final_report.get("threat_analysis")
                        ),
                        "pii_analysis_successful": bool(
                            final_report.get("pii_analysis")
                        ),
                    },
                )

                # Log the complete final report in debug mode
                logger.debug(
                    "Complete final report contents", final_report=final_report
                )
            else:
                logger.debug("Workflow completed with error", error_report=final_report)

            return final_report

        except Exception as e:
            logger.error(f"ReAct workflow failed: {e}")
            return {"error": str(e)}

    async def ainvoke(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """LangGraph-compatible async invoke method"""
        try:
            logger.info(
                "Starting ReAct workflow via ainvoke",
                input_length=len(state.get("input_text", "")),
                has_image=state.get("input_image") is not None,
            )

            # Convert dict to proper state and invoke workflow
            result_state = await self.workflow.ainvoke(state)

            # Return the final report or the complete state
            return result_state.get("final_report", result_state)

        except Exception as e:
            logger.error(f"ReAct workflow ainvoke failed: {e}")
            return {"error": str(e)}


# Factory function for easy instantiation
def create_cybershield_workflow(
    memory=None,
    vectorstore=None,
    llm_model="gpt-4o",
    abuseipdb_client=None,
    shodan_client=None,
    virustotal_client=None,
):
    """Create a CyberShield ReAct workflow instance"""
    return CyberShieldReActAgent(
        memory,
        vectorstore,
        llm_model,
        abuseipdb_client,
        shodan_client,
        virustotal_client,
    )
