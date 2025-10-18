# Individual workflow step implementations for CyberShield ReAct workflow
#
# This module contains all the individual tool step implementations that were
# previously in react_workflow.py, focusing on:
# - Threat intelligence tool execution (VirusTotal, AbuseIPDB, Shodan)
# - Milvus vector database search
# - RegexChecker IOC extraction
# - Dynamic tool execution with asyncio.gather
# - Comprehensive caching using RedisSTM

import asyncio
import time
from typing import Any

from langchain_core.messages import HumanMessage

from utils.logging_config import get_security_logger

logger = get_security_logger("workflow_steps")


class WorkflowSteps:
    """Individual workflow step implementations with caching support"""

    def __init__(
        self,
        memory=None,
        vectorstore=None,
        llm=None,
        abuseipdb_client=None,
        shodan_client=None,
        virustotal_client=None,
        regex_checker=None,
    ):
        self.memory = memory
        self.vectorstore = vectorstore
        self.llm = llm
        self.abuseipdb_client = abuseipdb_client
        self.shodan_client = shodan_client
        self.virustotal_client = virustotal_client
        self.regex_checker = regex_checker

    async def _generate_cache_key(self, operation: str, input_text: str) -> str:
        """Generate consistent cache key for operations"""
        import hashlib

        # Create hash of input text for consistent caching
        text_hash = hashlib.md5(input_text.encode()).hexdigest()[:16]
        return f"cybershield:{operation}:{text_hash}"

    async def virustotal_step(self, state) -> dict:
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

    async def abuseipdb_step(self, state) -> dict:
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

    async def shodan_step(self, state) -> dict:
        """Shodan analysis step with caching and graceful rate limit handling"""
        logger.info("Shodan analysis step")

        try:
            if not self.shodan_client:
                logger.info("Shodan client not available, excluding from results")
                return {**state, "threat_results": []}  # Empty results, no error shown

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
            rate_limited = False

            # Process IPs
            for ip in iocs.get("ips", [])[:5]:  # Conservative limit for Shodan
                try:
                    result = await self.shodan_client.lookup_ip(ip)

                    # Check for rate limit errors
                    if "error" in result:
                        error_msg = str(result.get("error", "")).lower()
                        # Detect rate limit errors: 403 Forbidden, 429 Too Many Requests
                        if (
                            "403" in error_msg
                            or "429" in error_msg
                            or "forbidden" in error_msg
                            or "rate" in error_msg
                        ):
                            logger.warning(
                                f"Shodan rate limit detected, excluding from results: {result.get('error')}"
                            )
                            rate_limited = True
                            break  # Stop processing on rate limit

                    results.append({"type": "ip", "value": ip, "result": result})
                except Exception as e:
                    error_msg = str(e).lower()
                    if (
                        "403" in error_msg
                        or "429" in error_msg
                        or "forbidden" in error_msg
                    ):
                        logger.warning(
                            f"Shodan rate limit detected (exception), excluding from results: {e}"
                        )
                        rate_limited = True
                        break
                    results.append({"type": "ip", "value": ip, "error": str(e)})

            # If rate limited, return empty results (exclude Shodan entirely)
            if rate_limited:
                logger.info("Shodan excluded from analysis due to rate limiting")
                return {**state, "threat_results": []}  # Empty results, no error shown

            # If no results, also exclude
            if not results:
                logger.info("No Shodan results to report")
                return {**state, "threat_results": []}

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
            error_msg = str(e).lower()
            if "403" in error_msg or "429" in error_msg or "forbidden" in error_msg:
                logger.warning(
                    f"Shodan rate limit detected (outer exception), excluding from results: {e}"
                )
                return {**state, "threat_results": []}  # Empty results, no error shown
            logger.error(f"Shodan step failed: {e}")
            return {**state, "threat_results": []}

    async def milvus_search_step(self, state) -> dict:
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
            cache_key = await self._generate_cache_key("milvus", input_text)

            # Check cache first
            if self.memory:
                try:
                    cached_result = await self.memory.get(cache_key)
                    if cached_result:
                        logger.info("Retrieved cached Milvus results")
                        return {**state, "threat_results": [cached_result]}
                except Exception as e:
                    logger.warning(f"Milvus cache retrieval failed: {e}")

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
                    ip_results = await self.vectorstore.search_by_ip(ip, limit=5)
                    results.append(
                        {"type": "ip_history", "value": ip, "results": ip_results}
                    )
                except Exception as e:
                    results.append({"type": "ip_history", "value": ip, "error": str(e)})

            # Prepare result for caching and return
            vector_result = {
                "tool": f"VectorSearch({self.vectorstore.__class__.__name__})",
                "analysis": results,
                "status": "success",
            }

            # Cache the result
            if self.memory:
                try:
                    await self.memory.set(
                        cache_key, vector_result, ttl=1800
                    )  # 30 minutes
                    logger.info("Cached vector search results")
                except Exception as e:
                    logger.warning(f"Vector search cache storage failed: {e}")

            return {**state, "threat_results": [vector_result]}

        except Exception as e:
            logger.error(f"Vector search step failed: {e}")
            return {
                **state,
                "threat_results": [{"tool": "VectorSearch", "error": str(e)}],
            }

    async def regex_checker_step(self, state) -> dict:
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

            cache_key = await self._generate_cache_key("regex", input_text)

            # Check cache first
            if self.memory:
                try:
                    cached_result = await self.memory.get(cache_key)
                    if cached_result:
                        logger.info("Retrieved cached RegexChecker results")
                        return {**state, "threat_results": [cached_result]}
                except Exception as e:
                    logger.warning(f"RegexChecker cache retrieval failed: {e}")

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

            # Prepare result for caching and return
            regex_result = {
                "tool": "RegexChecker",
                "analysis": results,
                "status": "success",
            }

            # Cache the result
            if self.memory:
                try:
                    await self.memory.set(
                        cache_key, regex_result, ttl=1800
                    )  # 30 minutes
                    logger.info("Cached RegexChecker results")
                except Exception as e:
                    logger.warning(f"RegexChecker cache storage failed: {e}")

            return {**state, "threat_results": [regex_result]}

        except Exception as e:
            logger.error(f"RegexChecker step failed: {e}")
            return {
                **state,
                "threat_results": [{"tool": "RegexChecker", "error": str(e)}],
            }

    async def dynamic_tool_executor(self, state) -> dict:
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

    async def _select_dynamic_tools(self, state) -> list[dict]:
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
        self, tool_name: str, tool_input: dict[str, Any], state: dict[str, Any]
    ) -> dict[str, Any]:
        """Execute a specific tool with given input"""
        try:
            # Route to the appropriate tool method based on tool_name
            if tool_name == "virustotal_lookup_tool":
                result = await self.virustotal_step(state)
                return result.get("threat_results", [{}])[0]

            elif tool_name == "abuseipdb_check_tool":
                result = await self.abuseipdb_step(state)
                return result.get("threat_results", [{}])[0]

            elif tool_name == "shodan_lookup_tool":
                result = await self.shodan_step(state)
                return result.get("threat_results", [{}])[0]

            elif tool_name == "ioc_extraction_tool":
                result = await self.regex_checker_step(state)
                return result.get("extracted_iocs", {})

            elif tool_name == "vector_search_tool":
                result = await self.milvus_search_step(state)
                return result.get("vector_results", {})

            elif tool_name == "vision_analysis_tool":
                # Vision analysis would be handled by vision agent
                return {
                    "tool": tool_name,
                    "status": "info",
                    "message": "Vision analysis requires image input",
                }

            else:
                logger.warning(f"Unknown tool name: {tool_name}")
                return {
                    "tool": tool_name,
                    "error": f"Unknown tool: {tool_name}",
                    "available_tools": [
                        "virustotal_lookup_tool",
                        "abuseipdb_check_tool",
                        "shodan_lookup_tool",
                        "ioc_extraction_tool",
                        "vector_search_tool",
                        "vision_analysis_tool",
                    ],
                }

        except Exception as e:
            logger.error(f"Tool execution failed for {tool_name}: {e}")
            return {"tool": tool_name, "error": str(e), "input": tool_input}
