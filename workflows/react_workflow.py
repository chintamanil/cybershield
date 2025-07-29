# ReAct workflow using LangGraph for CyberShield
from typing import Dict, List, Optional, Any, TypedDict, Annotated
import os
from langgraph.graph import StateGraph, END
# from langgraph.prebuilt import ToolExecutor, ToolInvocation  # Not used in current implementation
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from utils.logging_config import get_security_logger

logger = get_security_logger("react_workflow")

# Placeholder: LangGraph DAG execution model for ReAct agent flow
# Define StateGraph and wire up SupervisorAgent -> PII -> LogParser -> ThreatAgent -> Summary

class CyberShieldState(TypedDict):
    """State schema for CyberShield ReAct workflow"""
    messages: Annotated[List[Any], "The messages in the conversation"]
    input_text: str
    input_image: Optional[bytes]
    pii_masked_text: Optional[str]
    pii_mapping: Optional[Dict]
    extracted_iocs: Optional[List[Dict]]
    threat_analysis: Optional[Dict]
    vision_analysis: Optional[Dict]
    final_report: Optional[Dict]
    next_action: Optional[str]
    tool_calls: List[Dict]
    agent_scratchpad: str
    iteration_count: int

class CyberShieldReActAgent:
    """ReAct agent using LangGraph for cybersecurity analysis"""

    def __init__(self, memory=None, vectorstore=None, llm_model="gpt-4o",
                 abuseipdb_client=None, shodan_client=None, virustotal_client=None):
        self.memory = memory
        self.vectorstore = vectorstore
        self.abuseipdb_client = abuseipdb_client
        self.shodan_client = shodan_client
        self.virustotal_client = virustotal_client

        # Import agents here to avoid circular imports
        from agents.pii_agent import PIIAgent
        from agents.log_parser import LogParserAgent
        from agents.threat_agent import ThreatAgent
        from agents.vision_agent import VisionAgent

        self.pii_agent = PIIAgent(memory)
        self.log_parser = LogParserAgent()
        self.threat_agent = ThreatAgent(memory)

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

    def _create_workflow(self) -> StateGraph:
        """Create the LangGraph workflow for ReAct processing"""
        workflow = StateGraph(CyberShieldState)

        # Add nodes
        workflow.add_node("agent", self._agent_step)
        workflow.add_node("tools", self._tool_step)
        workflow.add_node("synthesize", self._synthesize_step)

        # Add edges
        workflow.set_entry_point("agent")
        workflow.add_conditional_edges(
            "agent",
            self._should_continue,
            {
                "continue": "tools",
                "end": "synthesize"
            }
        )
        workflow.add_edge("tools", "agent")
        workflow.add_edge("synthesize", END)

        return workflow.compile()

    def _agent_step(self, state: CyberShieldState) -> CyberShieldState:
        """Agent reasoning step - decide what to do next"""
        iteration = state.get("iteration_count", 0)
        logger.info(f"Agent reasoning step {iteration}",
                   scratchpad_length=len(state.get("agent_scratchpad", "")))
        try:
            # Build prompt with current state
            prompt = self._build_agent_prompt(state)

            # Get LLM response
            response = self.llm.invoke(prompt)

            # Log the full reasoning chain with proper parsing
            self._log_agent_reasoning(response.content, iteration)

            # Parse response for tool calls or final answer
            parsed_response = self._parse_agent_response(response.content, state)

            # Update state
            state["messages"].append(response)
            state["agent_scratchpad"] += f"\nThought: {response.content}"
            state["iteration_count"] += 1

            if parsed_response.get("tool_calls"):
                state["tool_calls"] = parsed_response["tool_calls"]
                state["next_action"] = "use_tools"
            else:
                state["next_action"] = "finish"
                state["final_report"] = parsed_response.get("final_answer")

            return state

        except Exception as e:
            logger.error(f"Agent step failed: {e}")
            state["next_action"] = "finish"
            state["final_report"] = {"error": str(e)}
            return state

    async def _tool_step(self, state: CyberShieldState) -> CyberShieldState:
        """Execute tools based on agent decisions"""
        try:
            for tool_call in state.get("tool_calls", []):
                tool_name = tool_call.get("tool")
                tool_input = tool_call.get("input", {})

                logger.info(f"🔧 Action: {tool_name}",
                           action_input=tool_input,
                           iteration=state.get("iteration_count", 0))

                # Execute appropriate tool
                result = await self._execute_tool(tool_name, tool_input, state)

                # Check if JSON format is requested
                json_format = os.getenv("REACT_LOG_FORMAT", "").lower() == "json"

                if json_format:
                    import json
                    logger.info(json.dumps({
                        "type": "observation",
                        "iteration": state.get("iteration_count", 0),
                        "tool": tool_name,
                        "result_type": type(result).__name__,
                        "success": "error" not in result,
                        "observation": result
                    }))
                else:
                    logger.info(f"👁️ Observation",
                               tool=tool_name,
                               result_type=type(result).__name__,
                               success="error" not in result,
                               iteration=state.get("iteration_count", 0),
                               observation=str(result)[:400] + "..." if len(str(result)) > 400 else str(result))

                # Update scratchpad
                state["agent_scratchpad"] += f"\nAction: {tool_name}\nAction Input: {tool_input}\nObservation: {result}"

            # Clear tool calls
            state["tool_calls"] = []

            return state

        except Exception as e:
            logger.error(f"Tool step failed: {e}")
            state["agent_scratchpad"] += f"\nTool execution error: {str(e)}"
            return state

    async def _execute_tool(self, tool_name: str, tool_input: Dict, state: CyberShieldState) -> Dict:
        """Execute individual tools"""
        logger.info(f"Executing tool: {tool_name}", tool_input=tool_input, iteration=state.get("iteration_count", 0))
        try:
            if tool_name == "pii_detection_tool":
                text = tool_input.get("text", state.get("input_text", ""))
                masked_text, pii_map = await self.pii_agent.mask_pii(text)
                state["pii_masked_text"] = masked_text
                state["pii_mapping"] = pii_map
                return {"masked_text": masked_text, "pii_mapping": pii_map, "status": "success"}

            elif tool_name == "ioc_extraction_tool":
                text = tool_input.get("text", state.get("pii_masked_text", state.get("input_text", "")))
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
                    return {"error": "VirusTotal client not available", "status": "error"}
                # Accept both 'resource' and 'ip' parameters for flexibility
                resource = tool_input.get("resource", "") or tool_input.get("ip", "")
                result = await self.virustotal_client.lookup_ip(resource)
                return {"virustotal_result": result, "status": "success"}

            elif tool_name == "abuseipdb_lookup_tool":
                if not self.abuseipdb_client:
                    return {"error": "AbuseIPDB client not available", "status": "error"}
                ip = tool_input.get("ip", "")
                result = await self.abuseipdb_client.check_ip(ip)
                return {"abuseipdb_result": result, "status": "success"}

            else:
                return {"error": f"Unknown tool: {tool_name}", "status": "error"}

        except Exception as e:
            return {"error": str(e), "status": "error"}

    def _synthesize_step(self, state: CyberShieldState) -> CyberShieldState:
        """Final synthesis and report generation"""
        logger.info("Synthesizing final report",
                   iterations=state.get("iteration_count", 0),
                   tools_used=len(state.get("tool_calls", [])))
        try:
            # Compile comprehensive report
            final_report = {
                "input_analysis": {
                    "original_text": state.get("input_text", ""),
                    "has_image": state.get("input_image") is not None
                },
                "pii_analysis": {
                    "masked_text": state.get("pii_masked_text"),
                    "pii_mapping": state.get("pii_mapping")
                },
                "ioc_analysis": {
                    "extracted_iocs": state.get("extracted_iocs", [])
                },
                "threat_analysis": state.get("threat_analysis", {}),
                "vision_analysis": state.get("vision_analysis", {}),
                "recommendations": self._generate_recommendations(state),
                "processing_summary": {
                    "iterations": state.get("iteration_count", 0),
                    "tools_used": self._extract_tools_used(state.get("agent_scratchpad", ""))
                }
            }

            state["final_report"] = final_report
            return state

        except Exception as e:
            logger.error(f"Synthesis step failed: {e}")
            state["final_report"] = {"error": str(e)}
            return state

    def _log_agent_reasoning(self, response_content: str, iteration: int) -> None:
        """Parse and log agent reasoning in ReAct format"""
        lines = response_content.strip().split('\n')

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
                        logger.info(json.dumps({
                            "type": "thought",
                            "iteration": iteration,
                            "content": current_thought
                        }))
                    else:
                        logger.info(f"💭 Thought",
                                   iteration=iteration,
                                   thought=current_thought)

            elif line.startswith("Action:"):
                current_action = line.replace("Action:", "").strip()
                if current_action:
                    if json_format:
                        import json
                        logger.info(json.dumps({
                            "type": "action",
                            "iteration": iteration,
                            "action": current_action
                        }))
                    else:
                        logger.info(f"🔧 Action",
                                   iteration=iteration,
                                   action=current_action)

            elif line.startswith("Action Input:"):
                current_action_input = line.replace("Action Input:", "").strip()
                if current_action_input:
                    if json_format:
                        import json
                        try:
                            parsed_input = json.loads(current_action_input)
                        except:
                            parsed_input = current_action_input
                        logger.info(json.dumps({
                            "type": "action_input",
                            "iteration": iteration,
                            "input": parsed_input
                        }))
                    else:
                        logger.info(f"📥 Action Input",
                                   iteration=iteration,
                                   action_input=current_action_input)

            elif line.startswith("Final Answer:"):
                final_answer = line.replace("Final Answer:", "").strip()
                if final_answer:
                    if json_format:
                        import json
                        logger.info(json.dumps({
                            "type": "final_answer",
                            "iteration": iteration,
                            "answer": final_answer
                        }))
                    else:
                        logger.info(f"✅ Final Answer",
                                   iteration=iteration,
                                   final_answer=final_answer[:300] + "..." if len(final_answer) > 300 else final_answer)

        # If no structured format found, log the raw content
        if not any(keyword in response_content for keyword in ["Thought:", "Action:", "Final Answer:"]):
            if json_format:
                import json
                logger.info(json.dumps({
                    "type": "agent_response",
                    "iteration": iteration,
                    "response": response_content[:500] + "..." if len(response_content) > 500 else response_content
                }))
            else:
                logger.info(f"🤔 Agent Response",
                           iteration=iteration,
                           response=response_content[:500] + "..." if len(response_content) > 500 else response_content)

    def _should_continue(self, state: CyberShieldState) -> str:
        """Decide whether to continue or end the workflow"""
        if state.get("next_action") == "finish":
            return "end"
        elif state.get("iteration_count", 0) > 10:  # Prevent infinite loops
            return "end"
        else:
            return "continue"

    def _build_agent_prompt(self, state: CyberShieldState) -> List:
        """Build the prompt for the agent"""
        system_prompt = """You are CyberShield, an advanced AI security analyst. Your role is to analyze text and images for cybersecurity threats, PII, and other risks.

Available Tools:
- pii_detection_tool: Detect and mask PII in text
- ioc_extraction_tool: Extract indicators of compromise
- threat_analysis_tool: Analyze threats using external APIs
- vision_analysis_tool: Analyze images for security risks
- regex_pattern_tool: Check regex patterns
- shodan_lookup_tool: Lookup IP information on Shodan
- virustotal_lookup_tool: Check resources on VirusTotal
- abuseipdb_lookup_tool: Check IP reputation on AbuseIPDB

Use the ReAct format:
Thought: Analyze what needs to be done
Action: [tool_name]
Action Input: {"key": "value"}
Observation: [tool_result]
... (repeat as needed)
Thought: I now have enough information to provide a final answer
Final Answer: [comprehensive security analysis]

Always prioritize security and privacy. Be thorough in your analysis."""

        messages = [SystemMessage(content=system_prompt)]

        # Add input information
        input_text = state.get("input_text", "")
        has_image = state.get("input_image") is not None

        user_message = f"Please analyze the following for security risks:\n\nText: {input_text}"
        if has_image:
            user_message += "\n\nNote: An image has also been provided for analysis."

        messages.append(HumanMessage(content=user_message))

        # Add conversation history (keep only recent messages to avoid token limit)
        recent_messages = state.get("messages", [])[-2:]  # Keep only last 2 messages
        messages.extend(recent_messages)

        # Add current scratchpad (truncate if too long)
        if state.get("agent_scratchpad"):
            scratchpad = state['agent_scratchpad']
            # Truncate scratchpad if it's too long (keep last 2000 chars)
            if len(scratchpad) > 2000:
                scratchpad = "...\n" + scratchpad[-2000:]
            messages.append(HumanMessage(content=f"Current progress:\n{scratchpad}"))

        return messages

    def _parse_agent_response(self, response: str, state: CyberShieldState) -> Dict:
        """Parse agent response for tool calls or final answer"""
        lines = response.strip().split('\n')

        tool_calls = []
        final_answer = None

        i = 0
        while i < len(lines):
            line = lines[i].strip()

            if line.startswith("Action:"):
                tool_name = line.replace("Action:", "").strip()

                # Look for Action Input on next line
                if i + 1 < len(lines) and lines[i + 1].strip().startswith("Action Input:"):
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

                    tool_calls.append({
                        "tool": tool_name,
                        "input": tool_input
                    })
                    i += 2
                else:
                    i += 1

            elif line.startswith("Final Answer:"):
                final_answer = line.replace("Final Answer:", "").strip()
                # Include remaining lines
                if i + 1 < len(lines):
                    final_answer += "\n" + "\n".join(lines[i + 1:])
                break

            else:
                i += 1

        return {
            "tool_calls": tool_calls,
            "final_answer": final_answer
        }

    def _generate_recommendations(self, state: CyberShieldState) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []

        # PII recommendations
        if state.get("pii_mapping"):
            recommendations.append("PII detected - ensure proper handling and compliance")

        # IOC recommendations
        iocs = state.get("extracted_iocs", [])
        if iocs:
            recommendations.append(f"Found {len(iocs)} indicators of compromise - investigate further")

        # Threat recommendations
        threat_analysis = state.get("threat_analysis", {})
        if threat_analysis and threat_analysis.get("high_risk_indicators"):
            recommendations.append("High-risk threats detected - immediate attention required")

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
        lines = scratchpad.split('\n')

        for line in lines:
            if line.strip().startswith("Action:"):
                tool_name = line.replace("Action:", "").strip()
                if tool_name not in tools_used:
                    tools_used.append(tool_name)

        return tools_used

    async def process(self, input_text: str, input_image: Optional[bytes] = None) -> Dict:
        """Process input through the ReAct workflow"""
        logger.info("Starting ReAct workflow",
                   input_length=len(input_text),
                   has_image=input_image is not None)
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
                iteration_count=0
            )

            # Run workflow
            final_state = await self.workflow.ainvoke(initial_state)

            final_report = final_state.get("final_report", {"error": "No final report generated"})
            logger.info("ReAct workflow completed",
                       total_iterations=final_state.get("iteration_count", 0),
                       success="error" not in final_report,
                       report_keys=list(final_report.keys()) if isinstance(final_report, dict) else [])

            return final_report

        except Exception as e:
            logger.error(f"ReAct workflow failed: {e}")
            return {"error": str(e)}

# Factory function for easy instantiation
def create_cybershield_workflow(memory=None, vectorstore=None, llm_model="gpt-4o",
                               abuseipdb_client=None, shodan_client=None, virustotal_client=None):
    """Create a CyberShield ReAct workflow instance"""
    return CyberShieldReActAgent(memory, vectorstore, llm_model,
                                abuseipdb_client, shodan_client, virustotal_client)