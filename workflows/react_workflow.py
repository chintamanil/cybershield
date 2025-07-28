# ReAct workflow using LangGraph for CyberShield
from typing import Dict, List, Optional, Any, TypedDict, Annotated
import logging
from langgraph.graph import StateGraph, END
# from langgraph.prebuilt import ToolExecutor, ToolInvocation  # Not used in current implementation
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from langchain_core.tools import BaseTool
from langchain_openai import ChatOpenAI

logger = logging.getLogger(__name__)

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

    def __init__(self, memory=None, vectorstore=None, llm_model="gpt-4o"):
        self.memory = memory
        self.vectorstore = vectorstore

        # Import agents here to avoid circular imports
        from agents.pii_agent import PIIAgent
        from agents.log_parser import LogParserAgent
        from agents.threat_agent import ThreatAgent
        from agents.vision_agent import VisionAgent

        self.pii_agent = PIIAgent(memory)
        self.log_parser = LogParserAgent()
        self.threat_agent = ThreatAgent(memory)
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
        try:
            # Build prompt with current state
            prompt = self._build_agent_prompt(state)

            # Get LLM response
            response = self.llm.invoke(prompt)

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

                # Execute appropriate tool
                result = await self._execute_tool(tool_name, tool_input, state)

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
                from tools.regex_checker import regex_checker
                pattern = tool_input.get("pattern", "")
                text = tool_input.get("text", state.get("input_text", ""))
                matches = regex_checker(pattern, text)
                return {"matches": matches, "status": "success"}

            elif tool_name == "shodan_lookup_tool":
                from tools.shodan import shodan_lookup
                ip = tool_input.get("ip", "")
                result = shodan_lookup(ip)
                return {"shodan_result": result, "status": "success"}

            elif tool_name == "virustotal_lookup_tool":
                from tools.virustotal import virustotal_lookup
                resource = tool_input.get("resource", "")
                result = virustotal_lookup(resource)
                return {"virustotal_result": result, "status": "success"}

            elif tool_name == "abuseipdb_lookup_tool":
                from tools.abuseipdb import abuseipdb_lookup
                ip = tool_input.get("ip", "")
                result = abuseipdb_lookup(ip)
                return {"abuseipdb_result": result, "status": "success"}

            else:
                return {"error": f"Unknown tool: {tool_name}", "status": "error"}

        except Exception as e:
            return {"error": str(e), "status": "error"}

    def _synthesize_step(self, state: CyberShieldState) -> CyberShieldState:
        """Final synthesis and report generation"""
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

        # Add conversation history
        messages.extend(state.get("messages", []))

        # Add current scratchpad
        if state.get("agent_scratchpad"):
            messages.append(HumanMessage(content=f"Current progress:\n{state['agent_scratchpad']}"))

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

            return final_state.get("final_report", {"error": "No final report generated"})

        except Exception as e:
            logger.error(f"ReAct workflow failed: {e}")
            return {"error": str(e)}

# Factory function for easy instantiation
def create_cybershield_workflow(memory=None, vectorstore=None, llm_model="gpt-4o"):
    """Create a CyberShield ReAct workflow instance"""
    return CyberShieldReActAgent(memory, vectorstore, llm_model)