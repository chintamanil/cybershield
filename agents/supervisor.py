# SupervisorAgent with Vision AI and LangGraph ReAct workflow
from typing import Dict, List, Optional, Union
from agents.pii_agent import PIIAgent
from agents.log_parser import LogParserAgent
from agents.threat_agent import ThreatAgent
from agents.vision_agent import VisionAgent
from utils.logging_config import get_security_logger
from utils.device_config import create_performance_config

logger = get_security_logger("supervisor")


class SupervisorAgent:
    """
    Supervisor agent that coordinates all CyberShield agents
    and integrates with the LangGraph ReAct workflow for intelligent processing.
    """

    def __init__(
        self,
        memory=None,
        vectorstore=None,
        use_react_workflow=True,
        abuseipdb_client=None,
        shodan_client=None,
        virustotal_client=None,
    ):
        self.memory = memory
        self.vectorstore = vectorstore
        self.use_react_workflow = use_react_workflow

        # Get performance configuration for M4 optimization
        self.perf_config = create_performance_config()

        logger.info(
            "Supervisor agent initializing with M4 optimization",
            use_react_workflow=use_react_workflow,
            device=self.perf_config["device"],
            batch_size=self.perf_config["batch_size"],
            memory_optimization=self.perf_config["memory_optimization"],
        )

        # Initialize individual agents
        self.pii_agent = PIIAgent(memory)
        self.log_parser = LogParserAgent()
        self.threat_agent = ThreatAgent(memory)
        self.vision_agent = VisionAgent(memory)

        # Initialize ReAct workflow if enabled
        if use_react_workflow:
            logger.debug(
                f"Attempting to initialize ReAct workflow with clients: {abuseipdb_client is not None}, {shodan_client is not None}, {virustotal_client is not None}"
            )
            try:
                from workflows.react_workflow import create_cybershield_workflow

                self.react_agent = create_cybershield_workflow(
                    memory,
                    vectorstore,
                    "gpt-4o",
                    abuseipdb_client,
                    shodan_client,
                    virustotal_client,
                )
                logger.info("ReAct workflow initialized", status="success")
            except Exception as e:
                logger.error("ReAct workflow initialization failed", error=str(e))
                logger.debug(f"ReAct workflow error details:", exc_info=True)
                self.react_agent = None
                self.use_react_workflow = False
        else:
            logger.info("ReAct workflow disabled", reason="use_react_workflow=False")
            self.react_agent = None

    async def initialize_clients(self):
        """Initialize all async clients in agents"""
        await self.threat_agent._get_clients()

    async def analyze(
        self, user_input: Union[str, Dict], image_data: Optional[bytes] = None
    ) -> Dict:
        """
        Main analysis method that processes text and/or image input.

        Args:
            user_input: Text input or dict with text and metadata
            image_data: Optional image data for vision analysis

        Returns:
            Comprehensive analysis results
        """
        try:
            # Extract text from input
            if isinstance(user_input, dict):
                text_input = user_input.get("text", "")
                if not image_data:
                    image_data = user_input.get("image")
            else:
                text_input = str(user_input)

            # Choose processing method
            logger.debug(
                f"use_react_workflow: {self.use_react_workflow}, react_agent exists: {self.react_agent is not None}"
            )
            if self.use_react_workflow and self.react_agent:
                return await self._process_with_react(text_input, image_data)
            else:
                logger.info("Using sequential processing (ReAct not available)")
                return await self._process_sequential(text_input, image_data)

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return {
                "status": "error",
                "error": str(e),
                "recommendations": ["System error occurred - please retry"],
            }

    async def _process_with_react(
        self, text_input: str, image_data: Optional[bytes] = None
    ) -> Dict:
        """Process input using the ReAct workflow"""
        try:
            logger.info("Processing with ReAct workflow")
            logger.debug(f"ReAct agent available: {self.react_agent is not None}")
            logger.debug(f"Text input length: {len(text_input) if text_input else 0}")

            result = await self.react_agent.process(text_input, image_data)

            # Debug: Log what we got back
            logger.info(
                "Received result from ReAct workflow",
                result_type=type(result).__name__,
                result_keys=(
                    list(result.keys()) if isinstance(result, dict) else "not_dict"
                ),
            )

            # Add supervisor metadata
            if isinstance(result, dict):
                result["processing_method"] = "react_workflow"
                result["supervisor_version"] = "2.0"
                logger.info("Successfully added supervisor metadata to ReAct result")
                return result
            else:
                logger.error(f"ReAct workflow returned non-dict result: {type(result)}")
                raise ValueError(
                    f"Invalid result type from ReAct workflow: {type(result)}"
                )

        except Exception as e:
            logger.error(f"ReAct processing failed: {e}")
            logger.debug(f"ReAct agent type: {type(self.react_agent)}")
            logger.debug(f"Exception type: {type(e)}")
            import traceback

            logger.debug(f"Full traceback: {traceback.format_exc()}")
            # Fallback to sequential processing
            logger.info("Falling back to sequential processing")
            return await self._process_sequential(text_input, image_data)

    async def _process_sequential(
        self, text_input: str, image_data: Optional[bytes] = None
    ) -> Dict:
        """Process input using sequential agent coordination (fallback method)"""
        try:
            logger.info("Processing with sequential workflow")

            results = {
                "processing_method": "sequential",
                "supervisor_version": "2.0",
                "input_analysis": {
                    "original_text": text_input,
                    "has_image": image_data is not None,
                },
            }

            # Step 1: PII Detection and Masking
            logger.debug("Step 1: PII Detection")
            masked_text, pii_map = await self.pii_agent.mask_pii(text_input)
            results["pii_analysis"] = {
                "masked_text": masked_text,
                "pii_mapping": pii_map,
                "pii_detected": bool(pii_map),
            }

            # Step 2: IOC Extraction
            logger.debug("Step 2: IOC Extraction")
            iocs = await self.log_parser.extract_iocs(masked_text)
            logger.debug(f"IOCs type: {type(iocs)}, value: {iocs}")
            results["ioc_analysis"] = {"extracted_iocs": iocs, "ioc_count": len(iocs)}

            # Step 3: Threat Analysis
            logger.debug("Step 3: Threat Analysis")
            threat_report = await self.threat_agent.evaluate(iocs)
            logger.debug(
                f"Threat report type: {type(threat_report)}, value: {threat_report}"
            )
            results["threat_analysis"] = threat_report

            # Step 4: Vision Analysis (if image provided)
            if image_data:
                logger.debug("Step 4: Vision Analysis")
                vision_analysis = await self.vision_agent.process_image(image_data)
                results["vision_analysis"] = vision_analysis

                # Extract text from image and re-analyze if needed
                ocr_text = vision_analysis.get("ocr", {}).get("text", "")
                if ocr_text.strip():
                    logger.debug("Re-analyzing OCR extracted text")
                    # Re-run analysis on OCR text
                    ocr_masked_text, ocr_pii_map = await self.pii_agent.mask_pii(
                        ocr_text
                    )
                    ocr_iocs = await self.log_parser.extract_iocs(ocr_masked_text)

                    # Merge results
                    if ocr_pii_map:
                        results["pii_analysis"]["ocr_pii_detected"] = True
                        results["pii_analysis"]["ocr_pii_mapping"] = ocr_pii_map

                    if ocr_iocs:
                        results["ioc_analysis"]["ocr_iocs"] = ocr_iocs
                        results["ioc_analysis"]["total_ioc_count"] = len(iocs) + len(
                            ocr_iocs
                        )
            else:
                results["vision_analysis"] = {"status": "no_image_provided"}

            # Step 5: Generate Recommendations
            results["recommendations"] = self._generate_recommendations(results)

            # Step 6: Store results in memory/vectorstore if available
            if self.memory:
                await self._store_analysis_results(results)

            results["status"] = "success"
            return results

        except Exception as e:
            logger.error(f"Sequential processing failed: {e}")
            return {
                "status": "error",
                "error": str(e),
                "processing_method": "sequential",
            }

    def _generate_recommendations(self, analysis_results: Dict) -> List[str]:
        """Generate comprehensive security recommendations"""
        recommendations = []

        # PII recommendations
        pii_analysis = analysis_results.get("pii_analysis", {})
        if pii_analysis.get("pii_detected"):
            recommendations.append(
                "🔒 PII detected - ensure proper data handling and compliance measures"
            )

        # IOC recommendations
        ioc_analysis = analysis_results.get("ioc_analysis", {})
        ioc_count = ioc_analysis.get("ioc_count", 0)
        total_ioc_count = ioc_analysis.get("total_ioc_count", ioc_count)

        if total_ioc_count > 0:
            recommendations.append(
                f"🚨 {total_ioc_count} indicators of compromise detected - investigate immediately"
            )

        # Threat recommendations
        threat_analysis = analysis_results.get("threat_analysis", {})
        if threat_analysis.get("high_risk_count", 0) > 0:
            recommendations.append(
                "⚠️ High-risk threats identified - escalate to security team"
            )

        # Vision recommendations
        vision_analysis = analysis_results.get("vision_analysis", {})
        if vision_analysis.get("recommendations"):
            recommendations.extend(
                [f"📷 {rec}" for rec in vision_analysis["recommendations"]]
            )

        # Overall security recommendations
        if vision_analysis.get("overall_risk") in ["high", "medium"]:
            recommendations.append("🛡️ monitoring recommended due to identified risks")

        # Default recommendation
        if not recommendations:
            recommendations.append(
                "✅ No immediate security concerns identified - continue monitoring"
            )

        return recommendations

    async def _store_analysis_results(self, results: Dict) -> None:
        """Store analysis results in memory and vectorstore"""
        try:
            if self.memory:
                # Store in short-term memory
                await self.memory.set("analysis_result", results)

                # Store PII mappings securely
                pii_mapping = results.get("pii_analysis", {}).get("pii_mapping")
                if pii_mapping:
                    # PII mappings are already stored by the PII agent
                    logger.debug(f"PII mappings available: {len(pii_mapping)} items")

            if self.vectorstore:
                # Create embeddings for threat intelligence
                threat_data = results.get("threat_analysis", {})
                if threat_data:
                    await self.vectorstore.store_threat_intelligence(threat_data)

        except Exception as e:
            logger.warning(f"Failed to store analysis results: {e}")

    def get_agent_status(self) -> Dict:
        """Get status of all agents and components"""
        return {
            "supervisor": {
                "version": "2.0",
                "react_workflow_enabled": self.use_react_workflow,
                "memory_available": self.memory is not None,
                "vectorstore_available": self.vectorstore is not None,
            },
            "agents": {
                "pii_agent": "active",
                "log_parser": "active",
                "threat_agent": "active",
                "vision_agent": "active",
            },
            "react_agent": "active" if self.react_agent else "inactive",
        }

    async def analyze_batch(self, inputs: List[str]) -> List[Dict]:
        """
        Analyze multiple text inputs in batch

        Args:
            inputs: List of text strings to analyze

        Returns:
            List of analysis results
        """
        results = []

        for i, text_input in enumerate(inputs):
            try:
                logger.info(f"Processing batch item {i+1}/{len(inputs)}")
                result = await self.analyze(text_input)
                results.append(result)
            except Exception as e:
                logger.error(f"Batch analysis failed for item {i+1}: {e}")
                results.append({"status": "error", "error": str(e), "input_index": i})

        return results
