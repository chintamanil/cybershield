# Temporal worker service for CyberShield
import asyncio
import logging
import signal
import sys
from typing import List

from utils.temporal_config import get_temporal_worker, get_config, close_temporal_connections
from utils.logging_config import setup_from_env, get_security_logger

# Import full workflow and all activities
from workflows.temporal.cybershield_workflow import CyberShieldWorkflow
from workflows.temporal.activities import (
    extract_iocs_activity,
    route_analysis_activity,
    synthesize_results_activity,
    virustotal_analysis_activity,
    abuseipdb_analysis_activity,
    shodan_analysis_activity,
    milvus_search_activity,
    vision_analysis_activity,
    pii_analysis_activity
)

# Setup logging
setup_from_env()
logger = get_security_logger("temporal_worker")


class CyberShieldWorker:
    """Temporal worker for CyberShield workflows and activities"""

    def __init__(self):
        self.worker = None
        self.config = get_config()
        self._shutdown_event = asyncio.Event()

    async def start(self):
        """Start the Temporal worker"""
        logger.info(
            "Starting CyberShield Temporal worker",
            task_queue=self.config.task_queue,
            target_host=self.config.target_host,
            namespace=self.config.namespace
        )

        try:
            # Define full workflows and activities (sandboxed=False allows all dependencies)
            workflows = [CyberShieldWorkflow]
            activities = [
                extract_iocs_activity,
                route_analysis_activity,
                synthesize_results_activity,
                virustotal_analysis_activity,
                abuseipdb_analysis_activity,
                shodan_analysis_activity,
                milvus_search_activity,
                vision_analysis_activity,
                pii_analysis_activity
            ]

            # Create worker
            self.worker = await get_temporal_worker(
                workflows=workflows,
                activities=activities,
                task_queue=self.config.task_queue
            )

            logger.info(
                "Temporal worker created successfully",
                workflows_count=len(workflows),
                activities_count=len(activities),
                max_concurrent_activities=self.config.max_concurrent_activities,
                max_concurrent_workflows=self.config.max_concurrent_workflows
            )

            # Start worker
            logger.info("Starting worker execution...")
            await self.worker.run()

        except KeyboardInterrupt:
            logger.info("Worker interrupted by user")
        except Exception as e:
            logger.error(f"Worker failed with error: {e}")
            raise
        finally:
            await self.shutdown()

    async def shutdown(self):
        """Graceful shutdown of the worker"""
        logger.info("Shutting down CyberShield Temporal worker")

        if self.worker:
            try:
                # The worker run() method handles its own cleanup
                pass
            except Exception as e:
                logger.error(f"Error during worker shutdown: {e}")

        # Close Temporal connections
        await close_temporal_connections()
        logger.info("Temporal worker shutdown complete")

    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, initiating graceful shutdown")
            self._shutdown_event.set()

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)


async def create_specialized_workers():
    """Create specialized workers for different analysis types"""
    config = get_config()
    workers = []

    # Main workflow worker
    main_worker = await get_temporal_worker(
        workflows=[CyberShieldWorkflow],
        activities=[
            extract_iocs_activity,
            route_analysis_activity,
            synthesize_results_activity,
            virustotal_analysis_activity,
            abuseipdb_analysis_activity,
            shodan_analysis_activity,
            milvus_search_activity,
            vision_analysis_activity,
            pii_analysis_activity
        ],
        task_queue=config.task_queue
    )
    workers.append(("main", main_worker))

    # Threat intelligence specialized worker
    threat_worker = await get_temporal_worker(
        workflows=[],
        activities=[
            virustotal_analysis_activity,
            abuseipdb_analysis_activity,
            shodan_analysis_activity,
            milvus_search_activity
        ],
        task_queue=f"{config.task_queue}-threat"
    )
    workers.append(("threat", threat_worker))

    # Vision specialized worker
    vision_worker = await get_temporal_worker(
        workflows=[],
        activities=[vision_analysis_activity],
        task_queue=f"{config.task_queue}-vision"
    )
    workers.append(("vision", vision_worker))

    # PII specialized worker
    pii_worker = await get_temporal_worker(
        workflows=[],
        activities=[pii_analysis_activity],
        task_queue=f"{config.task_queue}-pii"
    )
    workers.append(("pii", pii_worker))

    return workers


async def run_single_worker():
    """Run a single worker with all workflows and activities"""
    worker = CyberShieldWorker()
    worker.setup_signal_handlers()

    try:
        await worker.start()
    except Exception as e:
        logger.error(f"Worker failed: {e}")
        sys.exit(1)


async def run_multiple_workers():
    """Run multiple specialized workers"""
    logger.info("Starting multiple specialized Temporal workers")

    try:
        workers = await create_specialized_workers()
        logger.info(f"Created {len(workers)} specialized workers")

        # Run all workers concurrently
        tasks = []
        for worker_name, worker in workers:
            logger.info(f"Starting {worker_name} worker")
            task = asyncio.create_task(worker.run())
            tasks.append(task)

        # Wait for all workers to complete
        await asyncio.gather(*tasks)

    except KeyboardInterrupt:
        logger.info("Multiple workers interrupted by user")
    except Exception as e:
        logger.error(f"Multiple workers failed: {e}")
        raise
    finally:
        await close_temporal_connections()
        logger.info("All workers shutdown complete")


async def health_check():
    """Perform health check of Temporal connection"""
    try:
        from utils.temporal_config import get_temporal_client

        client = await get_temporal_client()

        # Simple connection test
        await client.workflow_service.get_system_info()

        logger.info("Temporal health check passed")
        return True
    except Exception as e:
        logger.error(f"Temporal health check failed: {e}")
        return False


def main():
    """Main entry point for the worker service"""
    import argparse

    parser = argparse.ArgumentParser(description="CyberShield Temporal Worker")
    parser.add_argument(
        "--mode",
        choices=["single", "multiple", "health-check"],
        default="single",
        help="Worker mode: single worker, multiple specialized workers, or health check"
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level"
    )

    args = parser.parse_args()

    # Set log level
    logging.getLogger().setLevel(getattr(logging, args.log_level))

    logger.info(
        "Starting CyberShield Temporal Worker",
        mode=args.mode,
        log_level=args.log_level
    )

    try:
        if args.mode == "health-check":
            result = asyncio.run(health_check())
            sys.exit(0 if result else 1)
        elif args.mode == "single":
            asyncio.run(run_single_worker())
        elif args.mode == "multiple":
            asyncio.run(run_multiple_workers())
    except KeyboardInterrupt:
        logger.info("Worker service interrupted")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Worker service failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()