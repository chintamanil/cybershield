# CyberShield Temporal Enterprise Features Implementation

## 🏗️ Current Architecture vs Enterprise Architecture

### **Current Simple Architecture**
```
Clients → FastAPI → CyberShieldWorkflow → Activities (API calls)
```

### **Target Enterprise Architecture**
```
Clients → Traffic Orchestrator Workflow → Child Workflows → Activities
   ↓           ↓                           ↓              ↓
Multi-tenant   Load Balancing         Threat Intel    HTTP/gRPC calls
Filtering      Task Queues            Scanner Jobs    DB writes
Signals        Search Attributes      Vision Analysis Encrypted payloads
```

## 📊 Feature Implementation Status

| Feature | Status | Priority | Implementation |
|---------|--------|----------|----------------|
| **Basic Task Queues** | ✅ Partial | High | Basic queues exist, need multi-tenant |
| **Signals & Queries** | ❌ Missing | High | Add real-time workflow control |
| **Search Attributes** | ❌ Missing | High | Multi-tenant filtering |
| **Child Workflows** | ❌ Missing | Medium | Traffic shaping, isolation |
| **Schedules** | ❌ Missing | Medium | Periodic security scans |
| **Data Converter** | ❌ Missing | Low | Payload encryption |
| **Worker Versioning** | ❌ Missing | Medium | Blue/green deployments |
| **Observability** | ❌ Missing | High | Tracing integration |
| **Multi-Region** | ❌ Missing | Low | Failover readiness |
| **mTLS** | ❌ Missing | Medium | Secure communications |

## 🚀 Implementation Plan (Without Temporal Cloud)

### **Phase 1: Core Enterprise Features (Week 1-2)**

#### **1. Multi-Tenant Task Queues & Search Attributes**

**File**: `workflows/temporal/enterprise/traffic_orchestrator.py`
```python
@workflow.defn
class TrafficOrchestratorWorkflow:
    """
    Enterprise traffic orchestrator with multi-tenant support
    """

    @workflow.run
    async def run(self, request: EnterpriseAnalysisRequest) -> AnalysisResult:
        # Set search attributes for filtering
        workflow.upsert_search_attributes({
            "tenant_id": request.tenant_id,
            "region": request.region,
            "sla_tier": request.sla_tier,
            "analysis_type": request.analysis_type.value,
            "priority": request.priority
        })

        # Route to tenant-specific task queue
        child_task_queue = f"cybershield-{request.tenant_id}-{request.sla_tier}"

        # Start child workflow for actual analysis
        result = await workflow.execute_child_workflow(
            CyberShieldWorkflow.run,
            request.to_base_request(),
            id=f"analysis-{request.tenant_id}-{workflow.uuid4()}",
            task_queue=child_task_queue
        )

        return result
```

**Search Attributes Schema** (`temporal-search-attributes.json`):
```json
{
    "tenant_id": "Keyword",
    "region": "Keyword",
    "sla_tier": "Keyword",
    "analysis_type": "Keyword",
    "priority": "Int",
    "threat_level": "Keyword",
    "created_at": "Datetime"
}
```

**Usage Examples**:
```bash
# Filter workflows by tenant
temporal workflow list --query 'tenant_id="enterprise_customer_1"'

# Filter by SLA and region
temporal workflow list --query 'sla_tier="premium" AND region="us-east-1"'

# High priority threats
temporal workflow list --query 'priority > 8 AND threat_level="critical"'
```

#### **2. Signals & Queries for Real-Time Control**

**File**: `workflows/temporal/enterprise/controllable_workflow.py`
```python
@workflow.defn
class ControllableAnalysisWorkflow:
    """
    Workflow with signals for real-time control
    """

    def __init__(self):
        self._paused = False
        self._cancelled = False
        self._priority = 5
        self._analysis_status = "starting"

    @workflow.signal
    async def pause_analysis(self):
        """Pause ongoing analysis"""
        self._paused = True
        self._analysis_status = "paused"

    @workflow.signal
    async def resume_analysis(self):
        """Resume paused analysis"""
        self._paused = False
        self._analysis_status = "running"

    @workflow.signal
    async def cancel_analysis(self, reason: str):
        """Cancel analysis with reason"""
        self._cancelled = True
        self._analysis_status = f"cancelled: {reason}"

    @workflow.signal
    async def update_priority(self, new_priority: int):
        """Update analysis priority"""
        self._priority = new_priority

    @workflow.query
    def get_status(self) -> Dict[str, Any]:
        """Query current workflow status"""
        return {
            "status": self._analysis_status,
            "paused": self._paused,
            "cancelled": self._cancelled,
            "priority": self._priority,
            "current_time": workflow.now().isoformat()
        }

    @workflow.query
    def get_progress(self) -> Dict[str, Any]:
        """Query analysis progress"""
        return {
            "completed_tools": self._completed_tools,
            "total_tools": self._total_tools,
            "progress_percent": len(self._completed_tools) / self._total_tools * 100,
            "estimated_remaining_seconds": self._estimate_remaining_time()
        }

    @workflow.run
    async def run(self, request: AnalysisRequest) -> AnalysisResult:
        try:
            while not self._cancelled:
                # Check if paused
                if self._paused:
                    await workflow.sleep(1)
                    continue

                # Execute analysis based on priority
                if self._priority >= 8:  # High priority
                    result = await self._execute_priority_analysis(request)
                else:  # Normal priority
                    result = await self._execute_normal_analysis(request)

                return result

        except Exception as e:
            self._analysis_status = f"failed: {str(e)}"
            raise
```

**Operations Examples**:
```bash
# Pause a running workflow
temporal workflow signal --workflow-id analysis-123 --name pause_analysis

# Query workflow status
temporal workflow query --workflow-id analysis-123 --name get_status

# Update priority
temporal workflow signal --workflow-id analysis-123 --name update_priority --input '{"new_priority": 9}'
```

#### **3. Child Workflows for Traffic Shaping**

**File**: `workflows/temporal/enterprise/child_workflows.py`
```python
@workflow.defn
class ThreatIntelChildWorkflow:
    """Child workflow for threat intelligence with resource limits"""

    @workflow.run
    async def run(self, request: ThreatIntelRequest) -> ThreatAnalysis:
        # Per-tenant concurrency limits
        tenant_config = await workflow.execute_activity(
            get_tenant_config_activity,
            request.tenant_id,
            start_to_close_timeout=timedelta(seconds=30)
        )

        # Adaptive concurrency based on tenant tier
        if tenant_config.sla_tier == "premium":
            max_concurrent = 10
        elif tenant_config.sla_tier == "standard":
            max_concurrent = 5
        else:  # basic
            max_concurrent = 2

        # Execute with concurrency limits
        semaphore = asyncio.Semaphore(max_concurrent)

        async def limited_execution(tool_func, *args):
            async with semaphore:
                return await workflow.execute_activity(
                    tool_func, *args,
                    start_to_close_timeout=timedelta(seconds=300),
                    retry_policy=tenant_config.retry_policy
                )

        # Run tools with limits
        results = await asyncio.gather(*[
            limited_execution(virustotal_analysis_activity, request.iocs),
            limited_execution(abuseipdb_analysis_activity, request.iocs),
            limited_execution(shodan_analysis_activity, request.iocs)
        ])

        return await self._aggregate_results(results)

@workflow.defn
class ScannerChildWorkflow:
    """Child workflow for periodic scanning jobs"""

    @workflow.run
    async def run(self, scan_request: PeriodicScanRequest) -> ScanResult:
        # Hedged calls for reliability
        primary_task = workflow.execute_activity(
            primary_scanner_activity,
            scan_request,
            start_to_close_timeout=timedelta(seconds=300)
        )

        # Start backup after delay
        await workflow.sleep(timedelta(seconds=30))
        backup_task = workflow.execute_activity(
            backup_scanner_activity,
            scan_request,
            start_to_close_timeout=timedelta(seconds=300)
        )

        # Return first successful result
        result = await workflow.race([primary_task, backup_task])
        return result
```

### **Phase 2: Operational Features (Week 3-4)**

#### **4. Schedules for Periodic Security Scans**

**File**: `workflows/temporal/enterprise/scheduled_workflows.py`
```python
# Create schedules programmatically
async def setup_security_schedules():
    """Setup periodic security scanning schedules"""

    # Daily vulnerability scans
    await client.create_schedule(
        id="daily-vuln-scan",
        schedule=ScheduleSpec(
            cron_expressions=["0 2 * * *"],  # Daily at 2 AM
            timezone="UTC"
        ),
        action=ScheduleActionStartWorkflow(
            workflow="VulnerabilityScannWorkflow",
            args=[{"scan_type": "full", "targets": "all"}],
            id_expression="vuln-scan-${now}",
            task_queue="cybershield-scheduled"
        ),
        policies=SchedulePolicies(
            overlap=ScheduleOverlapPolicy.BUFFER_ONE,
            catchup_window=timedelta(hours=1)
        ),
        search_attributes={
            "schedule_type": "vulnerability_scan",
            "frequency": "daily"
        }
    )

    # Hourly threat intel updates
    await client.create_schedule(
        id="hourly-threat-intel",
        schedule=ScheduleSpec(
            cron_expressions=["0 * * * *"],  # Every hour
        ),
        action=ScheduleActionStartWorkflow(
            workflow="ThreatIntelUpdateWorkflow",
            args=[{"sources": ["virustotal", "shodan", "abuseipdb"]}],
            task_queue="cybershield-intel"
        )
    )

    # Weekly security reports
    await client.create_schedule(
        id="weekly-security-report",
        schedule=ScheduleSpec(
            cron_expressions=["0 9 * * 1"],  # Monday at 9 AM
        ),
        action=ScheduleActionStartWorkflow(
            workflow="SecurityReportWorkflow",
            args=[{"report_type": "weekly", "recipients": ["security-team"]}],
            task_queue="cybershield-reports"
        )
    )
```

**Backfill After Incidents**:
```python
# Backfill missed scans after system outage
async def backfill_missed_scans(start_time: datetime, end_time: datetime):
    """Backfill security scans missed during outage"""

    schedule_handle = client.get_schedule_handle("daily-vuln-scan")

    # Calculate missed windows
    missed_windows = []
    current = start_time
    while current < end_time:
        missed_windows.append(current)
        current += timedelta(days=1)

    # Backfill each missed window
    for window_time in missed_windows:
        await schedule_handle.backfill([
            ScheduleBackfill(
                start_time=window_time,
                end_time=window_time + timedelta(hours=1),
                overlap=ScheduleOverlapPolicy.ALLOW_ALL
            )
        ])
```

#### **5. Worker Versioning for Blue/Green Deployments**

**File**: `deployment/worker_versioning.py`
```python
# Worker versioning setup
async def setup_worker_versioning():
    """Setup worker versioning for blue/green deployments"""

    # Create build ID for new version
    build_id = f"cybershield-{get_git_commit()}-{int(time.time())}"

    # Start workers with version
    worker = Worker(
        client,
        task_queue="cybershield-workflows",
        workflows=[CyberShieldWorkflow, DynamicCyberShieldWorkflow],
        activities=all_activities,
        build_id=build_id,
        use_worker_versioning=True
    )

    # Gradually shift traffic
    await client.update_worker_build_id_compatibility(
        task_queue="cybershield-workflows",
        operation=BuildIdOperation.AddNewCompatibleVersion(
            build_id=build_id,
            existing_compatible_build_id=previous_build_id
        )
    )

    # After validation, promote to default
    await client.update_worker_build_id_compatibility(
        task_queue="cybershield-workflows",
        operation=BuildIdOperation.PromoteBuildId(build_id=build_id)
    )
```

**Deployment Strategy**:
```bash
# Deploy new worker version
./deploy.sh --version=v2.1.0 --strategy=blue-green

# Gradual traffic shift
./gradual-shift.sh --from=v2.0.0 --to=v2.1.0 --steps=10 --interval=5m

# Rollback if issues
./rollback.sh --to=v2.0.0 --reason="high-error-rate"
```

### **Phase 3: Security & Observability (Week 5-6)**

#### **6. Data Converter for Payload Encryption**

**File**: `workflows/temporal/enterprise/encryption.py`
```python
class CyberShieldDataConverter:
    """Custom data converter with encryption for sensitive payloads"""

    def __init__(self, encryption_key: bytes):
        self.encryption_key = encryption_key
        self.fernet = Fernet(encryption_key)

    def encode(self, values: List[Any]) -> List[Payload]:
        """Encrypt sensitive data before storing in Temporal"""
        encoded = []

        for value in values:
            # Check if value contains sensitive data
            if self._contains_sensitive_data(value):
                # Encrypt the payload
                serialized = json.dumps(value, cls=SecurityEncoder)
                encrypted = self.fernet.encrypt(serialized.encode())

                encoded.append(Payload(
                    metadata={"encoding": "binary/encrypted"},
                    data=encrypted
                ))
            else:
                # Standard encoding for non-sensitive data
                encoded.append(Payload(
                    metadata={"encoding": "json/plain"},
                    data=json.dumps(value).encode()
                ))

        return encoded

    def decode(self, payloads: List[Payload]) -> List[Any]:
        """Decrypt payloads when reading from Temporal"""
        decoded = []

        for payload in payloads:
            if payload.metadata.get("encoding") == "binary/encrypted":
                # Decrypt sensitive data
                decrypted = self.fernet.decrypt(payload.data)
                value = json.loads(decrypted.decode())
                decoded.append(value)
            else:
                # Standard decoding
                value = json.loads(payload.data.decode())
                decoded.append(value)

        return decoded

    def _contains_sensitive_data(self, value: Any) -> bool:
        """Detect if value contains sensitive data"""
        sensitive_patterns = [
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit cards
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b'  # IP addresses
        ]

        value_str = str(value)
        return any(re.search(pattern, value_str) for pattern in sensitive_patterns)
```

#### **7. Observability with Tracing**

**File**: `workflows/temporal/enterprise/observability.py`
```python
class TracingActivityContext:
    """Activity context with distributed tracing"""

    def __init__(self, activity_info):
        self.activity_info = activity_info

        # Extract tracing headers from activity headers
        self.trace_context = {}
        headers = activity_info.headers

        if headers:
            # Extract OpenTelemetry context
            self.trace_context = {
                "trace_id": headers.get("trace-id"),
                "span_id": headers.get("span-id"),
                "trace_flags": headers.get("trace-flags"),
                "baggage": headers.get("baggage")
            }

    async def execute_with_tracing(self, func, *args, **kwargs):
        """Execute activity with distributed tracing"""
        import opentelemetry.trace as trace

        tracer = trace.get_tracer(__name__)

        with tracer.start_as_current_span(
            f"activity.{func.__name__}",
            context=self._restore_trace_context(),
            attributes={
                "activity.name": func.__name__,
                "activity.id": self.activity_info.activity_id,
                "workflow.id": self.activity_info.workflow_id,
                "task_queue": self.activity_info.task_queue
            }
        ) as span:
            try:
                result = await func(*args, **kwargs)
                span.set_status(trace.StatusCode.OK)
                return result
            except Exception as e:
                span.set_status(trace.StatusCode.ERROR, str(e))
                span.record_exception(e)
                raise

# Enhanced activities with tracing
@activity.defn
async def traced_virustotal_activity(iocs: IOCs) -> ThreatIntelResult:
    """VirusTotal activity with distributed tracing"""
    context = TracingActivityContext(activity.info())

    return await context.execute_with_tracing(
        _virustotal_analysis_impl,
        iocs
    )
```

#### **8. mTLS Configuration**

**File**: `config/temporal_tls.py`
```python
async def create_secure_temporal_client():
    """Create Temporal client with mTLS"""

    # Load client certificates
    with open("/etc/temporal/certs/client.pem", "rb") as f:
        client_cert = f.read()
    with open("/etc/temporal/certs/client-key.pem", "rb") as f:
        client_key = f.read()
    with open("/etc/temporal/certs/ca.pem", "rb") as f:
        ca_cert = f.read()

    # Create TLS config
    tls_config = TLSConfig(
        client_cert=client_cert,
        client_private_key=client_key,
        server_root_ca_cert=ca_cert,
        domain="temporal.cybershield.local"
    )

    # Connect with mTLS
    client = await Client.connect(
        target_host="temporal.cybershield.local:7233",
        namespace="cybershield-production",
        tls=tls_config
    )

    return client
```

### **Phase 4: Multi-Region Setup (Week 7-8)**

#### **9. Multi-Region Worker Deployment**

**File**: `deployment/multi_region.py`
```python
class MultiRegionWorkerManager:
    """Manage workers across multiple regions"""

    def __init__(self):
        self.regions = {
            "us-east-1": {"primary": True, "capacity": 100},
            "us-west-2": {"primary": False, "capacity": 75},
            "eu-west-1": {"primary": False, "capacity": 50}
        }

    async def deploy_workers(self):
        """Deploy workers in all regions"""
        tasks = []

        for region, config in self.regions.items():
            # Connect to region-specific Temporal cluster
            client = await self._connect_to_region(region)

            # Create workers with region-specific task queues
            for tenant in ["premium", "standard", "basic"]:
                task_queue = f"cybershield-{region}-{tenant}"

                worker = Worker(
                    client,
                    task_queue=task_queue,
                    workflows=[CyberShieldWorkflow],
                    activities=get_activities_for_region(region),
                    max_concurrent_activities=config["capacity"]
                )

                tasks.append(worker.run())

        # Run all workers concurrently
        await asyncio.gather(*tasks)

    async def handle_region_failover(self, failed_region: str):
        """Handle failover when a region goes down"""

        # Get workflows running in failed region
        failed_workflows = await self._get_workflows_in_region(failed_region)

        # Find backup region with capacity
        backup_region = self._select_backup_region(failed_region)

        # Signal workflows to migrate
        for workflow_id in failed_workflows:
            await self._signal_workflow_migration(
                workflow_id,
                failed_region,
                backup_region
            )

        # Scale up workers in backup regions
        await self._scale_workers(backup_region, scale_factor=1.5)
```

## 🎯 Implementation Priorities

### **High Priority (Implement First)**
1. **Multi-Tenant Task Queues** - Essential for production
2. **Search Attributes** - Required for ops dashboards
3. **Signals & Queries** - Real-time workflow control
4. **Observability** - Critical for debugging

### **Medium Priority (Implement Next)**
5. **Child Workflows** - Traffic shaping and isolation
6. **Schedules** - Periodic security scanning
7. **Worker Versioning** - Safe deployments

### **Low Priority (Future Enhancements)**
8. **Data Converter** - Enhanced security
9. **Multi-Region** - High availability
10. **mTLS** - Additional security layer

## 📈 Expected Benefits

### **Operational Benefits**
- **Multi-tenancy**: Isolate customers, apply SLA-based resource allocation
- **Observability**: End-to-end tracing, real-time workflow monitoring
- **Reliability**: Blue/green deployments, multi-region failover
- **Scalability**: Per-tenant task queues, adaptive concurrency

### **Security Benefits**
- **Data Protection**: Encrypted payloads for sensitive information
- **Access Control**: mTLS authentication and authorization
- **Audit Trail**: Complete workflow execution history with search
- **Compliance**: Tenant isolation and data encryption

### **Business Benefits**
- **SLA Compliance**: Priority-based processing, guaranteed response times
- **Cost Optimization**: Resource allocation based on tenant tier
- **Operational Excellence**: Automated incident response, proactive monitoring
- **Competitive Advantage**: Enterprise-grade security platform

This implementation plan transforms CyberShield from a simple Temporal usage into a production-ready, enterprise-grade security platform without requiring Temporal Cloud.