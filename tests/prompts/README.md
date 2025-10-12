# CyberShield Sample Prompts Testing Suite

Comprehensive testing suite for CyberShield sample prompts with automated, integration, and interactive testing capabilities.

## 📁 Directory Structure

```
tests/prompts/
├── README.md                           # This file
├── __init__.py                         # Python package initialization
├── generate_test_images.py            # Script to generate test images
├── test_sample_prompts.py             # Automated pytest unit tests
├── test_sample_prompts_integration.py # FastAPI integration tests
├── interactive_prompt_tester.py       # Interactive CLI tester (executable)
├── benchmark_tester.py                # Benchmark & caching tests (executable)
├── test_data/
│   └── prompts.json                   # All test prompts organized by category
├── test_images/
│   ├── security_logs_screenshot.png   # Security logs with IOCs
│   ├── email_with_pii.png            # Email screenshot with PII data
│   └── security_dashboard.png        # Security dashboard mockup
└── results/
    └── *.json                         # Saved test results and benchmarks
```

## 🚀 Quick Start

### Prerequisites

1. **Install dependencies:**
   ```bash
   pip install -e ".[testing]"
   pip install rich  # For interactive CLI features
   ```

2. **Start the FastAPI server:**
   ```bash
   cybershield
   # OR
   python server/main.py
   ```

   Server should be running at `http://localhost:8000`

3. **Generate test images (if not already present):**
   ```bash
   python tests/prompts/generate_test_images.py
   ```

## 🧪 Running Tests

### 1. Automated Unit Tests (pytest)

Test individual components without requiring the server:

```bash
# Run all unit tests
pytest tests/prompts/test_sample_prompts.py -v

# Run specific test class
pytest tests/prompts/test_sample_prompts.py::TestBasicSecurityAnalysis -v

# Run with coverage
pytest tests/prompts/test_sample_prompts.py -v --cov=agents --cov=tools
```

**Test Categories:**
- `TestBasicSecurityAnalysis` - Basic threat detection
- `TestPIIDetection` - PII detection and masking
- `TestNetworkSecurityEvents` - Network security IOCs
- `TestAdvancedPersistentThreats` - APT detection
- `TestErrorHandling` - Error handling and edge cases
- `TestImageAnalysis` - Image file validation

### 2. Integration Tests (FastAPI)

Test the complete analysis pipeline through API endpoints:

```bash
# Run all integration tests (requires server running)
pytest tests/prompts/test_sample_prompts_integration.py -v

# Run specific test class
pytest tests/prompts/test_sample_prompts_integration.py::TestAnalyzeEndpoint -v

# Skip if server not running
pytest tests/prompts/test_sample_prompts_integration.py -v --skip-server-check
```

**Test Categories:**
- `TestAPIHealth` - Server health and availability
- `TestAnalyzeEndpoint` - Text analysis endpoint
- `TestImageAnalysisEndpoint` - Image upload and analysis
- `TestMultimodalAnalysis` - Combined text + image
- `TestBatchAnalysis` - Batch processing
- `TestToolEndpoints` - Individual tool endpoints

### 3. Interactive CLI Tester

Full-featured interactive testing with menu-driven interface:

```bash
# Run interactive tester
python tests/prompts/interactive_prompt_tester.py
# OR (if executable)
./tests/prompts/interactive_prompt_tester.py
```

**Features:**
- ✅ CLI menu to select different prompt categories
- ✅ Real-time API response visualization with rich formatting
- ✅ Ability to modify prompts on-the-fly
- ✅ Save test results to JSON files
- ✅ Response time benchmarks
- ✅ Caching effectiveness testing
- ✅ Multi-modal analysis (text + image)
- ✅ Benchmark history tracking
- ✅ Run all tests automatically

**Menu Options:**
1. Basic Security Analysis
2. PII Detection
3. Network Security Events
4. Advanced Persistent Threats
5. Error Handling Tests
6. Image Analysis
7. Multi-modal Analysis (Text + Image)
8. Custom Prompt
9. Benchmark & Caching Tests
10. View Benchmark History
11. Run All Tests
0. Exit

### 4. Benchmark & Caching Tests

Automated performance benchmarking and caching effectiveness:

```bash
# Run benchmark tests
python tests/prompts/benchmark_tester.py
# OR (if executable)
./tests/prompts/benchmark_tester.py
```

**Features:**
- Response time measurements
- Caching effectiveness analysis (first vs cached requests)
- Performance regression detection
- Baseline comparison
- Statistical analysis (mean, min, max, speedup %)
- Saves results with timestamps

**Output:**
- Performance summary table
- Overall statistics
- Comparison with baseline (if exists)
- JSON results saved to `results/` directory

## 📊 Test Data

### Prompts Data (`test_data/prompts.json`)

Organized by category with expected IOCs:

```json
{
  "basic_security_analysis": [...],
  "pii_detection": [...],
  "network_security_events": [...],
  "advanced_persistent_threats": [...],
  "error_handling": [...]
}
```

Each prompt includes:
- `id`: Unique identifier
- `name`: Human-readable name
- `prompt`: The actual test text
- `expected_iocs`: Expected indicators of compromise
- `expected_pii`: Expected PII detections
- `category`: Threat category
- `severity`: Threat level (for APT tests)

### Test Images

Generated test images with realistic security scenarios:

1. **`security_logs_screenshot.png`** (1200x800)
   - Terminal-style security logs
   - Multiple IOCs: IPs, hashes, domains
   - Color-coded severity levels
   - 16+ threat indicators

2. **`email_with_pii.png`** (1000x700)
   - Email interface mockup
   - Multiple PII types: SSN, credit card, DOB
   - Contact information
   - Realistic email layout

3. **`security_dashboard.png`** (1400x900)
   - Security operations dashboard
   - Critical alerts panel
   - Network activity monitoring
   - IOC summary
   - System status

## 📈 Benchmark Results

### Example Output

```
Benchmark Summary
┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━┓
┃ Test                  ┃ First (s) ┃ Cached(s) ┃ Speedup ┃
┡━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━┩
│ Test IP 8.8.8.8...    │     3.245 │     0.423 │  87.0%  │
│ Failed login from...  │     2.987 │     0.389 │  87.0%  │
│ Firewall blocked...   │     3.112 │     0.401 │  87.1%  │
└───────────────────────┴───────────┴───────────┴─────────┘

Overall Statistics:
  Avg First Request  3.115s
  Avg Cached Request 0.404s
  Avg Cache Speedup  87.0%
  Best Speedup       87.1%
```

## 🎯 Expected Test Results

### Basic Security Analysis
- ✅ Detect IP addresses (IPv4)
- ✅ Extract MD5/SHA-256 hashes
- ✅ Identify malicious domains
- ✅ Parse timestamps and log levels

### PII Detection
- ✅ SSN masking (123-45-6789 → [SSN])
- ✅ Credit card masking
- ✅ Email detection and masking
- ✅ Phone number detection
- ✅ Date of birth identification

### Network Security Events
- ✅ Firewall rule violations
- ✅ DNS query analysis
- ✅ Port scanning detection
- ✅ C2 server identification
- ✅ Bitcoin wallet detection

### Advanced Persistent Threats
- ✅ Lateral movement detection
- ✅ Cobalt Strike signatures
- ✅ Phishing email analysis
- ✅ Multi-stage attack correlation

### Error Handling
- ✅ Graceful handling of invalid IOCs
- ✅ Partial extraction from mixed data
- ✅ Rate limiting awareness
- ✅ No false positives

### Image Analysis
- ✅ OCR text extraction
- ✅ IOC detection in images
- ✅ PII detection in screenshots
- ✅ Multi-modal correlation

## 💾 Saved Results

Results are saved to `tests/prompts/results/` with timestamps:

- `test_result_YYYYMMDD_HHMMSS_<name>.json` - Individual test results
- `benchmark_results_YYYYMMDD_HHMMSS.json` - Benchmark results
- `benchmark_baseline.json` - Baseline for comparison
- `test_summary_YYYYMMDD_HHMMSS.json` - Complete test run summary

### Result Format

```json
{
  "timestamp": "2024-08-15T14:30:00",
  "prompt_name": "Failed Login with Hash",
  "prompt_text": "...",
  "elapsed_time": 3.245,
  "result": {
    "analysis": "...",
    "iocs": {...},
    "threats": [...]
  }
}
```

## 🔧 Troubleshooting

### Server Not Running
```bash
Error: Server not running at http://localhost:8000

Solution:
1. Start the server: cybershield
2. Check server health: curl http://localhost:8000/health
3. Verify port 8000 is available
```

### Test Images Missing
```bash
Error: Test images not found

Solution:
python tests/prompts/generate_test_images.py
```

### Import Errors
```bash
ModuleNotFoundError: No module named 'rich'

Solution:
pip install rich requests pytest
# OR
pip install -e ".[testing]"
```

### API Timeout
```bash
requests.exceptions.ReadTimeout: Read timed out

Solution:
1. Increase TIMEOUT in test files (default: 60s)
2. Check server performance
3. Verify network connectivity
```

## 📝 Adding New Tests

### 1. Add to `prompts.json`

```json
{
  "your_category": [
    {
      "id": "test_001",
      "name": "Your Test Name",
      "prompt": "Your test prompt text",
      "expected_iocs": {
        "ips": ["192.168.1.1"],
        "domains": ["example.com"]
      },
      "category": "your_category"
    }
  ]
}
```

### 2. Add Unit Test

```python
# In test_sample_prompts.py
def test_your_new_test(self, regex_checker, prompts_data):
    """Test your new functionality."""
    prompt = prompts_data["your_category"][0]
    result = regex_checker.extract_iocs(prompt["prompt"])

    assert "192.168.1.1" in result["ips"]
```

### 3. Add Integration Test

```python
# In test_sample_prompts_integration.py
def test_your_integration(self, prompts_data):
    """Test via API endpoint."""
    prompt = prompts_data["your_category"][0]
    result = self._call_analyze_endpoint(prompt["prompt"])

    assert result is not None
```

## 📚 Additional Resources

- **CyberShield Documentation**: `../../CLAUDE.md`
- **API Documentation**: http://localhost:8000/docs (when server running)
- **Sample Prompts**: `../../README.md` (section: Sample Prompts for Testing)
- **Agent Documentation**: `../../agents/README.md`

## 🎓 Usage Examples

### Quick Test Run
```bash
# Start server
cybershield &

# Run all automated tests
pytest tests/prompts/ -v

# Run interactive tester
python tests/prompts/interactive_prompt_tester.py

# Run benchmarks
python tests/prompts/benchmark_tester.py
```

### CI/CD Integration
```bash
# Run in CI pipeline
pytest tests/prompts/test_sample_prompts.py -v --tb=short --junit-xml=test-results.xml

# Integration tests (with server)
pytest tests/prompts/test_sample_prompts_integration.py -v --tb=short
```

### Performance Monitoring
```bash
# Regular benchmark runs
python tests/prompts/benchmark_tester.py

# Compare with baseline
# Results automatically compared with benchmark_baseline.json
```

## 🤝 Contributing

When adding new sample prompts to the README:

1. Add corresponding test data to `test_data/prompts.json`
2. Create unit tests in `test_sample_prompts.py`
3. Add integration tests in `test_sample_prompts_integration.py`
4. Update this README with new test categories
5. Run all tests to verify functionality

---

**CyberShield** - Comprehensive testing for advanced AI-powered cybersecurity.
