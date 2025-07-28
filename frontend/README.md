# CyberShield Streamlit Frontend

A modern, interactive web interface for the CyberShield AI Security System built with Streamlit.

## 🌟 Features

### 📊 **Comprehensive Analysis Dashboard**
- **Single Text Analysis**: Analyze individual text inputs for security threats, PII, and IOCs
- **Batch Processing**: Upload files or enter multiple texts for bulk analysis
- **Image Analysis**: OCR text extraction and visual security risk assessment
- **Real-time Results**: Interactive visualizations and detailed breakdowns

### 🔧 **Advanced Security Tools**
- **IOC Extraction**: Extract indicators of compromise using regex patterns
- **IP Reputation**: Check IPs against AbuseIPDB, Shodan, and VirusTotal
- **Domain Analysis**: Analyze domains for threats and reputation
- **Hash Verification**: Verify file hashes against threat databases
- **Pattern Validation**: Validate specific IOC patterns

### 📈 **Data Visualization**
- Interactive charts and graphs using Plotly
- Risk level distributions and threat timelines
- IOC type breakdowns and statistics
- Progress tracking for batch operations

### 🛡️ **Security Features**
- PII detection and masking capabilities
- Multi-source threat intelligence integration
- Vision AI for image content analysis
- ReAct workflow for intelligent reasoning

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- FastAPI backend running on `http://localhost:8000`
- Required Python packages (see requirements.txt)

### Installation

1. **Install dependencies:**
```bash
cd frontend
pip install -r requirements.txt
```

2. **Start the FastAPI backend:**
```bash
cd ..
python server/main.py
```

3. **Launch Streamlit frontend:**
```bash
# Option 1: Using the runner script
python run_streamlit.py

# Option 2: Direct streamlit command
streamlit run streamlit_app.py --server.port 8501

# Option 3: With automatic setup
python run_streamlit.py --install
```

### Access the Application
- **Frontend UI**: http://localhost:8501
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs

## 📱 User Interface

### 🏠 **Main Dashboard**
The main interface provides four primary tabs:

#### 🔍 **Single Analysis**
- Text input area for security analysis
- Configuration options (ReAct workflow, vision analysis)
- Real-time progress indicators
- Comprehensive results display with multiple tabs:
  - 🔒 PII Analysis
  - 🚨 IOC Analysis  
  - ⚠️ Threat Analysis
  - 📷 Vision Analysis
  - 🔧 Tool Analysis
  - 💡 Recommendations

#### 📊 **Batch Analysis**
- **Manual Entry**: Enter multiple texts line by line
- **File Upload**: Support for TXT and CSV files
- **Progress Tracking**: Real-time batch processing status
- **Summary View**: Overview table of all results
- **Detailed Results**: Expandable sections for each input

#### 📷 **Image Analysis**
- **Image Upload**: Support for PNG, JPG, JPEG, GIF, BMP
- **OCR Extraction**: Text extraction with confidence scores
- **Content Classification**: Security risk assessment
- **PII Detection**: Identify sensitive information in images
- **Combined Analysis**: Image + text context analysis

#### 🔧 **Advanced Tools**
Direct access to security tools:
- **IOC Extraction**: Comprehensive pattern detection
- **IP Lookups**: AbuseIPDB, Shodan, VirusTotal integration
- **Hash Analysis**: File hash verification
- **Pattern Validation**: Specific IOC type validation

### 🎛️ **Sidebar Controls**

#### 🔍 **System Status**
- Real-time backend connectivity check
- Component availability verification
- Tool service status monitoring

#### ⚙️ **Analysis Options**
- **ReAct Workflow**: Enable intelligent multi-step reasoning
- **Vision Analysis**: Include image processing capabilities

#### 🛠️ **Quick Tools**
- **IP Reputation Check**: Instant IP analysis
- **Domain Analysis**: Quick domain reputation lookup

## 🔧 Configuration

### Environment Variables
```bash
# Backend Configuration
FASTAPI_HOST=localhost
FASTAPI_PORT=8000

# Streamlit Configuration  
STREAMLIT_SERVER_PORT=8501
STREAMLIT_SERVER_ENABLE_CORS=false
```

### Streamlit Configuration
The `.streamlit/config.toml` file contains:
- Theme customization (colors, fonts)
- Server settings (port, CORS, uploads)
- UI preferences (sidebar, navigation)

### Upload Limits
- **Max File Size**: 200MB
- **Supported Image Types**: PNG, JPG, JPEG, GIF, BMP
- **Supported Text Types**: TXT, CSV, JSON, LOG

## 📊 Data Visualization

### Chart Types
- **Bar Charts**: IOC distribution by type
- **Pie Charts**: Threat level distributions  
- **Line Charts**: Analysis timelines
- **Progress Bars**: Real-time processing status
- **Metrics Cards**: Key statistics and counts

### Interactive Elements
- **Expandable Sections**: Detailed result exploration
- **Tabbed Interface**: Organized result presentation
- **Filterable Tables**: Sortable data views
- **Downloadable Results**: Export capabilities

## 🔒 Security Considerations

### Data Handling
- **PII Protection**: Automatic detection and masking
- **Secure Transmission**: HTTPS recommended for production
- **Session Management**: Stateless design for security
- **Input Validation**: Comprehensive sanitization

### Access Control
- **CORS Configuration**: Restricted to frontend domains
- **File Upload Validation**: Type and size restrictions
- **API Rate Limiting**: Backend throttling support
- **Error Handling**: Secure error message display

## 🐛 Troubleshooting

### Common Issues

1. **Backend Connection Failed**
   ```
   ❌ Cannot connect to FastAPI backend
   ```
   - Ensure FastAPI server is running on port 8000
   - Check firewall settings
   - Verify backend health at http://localhost:8000/health

2. **File Upload Errors**
   ```
   File size exceeds maximum limit
   ```
   - Check file size (max 200MB)
   - Verify file type is supported
   - Try compressing large files

3. **Analysis Timeout**
   ```
   Request timed out
   ```
   - Reduce input size for batch operations
   - Check backend server resources
   - Try breaking large requests into smaller batches

4. **Missing Dependencies**
   ```
   ModuleNotFoundError
   ```
   - Run `pip install -r requirements.txt`
   - Use `python run_streamlit.py --install`
   - Check Python version compatibility

### Debug Mode
Enable debug logging:
```bash
streamlit run streamlit_app.py --logger.level debug
```

### Performance Tips
- **Batch Size**: Limit to 50-100 items per batch
- **Image Size**: Compress large images before upload
- **Browser Cache**: Clear cache if experiencing issues
- **Network**: Use stable internet connection for API calls

## 🔄 Development

### Project Structure
```
frontend/
├── streamlit_app.py         # Main Streamlit application
├── config.py               # Configuration settings
├── utils.py                # Utility functions and API client
├── requirements.txt        # Python dependencies
├── run_streamlit.py        # Application launcher
├── .streamlit/
│   └── config.toml         # Streamlit configuration
└── README.md              # This file
```

### Adding New Features
1. **New Analysis Type**: Add to `config.py` ANALYSIS_TYPES
2. **New Visualization**: Extend `utils.DataVisualizer`
3. **New Tool Integration**: Add methods to `utils.APIClient`
4. **UI Components**: Create reusable functions in `utils.UIHelpers`

### Testing
```bash
# Test backend connectivity
python -c "from utils import APIClient; print(APIClient().health_check())"

# Test Streamlit configuration
streamlit config show

# Validate requirements
pip check
```

## 📝 API Integration

The frontend integrates with these FastAPI endpoints:

### Core Endpoints
- `POST /analyze` - Single text analysis
- `POST /analyze-with-image` - Text + image analysis
- `POST /batch-analyze` - Multiple text analysis
- `POST /upload-image` - Image-only analysis
- `GET /status` - System status
- `GET /health` - Health check

### Tool Endpoints
- `POST /tools/abuseipdb/check` - IP reputation check
- `POST /tools/shodan/lookup` - IP intelligence lookup
- `POST /tools/virustotal/lookup` - Resource analysis
- `POST /tools/regex/extract` - IOC extraction
- `POST /tools/regex/validate` - Pattern validation

## 🎨 Customization

### Theme Modification
Edit `.streamlit/config.toml`:
```toml
[theme]
primaryColor = "#3498db"        # Primary accent color
backgroundColor = "#ffffff"     # Main background
secondaryBackgroundColor = "#f0f2f6"  # Sidebar/secondary areas
textColor = "#262730"          # Text color
font = "sans serif"            # Font family
```

### Adding Custom Charts
Extend `utils.DataVisualizer` with new chart types:
```python
@staticmethod
def create_custom_chart(data):
    fig = px.custom_chart(data)
    return fig
```

## 📞 Support

For issues and questions:
1. Check the troubleshooting section above
2. Verify backend connectivity
3. Review Streamlit logs
4. Check FastAPI documentation at `/docs`

## 🔄 Updates

The frontend automatically detects backend API changes and adapts accordingly. For manual updates:
1. Pull latest changes
2. Update dependencies: `pip install -r requirements.txt`
3. Restart both backend and frontend services