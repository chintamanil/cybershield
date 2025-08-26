---
layout: default
title: "API Documentation"
description: "Comprehensive CyberShield API reference with examples"
---

# 📚 API Documentation

## CyberShield API Reference

Complete API documentation for the CyberShield AI platform, including all endpoints, request/response formats, and practical examples.

---

## 🌐 **Base URL & Authentication**

### **Production API**
```
Base URL: https://cybershield-ai.com
Health Check: https://cybershield-ai.com/health
API Documentation: https://cybershield-ai.com/docs
```

### **Authentication**
Currently, CyberShield operates without authentication for public demonstration. In production deployments, implement:
- **API Keys**: Header-based authentication
- **JWT Tokens**: OAuth2/OpenID Connect
- **Rate Limiting**: Per-user/IP restrictions

---

## 🎯 **Core Analysis Endpoints**

### **1. Main Security Analysis**

#### `POST /analyze`

Primary endpoint for comprehensive security analysis combining multiple AI agents.

**Request:**
```json
{
  "text": "string",           // Required: Text to analyze
  "processing_mode": "string",  // Optional: "basic" | "comprehensive" 
  "session_id": "string"    // Optional: Session identifier
}
```

**Response:**
```json
{
  "status": "success",
  "processing_method": "sequential",
  "processing_time_ms": 1250.45,
  "pii_analysis": {
    "masked_text": "Contact [MASK_0] about incident",
    "pii_mapping": {
      "[MASK_0]": {
        "original": "john@company.com",
        "type": "email",
        "confidence": 0.95
      }
    },
    "pii_count": 1
  },
  "ioc_analysis": {
    "log_format": "unstructured",
    "text_length": 156,
    "extraction_timestamp": "2024-08-18T15:30:45.123456",
    "summary": {
      "total_iocs": 3,
      "ioc_types": ["ips", "domain", "email"]
    },
    "iocs": {
      "ips": ["203.0.113.1", "198.51.100.5"],
      "domain": ["malicious.example.com"],
      "email": ["admin@company.com"]
    }
  },
  "threat_analysis": {
    "ioc_reports": [
      {
        "ioc": "203.0.113.1",
        "ioc_type": "ip",
        "sources": {
          "abuseipdb": {
            "source": "abuseipdb",
            "data": {
              "abuseConfidencePercentage": 85,
              "countryCode": "CN",
              "lastReportedAt": "2024-08-15T09:22:33+00:00"
            }
          },
          "shodan": {
            "source": "shodan",
            "data": {
              "ports": [80, 443, 22],
              "hostnames": ["malicious-server.example.com"],
              "location": {"country_code": "CN"}
            }
          },
          "virustotal": {
            "source": "virustotal", 
            "data": {
              "attributes": {
                "reputation": -15,
                "last_analysis_stats": {
                  "malicious": 12,
                  "suspicious": 3,
                  "harmless": 65
                }
              }
            }
          }
        },
        "summary": {
          "risk_score": 88,
          "is_malicious": true,
          "confidence": 0.92,
          "threat_types": ["botnet", "malware_c2"]
        }
      }
    ]
  },
  "recommendations": [
    "Immediately isolate affected systems from network",
    "Block IP address 203.0.113.1 at firewall level", 
    "Scan systems for malware using updated signatures",
    "Review logs for additional compromise indicators"
  ]
}
```

**Example Usage:**
```bash
curl -X POST https://cybershield-ai.com/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Suspicious login from 203.0.113.1 accessing admin@company.com account. Hash detected: d41d8cd98f00b204e9800998ecf8427e",
    "processing_mode": "comprehensive"
  }'
```

---

### **2. Multimodal Analysis (Text + Image)**

#### `POST /analyze-with-image`

Advanced analysis combining text input with image processing for comprehensive security assessment.

**Request:**
```json
{
  "text": "string",           // Required: Text description
  "image": "base64_string", // Required: Base64 encoded image
  "processing_mode": "string"  // Optional: Analysis depth
}
```

**Response:**
```json
{
  "status": "success",
  "processing_method": "sequential",
  "processing_time_ms": 2847.23,
  "text_analysis": {
    // Same structure as /analyze endpoint
  },
  "vision_analysis": {
    "status": "success",
    "ocr": {
      "text": "CONFIDENTIAL DOCUMENT\nEmployee ID: E12345\nSSN: 123-45-6789",
      "confidence": 92,
      "word_count": 6
    },
    "classification": {
      "classifications": [
        {
          "label": "confidential_document",
          "score": 0.94
        },
        {
          "label": "financial_information", 
          "score": 0.87
        }
      ],
      "risk_level": "high",
      "confidence": 0.91
    },
    "sensitive_analysis": {
      "overall_risk": "high",
      "text_analysis": {
        "pii_detected": [
          {
            "type": "employee_id",
            "matches": ["E12345"],
            "count": 1
          },
          {
            "type": "ssn",
            "matches": ["123-45-6789"], 
            "count": 1
          }
        ]
      },
      "content_analysis": {
        "risk_level": "high",
        "flags": ["sensitive_document", "pii_present"],
        "max_risk_score": 0.94
      }
    },
    "recommendations": [
      "Immediately secure document - contains PII",
      "Verify authorized access to sensitive information",
      "Implement data loss prevention measures"
    ]
  }
}
```

**Example Usage:**
```bash
# Convert image to base64 first
IMAGE_B64=$(base64 -i suspicious_document.png)

curl -X POST https://cybershield-ai.com/analyze-with-image \
  -H "Content-Type: application/json" \
  -d "{
    \"text\": \"Suspicious document found on compromised system\",
    \"image\": \"$IMAGE_B64\",
    \"processing_mode\": \"comprehensive\"
  }"
```

---

### **3. Batch Analysis**

#### `POST /batch-analyze`

Process multiple inputs concurrently for bulk security analysis.

**Request:**
```json
{
  "inputs": [
    {
      "id": "log_entry_1",
      "text": "Failed login from 203.0.113.1",
      "processing_mode": "basic"
    },
    {
      "id": "log_entry_2", 
      "text": "Malware detected: hash d41d8cd98f00b204e9800998ecf8427e",
      "processing_mode": "comprehensive"
    }
  ],
  "session_id": "batch_session_123"
}
```

**Response:**
```json
{
  "status": "success",
  "total_processed": 2,
  "processing_time_ms": 3245.67,
  "results": [
    {
      "id": "log_entry_1",
      "status": "success",
      // ... standard analysis response
    },
    {
      "id": "log_entry_2",
      "status": "success", 
      // ... standard analysis response
    }
  ]
}
```

---

### **4. Image-Only Analysis**

#### `POST /upload-image`

Dedicated endpoint for image-only security analysis without accompanying text.

**Request:**
```json
{
  "image": "base64_string",  // Required: Base64 encoded image
  "analysis_type": "security" // Optional: "security" | "pii" | "full"
}
```

**Response:**
```json
{
  "status": "success",
  "processing_time_ms": 1834.12,
  "vision_analysis": {
    // Same structure as vision_analysis in /analyze-with-image
  }
}
```

---

## 🔧 **Tool-Specific Endpoints**

### **1. AbuseIPDB Integration**

#### `POST /tools/abuseipdb/check`

Direct IP reputation checking via AbuseIPDB API.

**Request:**
```json
{
  "ip": "203.0.113.1",      // Required: IP address to check
  "verbose": true           // Optional: Detailed response
}
```

**Response:**
```json
{
  "status": "success",
  "source": "abuseipdb",
  "data": {
    "ipAddress": "203.0.113.1",
    "isPublic": true,
    "ipVersion": 4,
    "isWhitelisted": false,
    "abuseConfidencePercentage": 85,
    "countryCode": "CN",
    "usageType": "Data Center/Web Hosting/Transit",
    "isp": "Example Hosting Provider",
    "domain": "example-hosting.com",
    "lastReportedAt": "2024-08-15T09:22:33+00:00",
    "numDistinctUsers": 15,
    "totalReports": 42
  },
  "risk_assessment": {
    "risk_level": "high",
    "confidence": 0.85,
    "factors": ["high_abuse_confidence", "recent_reports", "datacenter_ip"]
  }
}
```

---

### **2. Shodan Integration**

#### `POST /tools/shodan/lookup`

Host intelligence and reconnaissance via Shodan API.

**Request:**
```json
{
  "ip": "203.0.113.1",      // Required: IP address to lookup
  "include_ports": true     // Optional: Include port scan data
}
```

**Response:**
```json
{
  "status": "success",
  "source": "shodan",
  "data": {
    "ip_str": "203.0.113.1",
    "ports": [22, 80, 443, 3389],
    "hostnames": ["malicious-server.example.com"],
    "location": {
      "country_code": "CN",
      "country_name": "China",
      "region_code": "BJ",
      "city": "Beijing"
    },
    "org": "Example Hosting Ltd",
    "isp": "China Telecom",
    "services": [
      {
        "port": 80,
        "protocol": "http",
        "product": "nginx",
        "version": "1.18.0"
      },
      {
        "port": 443,
        "protocol": "https",
        "ssl": {
          "cert": {
            "subject": {
              "CN": "malicious.example.com"
            },
            "expired": false
          }
        }
      }
    ]
  },
  "risk_assessment": {
    "open_ports": 4,
    "suspicious_services": ["rdp_exposed"],
    "security_issues": ["outdated_nginx", "weak_ssl_config"]
  }
}
```

---

### **3. VirusTotal Integration**

#### `POST /tools/virustotal/lookup`

Multi-engine malware analysis via VirusTotal API.

**Request:**
```json
{
  "resource": "203.0.113.1",           // Required: IP/domain/hash
  "resource_type": "ip",               // Required: "ip" | "domain" | "hash"
  "include_context": true              // Optional: Additional context
}
```

**Response:**
```json
{
  "status": "success",
  "source": "virustotal",
  "resource": "203.0.113.1",
  "resource_type": "ip",
  "data": {
    "attributes": {
      "reputation": -15,
      "last_analysis_date": 1692358923,
      "last_analysis_stats": {
        "malicious": 12,
        "suspicious": 3,
        "undetected": 65,
        "harmless": 0,
        "timeout": 0
      },
      "last_modification_date": 1692358923,
      "network": "203.0.113.0/24",
      "country": "CN",
      "as_owner": "Example Hosting Provider",
      "asn": 12345
    },
    "relationships": {
      "communicating_files": {
        "data": [
          {
            "type": "file",
            "id": "d41d8cd98f00b204e9800998ecf8427e",
            "attributes": {
              "meaningful_name": "malware.exe",
              "last_analysis_stats": {
                "malicious": 45,
                "undetected": 25
              }
            }
          }
        ]
      }
    }
  },
  "analysis": {
    "threat_level": "high",
    "detection_ratio": "12/80",
    "verdict": "malicious",
    "confidence": 0.89
  }
}
```

---

### **4. Regex IOC Extraction**

#### `POST /tools/regex/extract`

Advanced IOC pattern extraction using 25+ cybersecurity patterns.

**Request:**
```json
{
  "text": "string",           // Required: Text to analyze
  "patterns": ["ip", "hash", "email"], // Optional: Specific patterns
  "validate": true      // Optional: Validate extracted IOCs
}
```

**Response:**
```json
{
  "status": "success",
  "extraction_stats": {
    "text_length": 245,
    "processing_time_ms": 156.78,
    "patterns_matched": 8,
    "total_extractions": 15
  },
  "iocs": {
    "ips": [
      {
        "value": "203.0.113.1",
        "type": "ipv4",
        "position": [45, 56],
        "context": "login from 203.0.113.1 failed",
        "validation": {
          "valid": true,
          "is_private": false,
          "is_reserved": false
        }
      }
    ],
    "hashes": [
      {
        "value": "d41d8cd98f00b204e9800998ecf8427e",
        "type": "md5",
        "position": [123, 155],
        "context": "file hash: d41d8cd98f00b204e9800998ecf8427e detected",
        "validation": {
          "valid": true,
          "format": "lowercase_hex"
        }
      }
    ],
    "email": [
      {
        "value": "admin@company.com",
        "type": "email", 
        "position": [78, 94],
        "context": "account admin@company.com compromised",
        "validation": {
          "valid": true,
          "domain_valid": true
        }
      }
    ]
  },
  "pattern_coverage": {
    "ipv4": 2,
    "md5": 1,
    "email": 1,
    "domain": 0,
    "url": 0
  }
}
```

---

### **5. Pattern Validation**

#### `POST /tools/regex/validate`

Validate specific IOC types using targeted patterns.

**Request:**
```json
{
  "indicators": [
    {"value": "203.0.113.1", "type": "ipv4"},
    {"value": "malicious.example.com", "type": "domain"},
    {"value": "d41d8cd98f00b204e9800998ecf8427e", "type": "md5"}
  ]
}
```

**Response:**
```json
{
  "status": "success",
  "validation_results": [
    {
      "value": "203.0.113.1",
      "type": "ipv4",
      "valid": true,
      "details": {
        "is_private": false,
        "is_reserved": false,
        "network_class": "C",
        "octets_valid": true
      }
    },
    {
      "value": "malicious.example.com",
      "type": "domain",
      "valid": true,
      "details": {
        "tld_valid": true,
        "format_valid": true,
        "suspicious_tld": false
      }
    },
    {
      "value": "d41d8cd98f00b204e9800998ecf8427e",
      "type": "md5",
      "valid": true,
      "details": {
        "length": 32,
        "format": "hex",
        "case": "lowercase"
      }
    }
  ]
}
```

---

## ⚙️ **System Endpoints**

### **1. Health Check**

#### `GET /health`

Simple health verification for load balancers and monitoring.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-08-18T15:30:45.123456Z",
  "version": "2.1.0",
  "uptime_seconds": 86400
}
```

---

### **2. System Status**

#### `GET /status`

Comprehensive system status including component health and performance metrics.

**Response:**
```json
{
  "status": "operational",
  "timestamp": "2024-08-18T15:30:45.123456Z",
  "version": "2.1.0",
  "system_info": {
    "platform": "linux",
    "python_version": "3.12.11",
    "memory_usage": {
      "used_mb": 1024,
      "total_mb": 2048,
      "percentage": 50.0
    },
    "disk_usage": {
      "used_gb": 5.2,
      "total_gb": 20.0,
      "percentage": 26.0
    }
  },
  "components": {
    "database": {
      "status": "healthy",
      "type": "postgresql",
      "connections": 5,
      "response_time_ms": 12.5
    },
    "cache": {
      "status": "healthy",
      "type": "redis",
      "memory_usage_mb": 128,
      "hit_rate": 0.85
    },
    "vector_db": {
      "status": "healthy",
      "type": "milvus",
      "collections": 1,
      "total_vectors": 120000
    }
  },
  "agents": {
    "supervisor": "available",
    "pii_agent": "available",
    "threat_agent": "available",
    "log_parser": "available", 
    "vision_agent": "available"
  },
  "external_apis": {
    "virustotal": {
      "status": "available",
      "quota_remaining": 1000,
      "last_check": "2024-08-18T15:29:12.123456Z"
    },
    "abuseipdb": {
      "status": "available",
      "quota_remaining": 500,
      "last_check": "2024-08-18T15:29:15.123456Z"
    },
    "shodan": {
      "status": "available", 
      "quota_remaining": 100,
      "last_check": "2024-08-18T15:29:18.123456Z"
    },
    "openai": {
      "status": "available",
      "model": "gpt-4",
      "last_check": "2024-08-18T15:29:21.123456Z"
    }
  },
  "performance": {
    "avg_response_time_ms": 245.67,
    "requests_per_minute": 24,
    "cache_hit_rate": 0.78,
    "error_rate": 0.02
  }
}
```

---

### **3. Interactive Documentation**

#### `GET /docs`

Auto-generated interactive API documentation using FastAPI's built-in Swagger UI.

**Features:**
- **Interactive Testing**: Execute API calls directly from documentation
- **Request/Response Examples**: Complete examples for all endpoints
- **Schema Validation**: Real-time validation of request payloads
- **Authentication Support**: API key integration when enabled

**Access**: Visit [https://cybershield-ai.com/docs](https://cybershield-ai.com/docs)

---

## 🚨 **Error Handling**

### **Standard Error Response**

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input parameters",
    "details": {
      "field": "text",
      "issue": "Text input is required and cannot be empty"
    },
    "timestamp": "2024-08-18T15:30:45.123456Z",
    "request_id": "req_abc123def456"
  }
}
```

### **Common Error Codes**

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 422 | Invalid request parameters |
| `RATE_LIMITED` | 429 | Too many requests |
| `API_ERROR` | 503 | External API unavailable |
| `PROCESSING_ERROR` | 500 | Internal processing failure |
| `TIMEOUT_ERROR` | 504 | Request processing timeout |

---

## 📊 **Rate Limits & Quotas**

### **Default Rate Limits**

| Endpoint Type | Rate Limit | Window |
|---------------|------------|--------|
| **Analysis Endpoints** | 60 requests | per minute |
| **Tool Endpoints** | 100 requests | per minute |
| **System Endpoints** | 300 requests | per minute |

### **External API Quotas**

| Service | Free Tier | Paid Tier |
|---------|-----------|-----------|
| **VirusTotal** | 1,000/day | 15,000/day |
| **AbuseIPDB** | 1,000/day | 10,000/day |
| **Shodan** | 100/month | 10,000/month |

---

## 🔒 **Security Considerations**

### **Input Validation**
- All inputs validated against strict schemas
- XSS and injection prevention
- File size limits for image uploads (10MB max)
- Content-type verification

### **Data Privacy**
- PII automatically detected and masked
- No logging of sensitive data
- Secure session management
- GDPR-compliant data handling

### **API Security**
- HTTPS enforced for all endpoints
- Request/response validation
- Error message sanitization
- No sensitive data in responses

---

This comprehensive API documentation provides everything needed to integrate with and utilize the CyberShield AI platform's advanced cybersecurity analysis capabilities.