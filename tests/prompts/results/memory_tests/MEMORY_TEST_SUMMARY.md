# Memory & Context Test Summary

**Generated**: 2025-10-12T12:17:20.755152

**Session ID**: 849df1ac-cfb4-4fcb-9c70-5654ef64e1b2

## Scoring Metric

**Pronoun Resolution Score**: Measures actual context preservation via pronoun → IOC resolution

- Checks for `context_enrichment` field in responses
- Verifies that `context_used` contains actual resolved IOC values
- Confirms pronouns were successfully replaced with real indicators
- **1.00** = Perfect (all pronouns resolved correctly)
- **0.00** = No pronoun resolution occurred (may be expected for some tests)

## Test Results

### sequential_ioc_analysis

**Pronoun Resolution Score**: 1.00

**Resolution Details**:

- Request 2: ✓ Success
  - Resolved ip: `192.168.1.100`
- Request 3: ✓ Success
  - Resolved domain: `malware-c2.example.com`

**Full Analysis**:
```json
{
  "total_requests": 3,
  "successful_requests": 3,
  "pronoun_resolution_indicators": [
    {
      "request_number": 2,
      "has_context_enrichment": true,
      "enriched": true,
      "context_used": {
        "ip": "192.168.1.100"
      },
      "resolution_successful": true,
      "resolved_iocs": {
        "ip": "192.168.1.100"
      }
    },
    {
      "request_number": 3,
      "has_context_enrichment": true,
      "enriched": true,
      "context_used": {
        "domain": "malware-c2.example.com"
      },
      "resolution_successful": true,
      "resolved_iocs": {
        "domain": "malware-c2.example.com"
      }
    }
  ],
  "pronoun_resolution_score": 1.0
}
```

### incremental_threat_investigation

**Pronoun Resolution Score**: 1.00

**Resolution Details**:

- Request 2: ✓ Success
  - Resolved ip: `198.51.100.25`
- Request 3: ✓ Success
  - Resolved ip: `198.51.100.25`
- Request 4: ✓ Success
  - Resolved attack_chain: `6 events`

**Full Analysis**:
```json
{
  "total_requests": 4,
  "successful_requests": 4,
  "pronoun_resolution_indicators": [
    {
      "request_number": 2,
      "has_context_enrichment": true,
      "enriched": true,
      "context_used": {
        "ip": "198.51.100.25"
      },
      "resolution_successful": true,
      "resolved_iocs": {
        "ip": "198.51.100.25"
      }
    },
    {
      "request_number": 3,
      "has_context_enrichment": true,
      "enriched": true,
      "context_used": {
        "ip": "198.51.100.25"
      },
      "resolution_successful": true,
      "resolved_iocs": {
        "ip": "198.51.100.25"
      }
    },
    {
      "request_number": 4,
      "has_context_enrichment": true,
      "enriched": true,
      "context_used": {
        "attack_chain": {
          "event_count": 6,
          "events": [
            {
              "timestamp": "2025-10-12T11:54:01.390519",
              "input_text": "Suspicious activity from 192.168.1.100 connecting to malware-c2.example.com. Also detected traffic to 203.0.113.50 on port 443. File hash: d41d8cd98f00b204e9800998ecf8427e",
              "iocs_found": {
                "ips": [
                  "203.0.113.50",
                  "192.168.1.100"
                ],
                "domains": [
                  "malware-c2.example.com"
                ],
                "hashes": [
                  "d41d8cd98f00b204e9800998ecf8427e"
                ]
              },
              "threats_detected": {
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 7,
                "total": 7
              },
              "risk_level": "low",
              "summary": "4 IOCs detected, no significant threats"
            },
            {
              "timestamp": "2025-10-12T11:54:04.573072",
              "input_text": "Tell me more about the IP address 192.168.1.100 from the previous analysis. What threats are associated with it?",
              "iocs_found": {
                "ips": [
                  "192.168.1.100"
                ],
                "domains": [],
                "hashes": []
              },
              "threats_detected": {
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 3,
                "total": 3
              },
              "risk_level": "low",
              "summary": "1 IOCs detected, no significant threats"
            },
            {
              "timestamp": "2025-10-12T11:54:07.461910",
              "input_text": "What about the domain malware-c2.example.com? Is it malicious?",
              "iocs_found": {
                "ips": [],
                "domains": [
                  "malware-c2.example.com"
                ],
                "hashes": []
              },
              "threats_detected": {
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 1,
                "total": 1
              },
              "risk_level": "low",
              "summary": "1 IOCs detected, no significant threats"
            },
            {
              "timestamp": "2025-10-12T11:54:09.229182",
              "input_text": "Detected failed login from IP 198.51.100.25",
              "iocs_found": {
                "ips": [
                  "198.51.100.25"
                ],
                "domains": [],
                "hashes": []
              },
              "threats_detected": {
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 3,
                "total": 3
              },
              "risk_level": "low",
              "summary": "1 IOCs detected, no significant threats"
            },
            {
              "timestamp": "2025-10-12T11:54:12.125126",
              "input_text": "The same IP is now scanning ports 22, 23, 3389",
              "iocs_found": {
                "ips": [],
                "domains": [],
                "hashes": []
              },
              "threats_detected": {
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 0,
                "total": 0
              },
              "risk_level": "low",
              "summary": "No IOCs or threats detected"
            },
            {
              "timestamp": "2025-10-12T11:54:14.714959",
              "input_text": "Successful SSH connection established from that IP",
              "iocs_found": {
                "ips": [],
                "domains": [],
                "hashes": []
              },
              "threats_detected": {
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 0,
                "total": 0
              },
              "risk_level": "low",
              "summary": "No IOCs or threats detected"
            }
          ]
        }
      },
      "resolution_successful": true,
      "resolved_iocs": {
        "attack_chain": "6 events"
      }
    }
  ],
  "pronoun_resolution_score": 1.0
}
```

### cross_agent_data_sharing

**Pronoun Resolution Score**: 1.00

**Resolution Details**:

- Request 2: ✓ Success
  - Resolved ip: `45.76.123.89`
- Request 3: ✓ Success
  - Resolved domain: `suspicious-domain.net`

**Full Analysis**:
```json
{
  "total_requests": 3,
  "successful_requests": 3,
  "pronoun_resolution_indicators": [
    {
      "request_number": 2,
      "has_context_enrichment": true,
      "enriched": true,
      "context_used": {
        "ip": "45.76.123.89"
      },
      "resolution_successful": true,
      "resolved_iocs": {
        "ip": "45.76.123.89"
      }
    },
    {
      "request_number": 3,
      "has_context_enrichment": true,
      "enriched": true,
      "context_used": {
        "domain": "suspicious-domain.net"
      },
      "resolution_successful": true,
      "resolved_iocs": {
        "domain": "suspicious-domain.net"
      }
    }
  ],
  "pronoun_resolution_score": 1.0
}
```

### session_id_comparison

**Pronoun Resolution Score**: 1.00

**Full Analysis**:
```json
{
  "with_session": {
    "total_requests": 2,
    "successful_requests": 2,
    "pronoun_resolution_indicators": [
      {
        "request_number": 2,
        "has_context_enrichment": true,
        "enriched": true,
        "context_used": {
          "ip": "8.8.8.8"
        },
        "resolution_successful": true,
        "resolved_iocs": {
          "ip": "8.8.8.8"
        }
      }
    ],
    "pronoun_resolution_score": 1.0
  },
  "without_session": {
    "total_requests": 2,
    "successful_requests": 2,
    "pronoun_resolution_indicators": [
      {
        "request_number": 2,
        "has_context_enrichment": true,
        "enriched": true,
        "context_used": {
          "ip": "8.8.8.8"
        },
        "resolution_successful": true,
        "resolved_iocs": {
          "ip": "8.8.8.8"
        }
      }
    ],
    "pronoun_resolution_score": 1.0
  },
  "comparison": {
    "with_session_pronoun_score": 1.0,
    "without_session_pronoun_score": 1.0,
    "session_id_helps": true
  }
}
```

### redis_cache_persistence

**Pronoun Resolution Score**: 0.00

**Full Analysis**:
```json
{
  "cache_effectiveness": {
    "first_request_time": 0.028115272521972656,
    "subsequent_avg_time": 0.032973408699035645,
    "cache_likely_used": false,
    "all_response_times": [
      0.028115272521972656,
      0.03699302673339844,
      0.02895379066467285
    ]
  },
  "response_time_comparison": {
    "first_request": 0.028115272521972656,
    "cached_request": 0.03699302673339844,
    "speedup_percentage": -31.57626946168719
  }
}
```

