# Memory & Context Test Summary

**Generated**: 2025-10-12T15:02:41.492828

**Session ID**: 34573d92-542a-4501-9b3a-a5e3829c97d5

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
  - Resolved ip: `203.0.113.50`
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
        "ip": "203.0.113.50"
      },
      "resolution_successful": true,
      "resolved_iocs": {
        "ip": "203.0.113.50"
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
              "timestamp": "2025-10-12T15:02:03.557945",
              "input_text": "Suspicious activity from 192.168.1.100 connecting to malware-c2.example.com. Also detected traffic to 203.0.113.50 on port 443. File hash: d41d8cd98f00b204e9800998ecf8427e",
              "iocs_found": {
                "ips": [
                  "192.168.1.100",
                  "203.0.113.50"
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
                "low_risk": 5,
                "total": 5
              },
              "risk_level": "low",
              "summary": "4 IOCs detected, no significant threats"
            },
            {
              "timestamp": "2025-10-12T15:02:06.438306",
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
              "timestamp": "2025-10-12T15:02:09.654680",
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
              "timestamp": "2025-10-12T15:02:11.935261",
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
                "low_risk": 2,
                "total": 2
              },
              "risk_level": "low",
              "summary": "1 IOCs detected, no significant threats"
            },
            {
              "timestamp": "2025-10-12T15:02:14.335138",
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
              "timestamp": "2025-10-12T15:02:16.704144",
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
    "first_request_time": 2.915587902069092,
    "subsequent_avg_time": 1.4711440801620483,
    "cache_likely_used": true,
    "all_response_times": [
      2.915587902069092,
      0.12030529975891113,
      2.8219828605651855
    ]
  },
  "response_time_comparison": {
    "first_request": 2.915587902069092,
    "cached_request": 0.12030529975891113,
    "speedup_percentage": 95.8737207108887
  }
}
```

