# Memory & Context Test Summary

**Generated**: 2025-10-12T10:22:31.388714

**Session ID**: 00da04ef-c801-4972-a6b6-b22331d89187

## Test Results

### sequential_ioc_analysis

```json
{
  "total_requests": 3,
  "successful_requests": 3,
  "context_indicators": [
    {
      "request_number": 2,
      "references_previous": true,
      "maintains_context": true,
      "response_length": 41601
    },
    {
      "request_number": 3,
      "references_previous": false,
      "maintains_context": true,
      "response_length": 28688
    }
  ],
  "context_preservation_score": 0.5
}
```

### incremental_threat_investigation

```json
{
  "total_requests": 4,
  "successful_requests": 4,
  "context_indicators": [
    {
      "request_number": 2,
      "references_previous": false,
      "maintains_context": true,
      "response_length": 1452
    },
    {
      "request_number": 3,
      "references_previous": false,
      "maintains_context": true,
      "response_length": 1456
    },
    {
      "request_number": 4,
      "references_previous": false,
      "maintains_context": true,
      "response_length": 1391
    }
  ],
  "context_preservation_score": 0.0
}
```

### cross_agent_data_sharing

```json
{
  "total_requests": 3,
  "successful_requests": 3,
  "context_indicators": [
    {
      "request_number": 2,
      "references_previous": true,
      "maintains_context": true,
      "response_length": 1371
    },
    {
      "request_number": 3,
      "references_previous": false,
      "maintains_context": true,
      "response_length": 1372
    }
  ],
  "context_preservation_score": 0.5
}
```

### session_id_comparison

```json
{
  "with_session": {
    "total_requests": 2,
    "successful_requests": 2,
    "context_indicators": [
      {
        "request_number": 2,
        "references_previous": false,
        "maintains_context": true,
        "response_length": 1351
      }
    ],
    "context_preservation_score": 0.0
  },
  "without_session": {
    "total_requests": 2,
    "successful_requests": 2,
    "context_indicators": [
      {
        "request_number": 2,
        "references_previous": false,
        "maintains_context": true,
        "response_length": 1351
      }
    ],
    "context_preservation_score": 0.0
  },
  "comparison": {
    "with_session_context_score": 0.0,
    "without_session_context_score": 0.0,
    "session_id_helps": true
  }
}
```

### redis_cache_persistence

```json
{
  "cache_effectiveness": {
    "first_request_time": 3.856647253036499,
    "subsequent_avg_time": 3.9033055305480957,
    "cache_likely_used": false,
    "all_response_times": [
      3.856647253036499,
      3.958508014678955,
      3.8481030464172363
    ]
  },
  "response_time_comparison": {
    "first_request": 3.856647253036499,
    "cached_request": 3.958508014678955,
    "speedup_percentage": -2.641173925415575
  }
}
```

