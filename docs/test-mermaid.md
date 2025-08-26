---
layout: default
title: "Mermaid Test Page"
description: "Test page to verify Mermaid diagram rendering"
---

# 🧪 Mermaid Diagram Test

This page tests Mermaid diagram rendering functionality.

## Simple Flow Chart Test

```mermaid
graph TD
    A[Start] --> B{Is it working?}
    B -->|Yes| C[Great!]
    B -->|No| D[Debug needed]
    C --> E[End]
    D --> E
```

## Architecture Test

```mermaid
graph LR
    Client[Client] --> ALB[Load Balancer]
    ALB --> ECS[ECS Container]
    ECS --> DB[(Database)]
```

## Pie Chart Test

```mermaid
pie title Test Coverage
    "Passing Tests" : 85
    "Failing Tests" : 10
    "Pending Tests" : 5
```

---

If you see rendered diagrams above (not code blocks), Mermaid is working correctly!