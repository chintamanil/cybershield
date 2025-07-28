# 🛡️ CyberShield AI System — Project Plan

## 📘 Executive Summary

CyberShield is a modular, AI-powered multi-agent system designed to automate complex cybersecurity tasks such as:

- IP/domain threat assessment
- PII redaction (text/image)
- Image-based risk detection

It uses agentic reasoning via the ReAct framework (Reason + Act) and integrates tools like Shodan, VirusTotal, AbuseIPDB alongside LLMs, NLP, and Vision AI.

**LLMs:** Azure GPT-4o, AWS Bedrock Claude
**Outcome:** Scalable, privacy-preserving AI assistant for cybersecurity automation.

## 🧩 Solution Outline

### Core Problem
Security teams manually assess threats & redact sensitive content—slow and error-prone.

### Key Features
- 🧠 Agentic multi-step reasoning (ReAct)
- 🛡️ NLP-based PII redaction (with reversibility)
- 🖼️ Image moderation (nudity/violence)
- 🌐 Real-time intelligence via APIs

### Tools & Technologies
- **NLP:** SpaCy, Regex, Presidio, AWS Comprehend
- **Vision:** OCR + CLIP / YOLOv8
- **Orchestration:** LangChain, CrewAI
- **APIs:** VirusTotal, AbuseIPDB, Shodan
- **Frameworks:** FastAPI, React, Redis, Milvus

## ⚙️ Working Mechanism

### ReAct Loop
1. **Thought** → Reason with LLM
2. **Action** → Trigger external/internal tools
3. **Observation** → Feed result back for next step

### Core Components
- **Agent:** Reasoning & orchestration
- **Planner:** Chain-of-thought, reflection
- **Tools:** APIs, NLP/PII tools, OCR
- **Memory:** Short-Term (chat) & Long-Term (facts)
- **Vision Module:** OCR + classifier

## 🧠 Memory Models

| Feature | Short-Term Memory (STM) | Long-Term Memory (LTM) |
|---------|-------------------------|------------------------|
| **Scope** | Session-based | Persistent |
| **Use Case** | Multi-turn context | Personalization, reuse |
| **Example** | Last API call | Known malicious IPs |
| **Store** | Redis / context | Milvus / S3 |

## 📊 Data Sources & Processing

- **Types:** IPs, domains, hashes, PDFs, images
- **Sources:** Public APIs + Kaggle/DARPA/CICIDS
- **Preprocessing:**
  - **Text:** SpaCy + Regex + normalizers
  - **Image:** Resize, OCR, noise cleaning

## 🔐 Use Cases

| Scenario | Description |
|----------|-------------|
| **SOC Automation** | Log scanning, alert enrichment |
| **Privacy Compliance** | Automated redaction (text/images) |
| **Threat Intelligence** | API-enriched reputation checks |
| **Image Risk Detection** | Screenshot risk scanning |

## 🧪 Feasibility & Challenges

- **Multi-tool Orchestration** → 🧠 Solved by ReAct planning
- **Reversible PII Redaction** → 🔐 Store encrypted mappings
- **Rate Limits** → ⏱ Caching, scheduling
- **Vision Model Accuracy** → 🧠 Pretrained models + OCR fallback

## 📉 Cost Optimization

| Resource | Est. Cost |
|----------|-----------|
| **LLM API** | $200/month (10K queries) |
| **Cloud Infra** | $100–300/month |
| **APIs** | Free tiers + paid scale |

### Tips:
- Use open-source LLMs (Mistral, LLama3)
- Prompt/API caching
- Batch queries

## 🗓️ Timeline & Roles

| Phase | Deliverable | Time |
|-------|-------------|------|
| **1** | API + PII tooling | 2 weeks |
| **2** | ReAct agents | 2 weeks |
| **3** | Vision AI | 1 week |
| **4** | UI (React/Streamlit) | 1.5 weeks |
| **5** | Testing + Launch | 1 week |

### Team:
- NLP Engineer
- Backend Engineer
- ML Engineer
- Frontend Dev
- DevOps

## 🔗 Dependencies

- **Infra:** AWS/Azure, Redis, S3, GPU
- **DBs:** Redis (STM), Milvus (LTM)
- **Libs:** LangChain, LangGraph, Presidio, CLIP, YOLOv8
- **External APIs:** VirusTotal, AbuseIPDB, Shodan

## 🗺️ System Architecture

### Mermaid Diagram — System Architecture

```mermaid
graph TD
    UQ[User Query] --> AG[Agent ReAct Loop]
    AG --> TH[Thought LLM Reasoning]
    TH --> AC[Action Call Tools]
    AC --> VT[🛠 VirusTotal]
    AC --> SH[🛠 Shodan]
    AC --> AB[🛠 AbuseIPDB]
    AC --> PI[🔍 PII Detection Regex, SpaCy, Presidio]
    AC --> IM[🖼️ Image Scanner OCR + Classifier]

    AG --> OB[Observation Tool Results]
    OB --> AG

    AG --> STM[🧠 Short-Term Memory Redis]
    AG --> LTM[🧠 Long-Term Memory Milvus]

    STM --> AG
    LTM --> AG

    style AG fill:#f39c12,stroke:#333,stroke-width:2px
    style STM fill:#3498db,color:#fff
    style LTM fill:#2ecc71,color:#fff
    style VT fill:#9b59b6,color:#fff
    style SH fill:#9b59b6,color:#fff
    style AB fill:#9b59b6,color:#fff
    style PI fill:#e67e22,color:#fff
    style IM fill:#e74c3c,color:#fff
    style OB fill:#95a5a6
    style TH fill:#1abc9c
    style AC fill:#1abc9c
```

### Updated Multi-Agent Architecture

```mermaid
graph TD
    U1[User Input Text or Log]
    A1[SupervisorAgent]
    A2[PIIAgent]
    A3[ThreatAgent]
    A4[LogParserAgent]
    T1[RegexChecker]
    T2[ShodanTool]
    T3[VirusTotalTool]
    T4[AbuseIPDBTool]
    M1[ShortTermMemory]
    M2[PIIMapperStore]
    V1[VectorStore]
    DB1[QueryLogsDB]

    U1 --> A1
    A1 --> A2
    A1 --> A4
    A1 --> A3

    A2 --> T1
    A3 --> T2
    A3 --> T3
    A3 --> T4
    A4 --> T1

    T1 --> M1
    T2 --> M1
    T3 --> M1
    T4 --> M1

    A2 --> M2
    A1 --> V1
    A1 --> DB1

    style A1 fill:#2c3e50, color:#ffffff
    style A2 fill:#16a085, color:#ffffff
    style A3 fill:#e74c3c, color:#ffffff
    style A4 fill:#f39c12, color:#ffffff
```

### Agent Flow Diagram

```
User Input
   ↓
SupervisorAgent
   ├──> PIIAgent (as tool)
   ├──> LogParserAgent (as tool)
   ├──> ThreatAgent (as tool)
   ├──> VectorStore (retrieval)
   └──> QueryLogsDB (audit log)
```



