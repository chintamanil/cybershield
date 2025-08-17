"""
Bedrock Fine-tuning Data Preparation for CyberShield
Converts existing cybersecurity data into Bedrock training format
"""

import json
import pandas as pd
import asyncio
from typing import List, Dict, Any
from pathlib import Path
import boto3
from dataclasses import dataclass
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class TrainingExample:
    """Training example for Bedrock fine-tuning"""
    prompt: str
    completion: str
    category: str = "cybersecurity"

class CyberShieldDataPreparator:
    """Prepares CyberShield data for Bedrock fine-tuning"""
    
    def __init__(self, s3_bucket: str, aws_region: str = "us-east-1"):
        self.s3_bucket = s3_bucket
        self.s3_client = boto3.client('s3', region_name=aws_region)
        self.training_examples: List[TrainingExample] = []
        
    async def prepare_threat_classification_data(self, csv_path: str) -> List[TrainingExample]:
        """Convert cybersecurity attacks CSV to training examples"""
        logger.info(f"Loading cybersecurity data from {csv_path}")
        
        df = pd.read_csv(csv_path)
        examples = []
        
        for _, row in df.iterrows():
            # Create threat classification examples
            prompt = self._create_threat_classification_prompt(row)
            completion = self._create_threat_classification_completion(row)
            
            examples.append(TrainingExample(
                prompt=prompt,
                completion=completion,
                category="threat_classification"
            ))
            
        logger.info(f"Created {len(examples)} threat classification examples")
        return examples
    
    def _create_threat_classification_prompt(self, row: pd.Series) -> str:
        """Create a threat classification prompt"""
        return f"""Analyze the following cybersecurity incident and classify the threat:

Source IP: {row.get('Source_IP', 'unknown')}
Destination IP: {row.get('Destination_IP', 'unknown')}
Protocol: {row.get('Protocol', 'unknown')}
Port: {row.get('Destination_Port', 'unknown')}
Attack Type: {row.get('Attack_Type', 'unknown')}
Packet Length: {row.get('Packet_Length', 'unknown')}
Action Taken: {row.get('Action_Taken', 'unknown')}

Classify this threat and provide risk assessment:"""

    def _create_threat_classification_completion(self, row: pd.Series) -> str:
        """Create the expected completion for threat classification"""
        attack_type = row.get('Attack_Type', 'Unknown')
        severity = row.get('Severity_Level', 'Medium')
        action = row.get('Action_Taken', 'Monitor')
        
        return f"""**Threat Classification:** {attack_type}

**Risk Level:** {severity}

**Analysis:**
- Attack Vector: Network-based intrusion attempt
- Source Reputation: {self._assess_ip_reputation(row.get('Source_IP', ''))}
- Protocol Risk: {self._assess_protocol_risk(row.get('Protocol', ''))}
- Port Analysis: {self._assess_port_risk(row.get('Destination_Port', ''))}

**Recommended Action:** {action}

**IOCs Identified:**
- Source IP: {row.get('Source_IP', 'N/A')}
- Destination Port: {row.get('Destination_Port', 'N/A')}
- Attack Signature: {attack_type}

**Confidence Score:** {self._calculate_confidence_score(row)}%"""

    def _assess_ip_reputation(self, ip: str) -> str:
        """Assess IP reputation for training data"""
        if not ip or ip == 'unknown':
            return "Unknown - requires investigation"
        # Simple heuristic for training data
        if ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.'):
            return "Internal network - potentially compromised host"
        return "External IP - requires threat intelligence lookup"
    
    def _assess_protocol_risk(self, protocol: str) -> str:
        """Assess protocol risk level"""
        high_risk = ['TCP', 'UDP']
        if protocol in high_risk:
            return f"{protocol} - High risk protocol, commonly exploited"
        return f"{protocol} - Standard protocol, monitor for anomalies"
    
    def _assess_port_risk(self, port: str) -> str:
        """Assess destination port risk"""
        try:
            port_num = int(port)
            common_targets = {22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 21: 'FTP', 23: 'Telnet'}
            if port_num in common_targets:
                return f"Port {port} ({common_targets[port_num]}) - Common attack target"
            elif port_num < 1024:
                return f"Port {port} - Privileged port, high risk"
            else:
                return f"Port {port} - Non-standard port, investigate"
        except:
            return "Invalid port - data quality issue"
    
    def _calculate_confidence_score(self, row: pd.Series) -> int:
        """Calculate confidence score for the classification"""
        score = 70  # Base confidence
        if row.get('Attack_Type') != 'unknown':
            score += 15
        if row.get('Source_IP') != 'unknown':
            score += 10
        if row.get('Action_Taken') != 'unknown':
            score += 5
        return min(score, 95)

    async def prepare_log_parsing_data(self) -> List[TrainingExample]:
        """Create log parsing training examples"""
        log_examples = [
            {
                "log": "2024-01-15 10:30:45 [ERROR] Failed login attempt from 203.0.113.42 for user admin",
                "structured": {
                    "timestamp": "2024-01-15 10:30:45",
                    "level": "ERROR", 
                    "event": "failed_login",
                    "source_ip": "203.0.113.42",
                    "username": "admin",
                    "iocs": ["203.0.113.42"]
                }
            },
            {
                "log": "Firewall blocked connection to 185.220.101.42:443. DNS query for malware-c2.example.com detected",
                "structured": {
                    "event": "firewall_block",
                    "destination_ip": "185.220.101.42",
                    "destination_port": "443",
                    "dns_query": "malware-c2.example.com",
                    "iocs": ["185.220.101.42", "malware-c2.example.com"]
                }
            }
        ]
        
        examples = []
        for log_data in log_examples:
            prompt = f"""Parse the following cybersecurity log entry and extract structured information:

Log Entry: {log_data['log']}

Extract: timestamp, event type, IOCs, risk level, and recommended actions."""

            completion = f"""**Parsed Log Analysis:**

**Structured Data:**
```json
{json.dumps(log_data['structured'], indent=2)}
```

**Risk Assessment:**
- Event Type: {log_data['structured'].get('event', 'security_event')}
- Risk Level: High
- IOCs Found: {len(log_data['structured'].get('iocs', []))} indicators

**Recommended Actions:**
1. Block source IP immediately
2. Investigate user account security
3. Review related log entries
4. Update threat intelligence feeds

**Next Steps:**
- Correlate with other security events
- Check for lateral movement
- Verify user legitimacy"""

            examples.append(TrainingExample(
                prompt=prompt,
                completion=completion,
                category="log_parsing"
            ))
        
        return examples

    async def prepare_ioc_extraction_data(self) -> List[TrainingExample]:
        """Create IOC extraction training examples"""
        ioc_examples = [
            {
                "text": "Suspicious activity detected from IP 198.51.100.5 connecting to malware-command.example.com with hash d41d8cd98f00b204e9800998ecf8427e",
                "iocs": {
                    "ips": ["198.51.100.5"],
                    "domains": ["malware-command.example.com"], 
                    "hashes": ["d41d8cd98f00b204e9800998ecf8427e"]
                }
            },
            {
                "text": "Email from phishing@temp-mail.org containing bitcoin address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa and phone +1-555-0123",
                "iocs": {
                    "emails": ["phishing@temp-mail.org"],
                    "bitcoin_addresses": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
                    "phone_numbers": ["+1-555-0123"]
                }
            }
        ]
        
        examples = []
        for ioc_data in ioc_examples:
            prompt = f"""Extract all cybersecurity indicators of compromise (IOCs) from the following text:

Text: {ioc_data['text']}

Identify and categorize: IP addresses, domains, hashes, emails, URLs, bitcoin addresses, phone numbers."""

            ioc_list = []
            for category, items in ioc_data['iocs'].items():
                for item in items:
                    ioc_list.append(f"- {category.upper()}: {item}")

            completion = f"""**IOCs Extracted:**

{chr(10).join(ioc_list)}

**Risk Assessment:**
- Total IOCs: {sum(len(items) for items in ioc_data['iocs'].values())}
- Categories: {', '.join(ioc_data['iocs'].keys())}
- Threat Level: High

**Threat Intelligence Actions:**
1. Query VirusTotal for hash/domain reputation
2. Check AbuseIPDB for IP reputation  
3. Search Shodan for infrastructure details
4. Cross-reference with known threat feeds

**Detection Rules:**
- Block IP addresses immediately
- Add domains to DNS blacklist
- Create hash-based detection rules
- Monitor for similar IOC patterns"""

            examples.append(TrainingExample(
                prompt=prompt,
                completion=completion,
                category="ioc_extraction"
            ))
        
        return examples

    def convert_to_bedrock_format(self, examples: List[TrainingExample]) -> List[Dict[str, Any]]:
        """Convert training examples to Bedrock JSONL format"""
        bedrock_examples = []
        
        for example in examples:
            # Claude fine-tuning format
            bedrock_example = {
                "messages": [
                    {
                        "role": "user",
                        "content": example.prompt
                    },
                    {
                        "role": "assistant", 
                        "content": example.completion
                    }
                ]
            }
            bedrock_examples.append(bedrock_example)
        
        return bedrock_examples

    async def upload_training_data(self, examples: List[Dict[str, Any]], filename: str):
        """Upload training data to S3 in JSONL format"""
        # Convert to JSONL format
        jsonl_content = "\n".join(json.dumps(example) for example in examples)
        
        # Upload to S3
        try:
            self.s3_client.put_object(
                Bucket=self.s3_bucket,
                Key=f"training-data/{filename}",
                Body=jsonl_content.encode('utf-8'),
                ContentType='application/jsonl'
            )
            logger.info(f"Uploaded {len(examples)} examples to s3://{self.s3_bucket}/training-data/{filename}")
            return f"s3://{self.s3_bucket}/training-data/{filename}"
        except Exception as e:
            logger.error(f"Failed to upload training data: {e}")
            raise

    async def prepare_all_training_data(self, csv_path: str = None):
        """Prepare all training data for fine-tuning"""
        all_examples = []
        
        # Threat classification from existing dataset
        if csv_path and Path(csv_path).exists():
            threat_examples = await self.prepare_threat_classification_data(csv_path)
            all_examples.extend(threat_examples[:1000])  # Limit for initial training
        
        # Log parsing examples
        log_examples = await self.prepare_log_parsing_data()
        all_examples.extend(log_examples)
        
        # IOC extraction examples  
        ioc_examples = await self.prepare_ioc_extraction_data()
        all_examples.extend(ioc_examples)
        
        # Convert to Bedrock format
        bedrock_format = self.convert_to_bedrock_format(all_examples)
        
        # Split into train/validation
        split_idx = int(len(bedrock_format) * 0.8)
        train_data = bedrock_format[:split_idx]
        val_data = bedrock_format[split_idx:]
        
        # Upload to S3
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        train_uri = await self.upload_training_data(
            train_data, 
            f"cybershield_train_{timestamp}.jsonl"
        )
        
        val_uri = await self.upload_training_data(
            val_data,
            f"cybershield_validation_{timestamp}.jsonl"
        )
        
        logger.info(f"Training data prepared:")
        logger.info(f"  Train: {len(train_data)} examples at {train_uri}")
        logger.info(f"  Validation: {len(val_data)} examples at {val_uri}")
        
        return {
            "train_uri": train_uri,
            "validation_uri": val_uri,
            "train_count": len(train_data),
            "validation_count": len(val_data)
        }

# Usage example
async def main():
    """Example usage of the data preparation pipeline"""
    preparator = CyberShieldDataPreparator(
        s3_bucket="cybershield-dev-bedrock-training-nazqkk52"
    )
    
    # Prepare training data from existing cybersecurity dataset
    result = await preparator.prepare_all_training_data(
        csv_path="data/cybersecurity_attacks.csv"
    )
    
    print("Training data preparation complete:")
    print(f"Training examples: {result['train_count']}")
    print(f"Validation examples: {result['validation_count']}")
    print(f"Training data URI: {result['train_uri']}")
    print(f"Validation data URI: {result['validation_uri']}")

if __name__ == "__main__":
    asyncio.run(main())