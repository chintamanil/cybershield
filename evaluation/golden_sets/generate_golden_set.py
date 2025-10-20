"""
Generate golden dataset for retrieval evaluation.

Creates query-passage pairs from cybersecurity_attacks.csv with:
- 10 query categories
- 10-20 examples per category
- Expected passages and answers
- Attack type coverage
"""

import json
import random
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd

from utils.logging_config import get_security_logger

logger = get_security_logger('golden_set_generator')

# Define query categories and templates
QUERY_CATEGORIES = {
    'ip_reputation': {
        'templates': [
            'What attacks involved IP {ip}?',
            'Show me historical data for {ip}',
            'Has {ip} been seen in any attacks?',
            'Find all incidents with IP address {ip}',
            'Is {ip} associated with malicious activity?',
            'Analyze threat activity for {ip}',
            'Check IP reputation for {ip}',
            'Find security events involving {ip}',
        ],
        'count': 30,
    },
    'attack_type': {
        'templates': [
            'Find all {attack_type} attacks',
            'Show me {attack_type} incidents',
            'What {attack_type} activity has been detected?',
            'List {attack_type} attack patterns',
            'Analyze {attack_type} threats',
            'Search for {attack_type} security events',
            'What are common {attack_type} signatures?',
        ],
        'count': 25,
    },
    'severity': {
        'templates': [
            'Show {severity} severity attacks',
            'Find all {severity} priority incidents',
            'What are the {severity} severity threats?',
            'List {severity} risk events',
            'Analyze {severity} criticality attacks',
            'Search {severity} severity security incidents',
        ],
        'count': 20,
    },
    'protocol': {
        'templates': [
            'Find {protocol} protocol attacks',
            'Show {protocol} traffic anomalies',
            'What attacks use {protocol}?',
            'Analyze {protocol} protocol threats',
            'Search for {protocol} security events',
            'List {protocol} protocol incidents',
        ],
        'count': 15,
    },
    'port_scan': {
        'templates': [
            'Find attacks on port {port}',
            'Show traffic to destination port {port}',
            'What attacks targeted port {port}?',
            'Analyze port {port} activity',
        ],
        'count': 10,
    },
    'geo_location': {
        'templates': [
            'Find attacks from {location}',
            'Show incidents originating in {location}',
            'What threats come from {location}?',
        ],
        'count': 10,
    },
    'malware_ioc': {
        'templates': [
            'Find attacks with IoC detected',
            'Show malware indicators',
            'What attacks had malware IoCs?',
            'List incidents with indicators of compromise',
        ],
        'count': 10,
    },
    'attack_signature': {
        'templates': [
            'Find attacks matching {signature}',
            'Show incidents with {signature}',
            'What attacks use {signature}?',
        ],
        'count': 10,
    },
    'time_based': {
        'templates': [
            'Show attacks in {year}',
            'Find incidents from {month} {year}',
            'What happened in {time_period}?',
        ],
        'count': 10,
    },
    'combined': {
        'templates': [
            'Find {attack_type} attacks from IP {ip}',
            'Show {severity} {attack_type} incidents',
            'What {protocol} attacks had {severity} severity?',
            'Find {attack_type} with IoC from {location}',
        ],
        'count': 25,
    },
}


def load_attack_data(csv_path: str = 'data/cybersecurity_attacks.csv') -> pd.DataFrame:
    """Load cybersecurity attacks CSV"""
    df = pd.read_csv(csv_path)
    logger.info('attack_data_loaded', rows=len(df), columns=list(df.columns))
    return df


def generate_ip_reputation_queries(
    df: pd.DataFrame, count: int
) -> List[Dict[str, Any]]:
    """Generate IP reputation lookup queries"""
    queries = []
    templates = QUERY_CATEGORIES['ip_reputation']['templates']

    # Sample diverse IPs
    source_ips = df['Source IP Address'].dropna().unique()
    dest_ips = df['Destination IP Address'].dropna().unique()
    all_ips = list(set(list(source_ips) + list(dest_ips)))

    sampled_ips = random.sample(all_ips, min(count, len(all_ips)))

    for ip in sampled_ips:
        # Find all records with this IP
        relevant_records = df[
            (df['Source IP Address'] == ip) | (df['Destination IP Address'] == ip)
        ]

        if len(relevant_records) == 0:
            continue

        query_text = random.choice(templates).format(ip=ip)

        # Create passage IDs (using index as ID)
        relevant_passage_ids = [f'doc_{idx}' for idx in relevant_records.index]

        # Expected answer
        attack_types = relevant_records['Attack Type'].value_counts().to_dict()
        severity = (
            relevant_records['Severity Level'].mode()[0]
            if len(relevant_records) > 0
            else 'Unknown'
        )

        expected_answer = (
            f'IP {ip} appears in {len(relevant_records)} attack records. '
            f'Primary attack types: {", ".join([f"{k} ({v})" for k, v in list(attack_types.items())[:3]])}. '
            f'Most common severity: {severity}.'
        )

        queries.append(
            {
                'query': query_text,
                'category': 'ip_reputation',
                'relevant_passages': relevant_passage_ids,
                'expected_answer': expected_answer,
                'metadata': {
                    'ip': ip,
                    'attack_count': len(relevant_records),
                    'attack_types': list(attack_types.keys()),
                },
            }
        )

    logger.info('ip_reputation_queries_generated', count=len(queries))
    return queries


def generate_attack_type_queries(df: pd.DataFrame, count: int) -> List[Dict[str, Any]]:
    """Generate attack type queries"""
    queries = []
    templates = QUERY_CATEGORIES['attack_type']['templates']

    attack_types = df['Attack Type'].dropna().unique()

    for attack_type in attack_types:
        # Find all records with this attack type
        relevant_records = df[df['Attack Type'] == attack_type]

        if len(relevant_records) == 0:
            continue

        # Generate multiple queries for each attack type
        num_queries = min(3, count // len(attack_types) + 1)

        for _ in range(num_queries):
            query_text = random.choice(templates).format(attack_type=attack_type)

            # Sample subset of relevant passages (simulate realistic recall)
            sample_size = min(50, len(relevant_records))
            sampled_records = relevant_records.sample(n=sample_size)
            relevant_passage_ids = [f'doc_{idx}' for idx in sampled_records.index]

            # Expected answer
            severity_counts = sampled_records['Severity Level'].value_counts().to_dict()
            signatures = sampled_records['Attack Signature'].unique()

            expected_answer = (
                f'Found {len(sampled_records)} {attack_type} attacks. '
                f'Severity distribution: {severity_counts}. '
                f'Signatures: {", ".join(signatures[:3])}.'
            )

            queries.append(
                {
                    'query': query_text,
                    'category': 'attack_type',
                    'relevant_passages': relevant_passage_ids,
                    'expected_answer': expected_answer,
                    'metadata': {
                        'attack_type': attack_type,
                        'total_count': len(relevant_records),
                        'sampled_count': len(sampled_records),
                    },
                }
            )

            if len(queries) >= count:
                break

        if len(queries) >= count:
            break

    logger.info('attack_type_queries_generated', count=len(queries))
    return queries[:count]


def generate_severity_queries(df: pd.DataFrame, count: int) -> List[Dict[str, Any]]:
    """Generate severity-based queries"""
    queries = []
    templates = QUERY_CATEGORIES['severity']['templates']

    severities = df['Severity Level'].dropna().unique()

    for severity in severities:
        relevant_records = df[df['Severity Level'] == severity]

        if len(relevant_records) == 0:
            continue

        num_queries = min(4, count // len(severities) + 1)

        for _ in range(num_queries):
            query_text = random.choice(templates).format(severity=severity)

            sample_size = min(50, len(relevant_records))
            sampled_records = relevant_records.sample(n=sample_size)
            relevant_passage_ids = [f'doc_{idx}' for idx in sampled_records.index]

            attack_types = sampled_records['Attack Type'].value_counts().to_dict()

            expected_answer = (
                f'Found {len(sampled_records)} {severity} severity incidents. '
                f'Attack types: {", ".join([f"{k} ({v})" for k, v in list(attack_types.items())[:3]])}.'
            )

            queries.append(
                {
                    'query': query_text,
                    'category': 'severity',
                    'relevant_passages': relevant_passage_ids,
                    'expected_answer': expected_answer,
                    'metadata': {
                        'severity': severity,
                        'total_count': len(relevant_records),
                    },
                }
            )

    logger.info('severity_queries_generated', count=len(queries))
    return queries[:count]


def generate_protocol_queries(df: pd.DataFrame, count: int) -> List[Dict[str, Any]]:
    """Generate protocol-based queries"""
    queries = []
    templates = QUERY_CATEGORIES['protocol']['templates']

    protocols = df['Protocol'].dropna().unique()

    for protocol in protocols:
        relevant_records = df[df['Protocol'] == protocol]

        if len(relevant_records) == 0:
            continue

        query_text = random.choice(templates).format(protocol=protocol)

        sample_size = min(30, len(relevant_records))
        sampled_records = relevant_records.sample(n=sample_size)
        relevant_passage_ids = [f'doc_{idx}' for idx in sampled_records.index]

        attack_types = sampled_records['Attack Type'].value_counts().to_dict()

        expected_answer = (
            f'Found {len(sampled_records)} {protocol} protocol attacks. '
            f'Types: {", ".join(list(attack_types.keys())[:3])}.'
        )

        queries.append(
            {
                'query': query_text,
                'category': 'protocol',
                'relevant_passages': relevant_passage_ids,
                'expected_answer': expected_answer,
                'metadata': {'protocol': protocol},
            }
        )

    logger.info('protocol_queries_generated', count=len(queries))
    return queries[:count]


def generate_port_scan_queries(df: pd.DataFrame, count: int) -> List[Dict[str, Any]]:
    """Generate port-based queries"""
    queries = []
    templates = QUERY_CATEGORIES['port_scan']['templates']

    # Get common destination ports
    common_ports = df['Destination Port'].value_counts().head(15).index.tolist()

    for port in common_ports:
        relevant_records = df[df['Destination Port'] == port]

        if len(relevant_records) == 0:
            continue

        query_text = random.choice(templates).format(port=port)

        sample_size = min(30, len(relevant_records))
        sampled_records = relevant_records.sample(n=sample_size)
        relevant_passage_ids = [f'doc_{idx}' for idx in sampled_records.index]

        attack_types = sampled_records['Attack Type'].value_counts().to_dict()

        expected_answer = (
            f'Found {len(sampled_records)} attacks on port {port}. '
            f'Types: {", ".join(list(attack_types.keys())[:3])}.'
        )

        queries.append(
            {
                'query': query_text,
                'category': 'port_scan',
                'relevant_passages': relevant_passage_ids,
                'expected_answer': expected_answer,
                'metadata': {'port': port},
            }
        )

    logger.info('port_scan_queries_generated', count=len(queries))
    return queries[:count]


def generate_geo_location_queries(df: pd.DataFrame, count: int) -> List[Dict[str, Any]]:
    """Generate geo-location based queries"""
    queries = []
    templates = QUERY_CATEGORIES['geo_location']['templates']

    # Get unique geo-locations
    locations = df['Geo-location Data'].dropna().unique()

    sampled_locations = random.sample(list(locations), min(count, len(locations)))

    for location in sampled_locations:
        relevant_records = df[df['Geo-location Data'] == location]

        if len(relevant_records) == 0:
            continue

        query_text = random.choice(templates).format(location=location)

        sample_size = min(30, len(relevant_records))
        sampled_records = relevant_records.sample(n=sample_size)
        relevant_passage_ids = [f'doc_{idx}' for idx in sampled_records.index]

        attack_types = sampled_records['Attack Type'].value_counts().to_dict()

        expected_answer = (
            f'Found {len(sampled_records)} attacks from {location}. '
            f'Types: {", ".join(list(attack_types.keys())[:3])}.'
        )

        queries.append(
            {
                'query': query_text,
                'category': 'geo_location',
                'relevant_passages': relevant_passage_ids,
                'expected_answer': expected_answer,
                'metadata': {'location': location},
            }
        )

    logger.info('geo_location_queries_generated', count=len(queries))
    return queries


def generate_malware_ioc_queries(df: pd.DataFrame, count: int) -> List[Dict[str, Any]]:
    """Generate malware IoC queries"""
    queries = []
    templates = QUERY_CATEGORIES['malware_ioc']['templates']

    # Find records with IoC detected
    ioc_records = df[
        df['Malware Indicators'].notna() & (df['Malware Indicators'] != '')
    ]

    for i in range(count):
        query_text = templates[i % len(templates)]

        sample_size = min(50, len(ioc_records))
        sampled_records = ioc_records.sample(n=sample_size)
        relevant_passage_ids = [f'doc_{idx}' for idx in sampled_records.index]

        attack_types = sampled_records['Attack Type'].value_counts().to_dict()
        severity_counts = sampled_records['Severity Level'].value_counts().to_dict()

        expected_answer = (
            f'Found {len(sampled_records)} attacks with malware indicators. '
            f'Types: {", ".join(list(attack_types.keys())[:3])}. '
            f'Severity: {severity_counts}.'
        )

        queries.append(
            {
                'query': query_text,
                'category': 'malware_ioc',
                'relevant_passages': relevant_passage_ids,
                'expected_answer': expected_answer,
                'metadata': {'has_ioc': True},
            }
        )

    logger.info('malware_ioc_queries_generated', count=len(queries))
    return queries


def generate_attack_signature_queries(
    df: pd.DataFrame, count: int
) -> List[Dict[str, Any]]:
    """Generate attack signature queries"""
    queries = []
    templates = QUERY_CATEGORIES['attack_signature']['templates']

    signatures = df['Attack Signature'].dropna().unique()

    for signature in signatures:
        relevant_records = df[df['Attack Signature'] == signature]

        if len(relevant_records) == 0:
            continue

        # Generate multiple queries for each signature
        num_queries = min(5, count // len(signatures) + 1)

        for _ in range(num_queries):
            query_text = random.choice(templates).format(signature=signature)

            sample_size = min(50, len(relevant_records))
            sampled_records = relevant_records.sample(n=sample_size)
            relevant_passage_ids = [f'doc_{idx}' for idx in sampled_records.index]

            attack_types = sampled_records['Attack Type'].value_counts().to_dict()

            expected_answer = (
                f'Found {len(sampled_records)} attacks with {signature}. '
                f'Types: {", ".join(list(attack_types.keys())[:3])}.'
            )

            queries.append(
                {
                    'query': query_text,
                    'category': 'attack_signature',
                    'relevant_passages': relevant_passage_ids,
                    'expected_answer': expected_answer,
                    'metadata': {'signature': signature},
                }
            )

    logger.info('attack_signature_queries_generated', count=len(queries))
    return queries[:count]


def generate_combined_queries(df: pd.DataFrame, count: int) -> List[Dict[str, Any]]:
    """Generate complex multi-criteria queries"""
    queries = []
    templates = QUERY_CATEGORIES['combined']['templates']

    attack_types = df['Attack Type'].dropna().unique()
    severities = df['Severity Level'].dropna().unique()
    protocols = df['Protocol'].dropna().unique()

    # Sample IPs
    all_ips = list(df['Source IP Address'].dropna().unique())

    for _ in range(count):
        template = random.choice(templates)

        # Determine which variables are needed
        if '{attack_type}' in template and '{ip}' in template:
            attack_type = random.choice(attack_types)
            ip = random.choice(all_ips)
            query_text = template.format(attack_type=attack_type, ip=ip)

            relevant_records = df[
                (df['Attack Type'] == attack_type)
                & (
                    (df['Source IP Address'] == ip)
                    | (df['Destination IP Address'] == ip)
                )
            ]

        elif '{severity}' in template and '{attack_type}' in template:
            severity = random.choice(severities)
            attack_type = random.choice(attack_types)
            query_text = template.format(severity=severity, attack_type=attack_type)

            relevant_records = df[
                (df['Severity Level'] == severity) & (df['Attack Type'] == attack_type)
            ]

        elif '{protocol}' in template and '{severity}' in template:
            protocol = random.choice(protocols)
            severity = random.choice(severities)
            query_text = template.format(protocol=protocol, severity=severity)

            relevant_records = df[
                (df['Protocol'] == protocol) & (df['Severity Level'] == severity)
            ]

        else:
            continue

        if len(relevant_records) == 0:
            continue

        relevant_passage_ids = [f'doc_{idx}' for idx in relevant_records.index]

        expected_answer = f'Found {len(relevant_records)} matching attacks.'

        queries.append(
            {
                'query': query_text,
                'category': 'combined',
                'relevant_passages': relevant_passage_ids,
                'expected_answer': expected_answer,
                'metadata': {'query_type': 'multi_criteria'},
            }
        )

    logger.info('combined_queries_generated', count=len(queries))
    return queries[:count]


def generate_golden_dataset(
    csv_path: str = 'data/cybersecurity_attacks.csv',
    output_path: str = 'evaluation/golden_sets/threat_intel_queries.jsonl',
) -> None:
    """
    Generate complete golden dataset with all query categories.

    Args:
        csv_path: Path to cybersecurity attacks CSV
        output_path: Output JSONL file path
    """
    logger.info('golden_dataset_generation_started')

    # Load data
    df = load_attack_data(csv_path)

    # Generate queries by category
    all_queries = []

    all_queries.extend(
        generate_ip_reputation_queries(df, QUERY_CATEGORIES['ip_reputation']['count'])
    )
    all_queries.extend(
        generate_attack_type_queries(df, QUERY_CATEGORIES['attack_type']['count'])
    )
    all_queries.extend(
        generate_severity_queries(df, QUERY_CATEGORIES['severity']['count'])
    )
    all_queries.extend(
        generate_protocol_queries(df, QUERY_CATEGORIES['protocol']['count'])
    )
    all_queries.extend(
        generate_port_scan_queries(df, QUERY_CATEGORIES['port_scan']['count'])
    )
    all_queries.extend(
        generate_geo_location_queries(df, QUERY_CATEGORIES['geo_location']['count'])
    )
    all_queries.extend(
        generate_malware_ioc_queries(df, QUERY_CATEGORIES['malware_ioc']['count'])
    )
    all_queries.extend(
        generate_attack_signature_queries(
            df, QUERY_CATEGORIES['attack_signature']['count']
        )
    )
    all_queries.extend(
        generate_combined_queries(df, QUERY_CATEGORIES['combined']['count'])
    )

    # Shuffle for variety
    random.shuffle(all_queries)

    # Write to JSONL
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, 'w') as f:
        for query in all_queries:
            f.write(json.dumps(query) + '\n')

    # Generate stats
    category_counts = {}
    for query in all_queries:
        category = query['category']
        category_counts[category] = category_counts.get(category, 0) + 1

    logger.info(
        'golden_dataset_generated',
        total_queries=len(all_queries),
        output_path=output_path,
        categories=category_counts,
    )

    # Print summary
    print(f'\n{"=" * 60}')
    print(f'Golden Dataset Generated: {output_path}')
    print(f'{"=" * 60}')
    print(f'Total Queries: {len(all_queries)}')
    print(f'\nCategory Breakdown:')
    for category, count in sorted(category_counts.items()):
        print(f'  {category:20s}: {count:3d} queries')
    print(f'{"=" * 60}\n')


if __name__ == '__main__':
    # Set random seed for reproducibility
    random.seed(42)

    generate_golden_dataset()
