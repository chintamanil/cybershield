#!/usr/bin/env python3
"""
Interactive Milvus Data Viewer
"""

import sys
import os
import pandas as pd
from typing import List, Dict

# Add the project root to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from pymilvus import connections, Collection, utility
    PYMILVUS_AVAILABLE = True
except ImportError:
    PYMILVUS_AVAILABLE = False
    print("pymilvus not available. Install with: pip install pymilvus")

class InteractiveMilvusViewer:
    def __init__(self, collection_name: str = "cybersecurity_attacks"):
        self.collection_name = collection_name
        self.collection = None

    def connect(self):
        """Connect to Milvus"""
        if not PYMILVUS_AVAILABLE:
            print("❌ pymilvus not available")
            return False

        try:
            connections.connect("default", host="localhost", port="19530")
            print("✅ Connected to Milvus")
            return True
        except Exception as e:
            print(f"❌ Failed to connect to Milvus: {e}")
            return False

    def load_collection(self):
        """Load the collection"""
        try:
            if not utility.has_collection(self.collection_name):
                print(f"❌ Collection '{self.collection_name}' not found")
                return False

            self.collection = Collection(self.collection_name)
            self.collection.load()
            print(f"✅ Loaded collection: {self.collection_name}")
            return True
        except Exception as e:
            print(f"❌ Failed to load collection: {e}")
            return False

    def get_total_count(self):
        """Get total number of records"""
        try:
            # Use a simple query to get count
            results = self.collection.query(
                expr="",
                output_fields=["id"],
                limit=1
            )
            # Get actual count by querying all IDs
            all_ids = self.collection.query(
                expr="",
                output_fields=["id"]
            )
            return len(all_ids)
        except Exception as e:
            print(f"❌ Failed to get count: {e}")
            return 0

    def query_by_attack_type(self, attack_type: str, limit: int = 10):
        """Query records by attack type"""
        try:
            results = self.collection.query(
                expr=f"attack_type == '{attack_type}'",
                output_fields=[
                    "id", "timestamp", "source_ip", "dest_ip", "protocol",
                    "attack_type", "severity_level", "full_context"
                ],
                limit=limit
            )
            return results
        except Exception as e:
            print(f"❌ Failed to query by attack type: {e}")
            return []

    def query_by_severity(self, severity: str, limit: int = 10):
        """Query records by severity level"""
        try:
            results = self.collection.query(
                expr=f"severity_level == '{severity}'",
                output_fields=[
                    "id", "timestamp", "source_ip", "dest_ip", "protocol",
                    "attack_type", "severity_level", "full_context"
                ],
                limit=limit
            )
            return results
        except Exception as e:
            print(f"❌ Failed to query by severity: {e}")
            return []

    def query_by_protocol(self, protocol: str, limit: int = 10):
        """Query records by protocol"""
        try:
            results = self.collection.query(
                expr=f"protocol == '{protocol}'",
                output_fields=[
                    "id", "timestamp", "source_ip", "dest_ip", "protocol",
                    "attack_type", "severity_level", "full_context"
                ],
                limit=limit
            )
            return results
        except Exception as e:
            print(f"❌ Failed to query by protocol: {e}")
            return []

    def query_by_ip(self, ip: str, limit: int = 10):
        """Query records by IP address (source or destination)"""
        try:
            results = self.collection.query(
                expr=f"source_ip == '{ip}' or dest_ip == '{ip}'",
                output_fields=[
                    "id", "timestamp", "source_ip", "dest_ip", "protocol",
                    "attack_type", "severity_level", "full_context"
                ],
                limit=limit
            )
            return results
        except Exception as e:
            print(f"❌ Failed to query by IP: {e}")
            return []

    def get_attack_type_stats(self):
        """Get statistics by attack type"""
        try:
            # Get all records with attack_type field
            results = self.collection.query(
                expr="",
                output_fields=["attack_type"],
                limit=10000  # Get a large sample
            )

            if not results:
                return {}

            df = pd.DataFrame(results)
            return df['attack_type'].value_counts().to_dict()
        except Exception as e:
            print(f"❌ Failed to get attack type stats: {e}")
            return {}

    def get_severity_stats(self):
        """Get statistics by severity level"""
        try:
            results = self.collection.query(
                expr="",
                output_fields=["severity_level"],
                limit=10000
            )

            if not results:
                return {}

            df = pd.DataFrame(results)
            return df['severity_level'].value_counts().to_dict()
        except Exception as e:
            print(f"❌ Failed to get severity stats: {e}")
            return {}

    def display_results(self, results: List[Dict], title: str = "Query Results"):
        """Display query results in a formatted way"""
        if not results:
            print(f"❌ No results found for {title}")
            return

        print(f"\n📋 {title} ({len(results)} records):")
        print("=" * 80)

        for i, record in enumerate(results[:5]):  # Show first 5 records
            print(f"\n--- Record {i+1} ---")
            print(f"ID: {record['id']}")
            print(f"Timestamp: {record['timestamp']}")
            print(f"Source: {record['source_ip']} -> Dest: {record['dest_ip']}")
            print(f"Protocol: {record['protocol']}")
            print(f"Attack Type: {record['attack_type']}")
            print(f"Severity: {record['severity_level']}")
            print(f"Context: {record['full_context'][:100]}...")

        if len(results) > 5:
            print(f"\n... and {len(results) - 5} more records")

def main():
    """Interactive main function"""
    print("🛡️ CyberShield Interactive Milvus Data Viewer")
    print("=" * 60)

    viewer = InteractiveMilvusViewer()

    # Connect to Milvus
    if not viewer.connect():
        return

    # Load collection
    if not viewer.load_collection():
        return

    # Get total count
    total_count = viewer.get_total_count()
    print(f"\n📊 Total records in collection: {total_count}")

    while True:
        print(f"\n🔍 Available Options:")
        print("1. View attack type statistics")
        print("2. View severity level statistics")
        print("3. Query by attack type")
        print("4. Query by severity level")
        print("5. Query by protocol")
        print("6. Query by IP address")
        print("7. Export data to CSV")
        print("8. Exit")

        choice = input("\nEnter your choice (1-8): ").strip()

        if choice == "1":
            stats = viewer.get_attack_type_stats()
            print(f"\n📊 Attack Type Statistics:")
            for attack_type, count in stats.items():
                print(f"   {attack_type}: {count}")

        elif choice == "2":
            stats = viewer.get_severity_stats()
            print(f"\n📊 Severity Level Statistics:")
            for severity, count in stats.items():
                print(f"   {severity}: {count}")

        elif choice == "3":
            attack_type = input("Enter attack type (e.g., DDoS, Malware, Intrusion): ").strip()
            if attack_type:
                results = viewer.query_by_attack_type(attack_type)
                viewer.display_results(results, f"Records with attack type '{attack_type}'")

        elif choice == "4":
            severity = input("Enter severity level (High, Medium, Low): ").strip()
            if severity:
                results = viewer.query_by_severity(severity)
                viewer.display_results(results, f"Records with severity '{severity}'")

        elif choice == "5":
            protocol = input("Enter protocol (TCP, UDP, ICMP): ").strip()
            if protocol:
                results = viewer.query_by_protocol(protocol)
                viewer.display_results(results, f"Records with protocol '{protocol}'")

        elif choice == "6":
            ip = input("Enter IP address: ").strip()
            if ip:
                results = viewer.query_by_ip(ip)
                viewer.display_results(results, f"Records involving IP '{ip}'")

        elif choice == "7":
            limit = input("Enter number of records to export (default 1000): ").strip()
            try:
                limit = int(limit) if limit else 1000
                filename = f"milvus_export_{limit}_records.csv"

                results = viewer.collection.query(
                    expr="",
                    output_fields=[
                        "id", "timestamp", "source_ip", "dest_ip", "source_port",
                        "dest_port", "protocol", "attack_type", "attack_signature",
                        "severity_level", "action_taken", "anomaly_score",
                        "malware_indicators", "geo_location", "user_info",
                        "log_source", "full_context"
                    ],
                    limit=limit
                )

                if results:
                    df = pd.DataFrame(results)
                    df.to_csv(filename, index=False)
                    print(f"✅ Exported {len(df)} records to {filename}")
                else:
                    print("❌ No data to export")

            except ValueError:
                print("❌ Invalid number")

        elif choice == "8":
            print("👋 Goodbye!")
            break

        else:
            print("❌ Invalid choice. Please enter a number between 1-8.")

if __name__ == "__main__":
    main()