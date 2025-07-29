#!/usr/bin/env python3
"""
Script to view and query data from Milvus collection
"""

import sys
import os
import pandas as pd

# Add the project root to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from pymilvus import connections, Collection, utility
    PYMILVUS_AVAILABLE = True
except ImportError:
    PYMILVUS_AVAILABLE = False
    print("pymilvus not available. Install with: pip install pymilvus")

class MilvusDataViewer:
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

    def get_collection_stats(self):
        """Get collection statistics"""
        if not self.collection:
            print("❌ Collection not loaded")
            return

        try:
            stats = self.collection.get_statistics()
            print(f"\n📊 Collection Statistics:")
            print(f"   Total records: {stats['row_count']}")
            print(f"   Collection name: {self.collection_name}")

            # Get schema info
            schema = self.collection.schema
            print(f"\n📋 Schema Fields:")
            for field in schema.fields:
                print(f"   - {field.name}: {field.dtype} (primary: {field.is_primary})")

        except Exception as e:
            print(f"❌ Failed to get stats: {e}")

    def query_sample_data(self, limit: int = 10):
        """Query sample data from the collection"""
        if not self.collection:
            print("❌ Collection not loaded")
            return

        try:
            print(f"\n🔍 Querying {limit} sample records...")

            # Query all fields
            results = self.collection.query(
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

            if not results:
                print("❌ No results found")
                return

            print(f"✅ Found {len(results)} records")

            # Convert to DataFrame for better display
            df = pd.DataFrame(results)

            # Display summary
            print(f"\n📋 Sample Data Summary:")
            print(f"   Attack types: {df['attack_type'].value_counts().head(3).to_dict()}")
            print(f"   Severity levels: {df['severity_level'].value_counts().to_dict()}")
            print(f"   Protocols: {df['protocol'].value_counts().head(3).to_dict()}")

            # Display detailed records
            print(f"\n📄 Detailed Records:")
            for i, record in enumerate(results[:5]):  # Show first 5 records
                print(f"\n--- Record {i+1} ---")
                print(f"ID: {record['id']}")
                print(f"Timestamp: {record['timestamp']}")
                print(f"Source IP: {record['source_ip']} -> Dest IP: {record['dest_ip']}")
                print(f"Protocol: {record['protocol']} ({record['source_port']} -> {record['dest_port']})")
                print(f"Attack Type: {record['attack_type']}")
                print(f"Severity: {record['severity_level']}")
                print(f"Signature: {record['attack_signature'][:100]}...")
                print(f"Context: {record['full_context'][:150]}...")

        except Exception as e:
            print(f"❌ Failed to query data: {e}")

    def search_similar(self, query_text: str, limit: int = 5):
        """Search for similar records using vector similarity"""
        if not self.collection:
            print("❌ Collection not loaded")
            return

        try:
            print(f"\n🔍 Searching for similar records to: '{query_text[:50]}...'")

            # For now, we'll use a simple text search since embeddings might not be available
            # In a real scenario, you'd create embeddings for the query_text
            results = self.collection.query(
                expr=f"full_context like '%{query_text[:20]}%'",
                output_fields=[
                    "id", "timestamp", "attack_type", "severity_level",
                    "source_ip", "dest_ip", "full_context"
                ],
                limit=limit
            )

            if not results:
                print("❌ No similar records found")
                return

            print(f"✅ Found {len(results)} similar records")

            for i, record in enumerate(results):
                print(f"\n--- Similar Record {i+1} ---")
                print(f"ID: {record['id']}")
                print(f"Attack Type: {record['attack_type']}")
                print(f"Severity: {record['severity_level']}")
                print(f"Source: {record['source_ip']} -> Dest: {record['dest_ip']}")
                print(f"Context: {record['full_context'][:100]}...")

        except Exception as e:
            print(f"❌ Failed to search: {e}")

    def export_to_csv(self, filename: str = "milvus_data_export.csv", limit: int = 1000):
        """Export data to CSV file"""
        if not self.collection:
            print("❌ Collection not loaded")
            return

        try:
            print(f"\n📤 Exporting {limit} records to {filename}...")

            results = self.collection.query(
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

            if not results:
                print("❌ No data to export")
                return

            df = pd.DataFrame(results)
            df.to_csv(filename, index=False)
            print(f"✅ Exported {len(df)} records to {filename}")

        except Exception as e:
            print(f"❌ Failed to export: {e}")

def main():
    """Main function to demonstrate Milvus data viewing"""
    print("🛡️ CyberShield Milvus Data Viewer")
    print("=" * 50)

    viewer = MilvusDataViewer()

    # Connect to Milvus
    if not viewer.connect():
        return

    # Load collection
    if not viewer.load_collection():
        return

    # Get collection statistics
    viewer.get_collection_stats()

    # Query sample data
    viewer.query_sample_data(limit=10)

    # Search for similar records
    viewer.search_similar("DDoS attack", limit=3)

    # Export data
    viewer.export_to_csv(limit=1000)

    print(f"\n🎉 Data viewing complete!")
    print(f"💡 You can also use the Milvus web interface at: http://localhost:9091")

if __name__ == "__main__":
    main()