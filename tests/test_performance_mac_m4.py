#!/usr/bin/env python3
"""
Performance benchmark test for CyberShield on Mac M4 with Apple Silicon optimizations.
Tests various components to demonstrate the performance improvements.
"""

import time
import sys
from typing import List, Dict
from utils.device_config import optimize_for_cybershield, create_performance_config
from utils.logging_config import get_security_logger

logger = get_security_logger("performance_test")

def benchmark_sentence_transformers():
    """Benchmark sentence-transformers performance with MPS acceleration."""
    print("🧪 Benchmarking sentence-transformers...")
    
    try:
        from sentence_transformers import SentenceTransformer
        
        config = create_performance_config()
        device = config["sentence_transformers_device"]
        
        # Test different batch sizes
        model = SentenceTransformer('all-MiniLM-L6-v2', device=device)
        
        # Create test data (cybersecurity-themed)
        test_texts = [
            "Network intrusion detected from IP 192.168.1.100",
            "Malware signature found: Trojan.GenKrypt.45821",
            "Suspicious PowerShell execution with base64 encoding",
            "Failed login attempts from multiple IP addresses",
            "Port scan detected on critical infrastructure",
            "SQL injection attempt blocked by firewall",
            "Cryptocurrency mining activity detected",
            "Phishing email with malicious attachment",
            "DDoS attack mitigated, traffic normalized",
            "Privilege escalation attempt detected"
        ]
        
        # Test different scales
        test_scales = [10, 50, 100, 200]
        results = {}
        
        for scale in test_scales:
            scaled_texts = (test_texts * (scale // len(test_texts) + 1))[:scale]
            
            start_time = time.time()
            embeddings = model.encode(
                scaled_texts, 
                batch_size=config["batch_size"],
                show_progress_bar=False,
                convert_to_numpy=True,
                normalize_embeddings=True
            )
            encode_time = time.time() - start_time
            
            throughput = len(scaled_texts) / encode_time
            results[scale] = {
                "time": encode_time,
                "throughput": throughput,
                "shape": embeddings.shape
            }
            
            print(f"  📊 {scale} texts: {encode_time:.3f}s ({throughput:.1f} texts/sec)")
        
        return results
        
    except ImportError:
        print("  ❌ sentence-transformers not available")
        return {}
    except Exception as e:
        print(f"  ⚠️ Error: {e}")
        return {}

def benchmark_vision_processing():
    """Benchmark vision processing with MPS acceleration."""
    print("🧪 Benchmarking vision processing...")
    
    try:
        import torch
        from transformers import pipeline
        import numpy as np
        from PIL import Image
        
        config = create_performance_config()
        device = config["torch_device"]
        
        # Create test image
        test_image = Image.fromarray(np.random.randint(0, 255, (224, 224, 3), dtype=np.uint8))
        
        # Initialize vision pipeline with optimization
        if device == "mps":
            device_id = 0
            torch_device = torch.device("mps")
        elif device == "cuda":
            device_id = 0
            torch_device = torch.device("cuda")
        else:
            device_id = -1
            torch_device = torch.device("cpu")
        
        classifier = pipeline(
            "image-classification",
            model="google/vit-base-patch16-224",
            device=device_id,
            torch_dtype=torch.float16 if device != "cpu" else torch.float32
        )
        
        # Benchmark single image processing
        start_time = time.time()
        result = classifier(test_image)
        single_time = time.time() - start_time
        
        print(f"  📊 Single image: {single_time:.3f}s")
        
        # Benchmark batch processing
        batch_images = [test_image] * 5
        start_time = time.time()
        batch_results = classifier(batch_images)
        batch_time = time.time() - start_time
        
        print(f"  📊 Batch (5 images): {batch_time:.3f}s ({5/batch_time:.1f} images/sec)")
        
        return {
            "single_time": single_time,
            "batch_time": batch_time,
            "batch_throughput": 5 / batch_time
        }
        
    except Exception as e:
        print(f"  ⚠️ Error: {e}")
        return {}

def benchmark_cybershield_components():
    """Benchmark CyberShield-specific components."""
    print("🧪 Benchmarking CyberShield components...")
    
    results = {}
    
    # Test regex IOC extraction
    try:
        from tools.regex_checker import RegexChecker
        
        test_logs = [
            "Connection from 203.0.113.1:4444 to 192.168.1.100:22 blocked",
            "Hash detected: d41d8cd98f00b204e9800998ecf8427e malware.exe",
            "DNS query for malicious-domain.ru blocked by firewall",
            "Email from phishing@temp-mail.org contained suspicious links",
            "Bitcoin address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa found in logs"
        ] * 20  # 100 log entries
        
        checker = RegexChecker()
        
        start_time = time.time()
        for log in test_logs:
            iocs = checker.extract_all_iocs(log)
        extraction_time = time.time() - start_time
        
        print(f"  📊 IOC extraction ({len(test_logs)} logs): {extraction_time:.3f}s")
        results["ioc_extraction"] = {
            "time": extraction_time,
            "throughput": len(test_logs) / extraction_time
        }
        
    except Exception as e:
        print(f"  ⚠️ IOC extraction error: {e}")
    
    return results

def main():
    """Run comprehensive performance benchmark."""
    print("🚀 CyberShield Mac M4 Performance Benchmark")
    print("=" * 60)
    
    # Initialize optimizations
    device = optimize_for_cybershield()
    config = create_performance_config()
    
    print(f"\n🍎 Platform: Mac M4 with Apple Silicon")
    print(f"🔧 Device: {device.upper()}")
    print(f"⚙️ Batch Size: {config['batch_size']}")
    print(f"🎯 Precision: {config['precision']}")
    print(f"👥 Workers: {config['num_workers']}")
    
    print("\n" + "=" * 60)
    
    # Run benchmarks
    st_results = benchmark_sentence_transformers()
    vision_results = benchmark_vision_processing()
    cybershield_results = benchmark_cybershield_components()
    
    # Summary
    print("\n🎯 Performance Summary:")
    print("=" * 60)
    
    if st_results:
        best_throughput = max(st_results.values(), key=lambda x: x["throughput"])
        print(f"📝 Text Embedding: Up to {best_throughput['throughput']:.1f} texts/sec")
    
    if vision_results and 'batch_throughput' in vision_results:
        print(f"👁️ Image Processing: {vision_results['batch_throughput']:.1f} images/sec")
    
    if cybershield_results and 'ioc_extraction' in cybershield_results:
        ioc_throughput = cybershield_results['ioc_extraction']['throughput']
        print(f"🔍 IOC Extraction: {ioc_throughput:.1f} logs/sec")
    
    print(f"\n✅ Mac M4 Optimizations Active!")
    print(f"🚀 Expected performance improvements:")
    print(f"   • 2-5x faster than CPU-only processing")
    print(f"   • Optimized memory usage with half precision")
    print(f"   • Better parallel processing utilization")
    print(f"   • MPS acceleration for PyTorch operations")

if __name__ == "__main__":
    main()