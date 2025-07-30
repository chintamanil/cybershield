"""
Device configuration for optimal performance on Apple Silicon and other platforms.
Automatically detects and configures the best available compute device.
"""

import os
import sys
from typing import Optional
import logging

def get_optimal_device() -> str:
    """
    Detect and return the optimal compute device for the current system.
    
    Returns:
        str: Device identifier ('mps', 'cuda', or 'cpu')
    """
    try:
        import torch
        
        # Check for Apple Silicon MPS (Metal Performance Shaders)
        if torch.backends.mps.is_available() and torch.backends.mps.is_built():
            print("🚀 Apple Silicon MPS acceleration detected and enabled")
            return "mps"
        
        # Check for NVIDIA CUDA
        elif torch.cuda.is_available():
            print(f"🚀 CUDA acceleration detected: {torch.cuda.get_device_name()}")
            return "cuda"
        
        # Fallback to CPU
        else:
            print("💻 Using CPU computation (no GPU acceleration available)")
            return "cpu"
            
    except ImportError:
        print("⚠️ PyTorch not available, defaulting to CPU")
        return "cpu"

def configure_torch_settings():
    """Configure PyTorch settings for optimal performance."""
    try:
        import torch
        
        # Set number of threads for CPU operations
        if hasattr(torch, 'set_num_threads'):
            # Use all available cores on Apple Silicon
            num_threads = os.cpu_count() or 4
            torch.set_num_threads(num_threads)
            print(f"🔧 PyTorch configured to use {num_threads} CPU threads")
        
        # Enable optimizations
        if hasattr(torch.backends, 'cudnn'):
            torch.backends.cudnn.benchmark = True
            torch.backends.cudnn.enabled = True
        
        # Apple Silicon specific optimizations
        if sys.platform == "darwin" and torch.backends.mps.is_available():
            # Enable MPS fallback to CPU for unsupported operations
            os.environ['PYTORCH_ENABLE_MPS_FALLBACK'] = '1'
            print("🍎 Apple Silicon MPS fallback enabled")
            
    except ImportError:
        pass

def get_sentence_transformers_device() -> str:
    """
    Get the optimal device configuration for sentence-transformers.
    
    Returns:
        str: Device identifier optimized for sentence-transformers
    """
    device = get_optimal_device()
    
    # sentence-transformers has some compatibility considerations with MPS
    if device == "mps":
        # Check if we can use MPS with sentence-transformers
        try:
            import sentence_transformers
            # For newer versions, MPS should work fine
            print("📝 sentence-transformers will use MPS acceleration")
            return "mps"
        except ImportError:
            print("📝 sentence-transformers not available, using CPU")
            return "cpu"
    
    return device

def optimize_for_cybershield():
    """
    Apply CyberShield-specific optimizations for the current platform.
    """
    print("🛡️ Optimizing CyberShield for current platform...")
    
    # Configure PyTorch
    configure_torch_settings()
    
    # Set environment variables for optimal performance
    if sys.platform == "darwin":  # macOS
        # Apple Silicon optimizations
        os.environ['ACCELERATE_USE_MPS'] = '1'  # For Hugging Face Accelerate
        os.environ['TRANSFORMERS_CACHE'] = os.path.expanduser('~/.cache/huggingface/transformers')
        print("🍎 Apple Silicon optimizations applied")
    
    # Memory optimizations
    os.environ['TOKENIZERS_PARALLELISM'] = 'false'  # Avoid tokenizer warnings
    
    # Get optimal device
    device = get_optimal_device()
    
    print(f"✅ CyberShield optimized for device: {device.upper()}")
    return device

def create_performance_config() -> dict:
    """
    Create a performance configuration dictionary for CyberShield components.
    
    Returns:
        dict: Configuration settings optimized for the current platform
    """
    device = get_optimal_device()
    
    config = {
        "device": device,
        "torch_device": device,
        "sentence_transformers_device": get_sentence_transformers_device(),
        "batch_size": {
            "mps": 32,      # Apple Silicon can handle larger batches
            "cuda": 64,     # NVIDIA GPUs typically handle even larger batches
            "cpu": 16       # Conservative batch size for CPU
        }.get(device, 16),
        "num_workers": {
            "mps": 4,       # Optimal for Apple Silicon
            "cuda": 8,      # More workers for CUDA
            "cpu": 2        # Conservative for CPU
        }.get(device, 2),
        "memory_optimization": device != "cpu",  # Enable for GPU devices
        "precision": {
            "mps": "float16",   # Apple Silicon supports half precision
            "cuda": "float16",  # CUDA supports half precision
            "cpu": "float32"    # CPU needs full precision
        }.get(device, "float32")
    }
    
    return config

# Initialize optimizations when module is imported
if __name__ != "__main__":
    try:
        optimize_for_cybershield()
    except Exception as e:
        print(f"⚠️ Could not apply optimizations: {e}")

if __name__ == "__main__":
    print("🧪 CyberShield Device Configuration Test")
    print("=" * 50)
    
    device = optimize_for_cybershield()
    config = create_performance_config()
    
    print("\n📊 Performance Configuration:")
    for key, value in config.items():
        print(f"  {key}: {value}")
    
    print(f"\n🎯 Recommended settings for {device.upper()}:")
    if device == "mps":
        print("  • Large language models will use Apple Silicon GPU")
        print("  • Vector embeddings will be accelerated")
        print("  • Image processing will use Metal acceleration")
        print("  • Expect 2-5x performance improvement over CPU")
    elif device == "cuda":
        print("  • NVIDIA GPU acceleration enabled")
        print("  • Expect significant performance improvements")
    else:
        print("  • CPU-only processing")
        print("  • Consider upgrading hardware for better performance")