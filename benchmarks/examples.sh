#!/bin/bash
# Example benchmark workflows for SPHINCS+ STARK analysis

# Make sure we're in the right directory
cd "$(dirname "$0")/.."

echo "SPHINCS+ STARK Benchmark Examples"
echo "=================================="
echo ""

# Example 1: Quick benchmark (skip proof generation for fast testing)
echo "Example 1: Quick benchmark - build and execute only"
echo "---------------------------------------------------"
echo "Command: python benchmarks/benchmark.py --name quick_test --skip-proof"
echo ""

# Example 2: Full benchmark with default settings
echo "Example 2: Full benchmark with SHA2 hasher"
echo "------------------------------------------"
echo "Command: python benchmarks/benchmark.py --name full_sha2"
echo ""

# Example 3: Benchmark with specific features
echo "Example 3: Benchmark with BLAKE2s and sparse addressing"
echo "-------------------------------------------------------"
echo "Command: python benchmarks/benchmark.py --name blake_sparse --features blake_hash sparse_addr"
echo ""

# Example 4: Run multiple benchmarks from config
echo "Example 4: Run multiple benchmarks from configuration"
echo "-----------------------------------------------------"
echo "Command: python benchmarks/benchmark.py --config benchmarks/benchmark_config.json"
echo ""

# Example 5: Compare results
echo "Example 5: Compare benchmark results"
echo "------------------------------------"
echo "Command: python benchmarks/compare_results.py benchmarks/results/*.json"
echo ""

# Example 6: Custom output location
echo "Example 6: Save results to custom location"
echo "------------------------------------------"
echo "Command: python benchmarks/benchmark.py --name custom --output my_results.json"
echo ""

# Example 7: Different prover parameters
echo "Example 7: Test with different prover parameters"
echo "------------------------------------------------"
echo "Command: python benchmarks/benchmark.py --name pow20 --prover-params my_params.json"
echo ""

echo ""
echo "To run any example, copy the command and execute it."
echo "All results will be saved to benchmarks/results/ by default."
