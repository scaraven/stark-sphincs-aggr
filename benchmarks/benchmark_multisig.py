#!/usr/bin/env python3
"""
Multi-Signature Aggregation Benchmark Suite

This script benchmarks SPHINCS+ BTC with multiple signatures by:
- Generating N signatures with varied RNG seeds
- Measuring generation time, execution time, and proof time
- Tracking per-signature and aggregate metrics
"""

import argparse
import json
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import sys


class MultiSigBenchmarkRunner:
    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root
        self.sphincs_package = workspace_root / "packages" / "sphincs-btc"
        self.target_dir = workspace_root / "target"
        self.results_dir = workspace_root / "benchmarks" / "results"
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.temp_args_dir = self.results_dir / "temp_args"
        self.temp_args_dir.mkdir(parents=True, exist_ok=True)

    def generate_multi_sig_args(self, num_sigs: int, seed: int, message_prefix: str = "test") -> Dict[str, Any]:
        """Generate multi-signature test vectors."""
        print(f"\n{'='*60}")
        print(f"Generating {num_sigs} signature(s) with seed {seed}...")
        print(f"{'='*60}")
        
        args_file = self.temp_args_dir / f"multisig_n{num_sigs}_seed{seed}.json"
        
        cmd = [
            "python3",
            str(self.sphincs_package / "scripts" / "generate_args.py"),
            "--num-signatures", str(num_sigs),
            "--seed", str(seed),
            "--message-prefix", message_prefix
        ]
        
        start_time = time.time()
        result = subprocess.run(
            cmd,
            cwd=self.workspace_root,
            capture_output=True,
            text=True
        )
        gen_time = time.time() - start_time
        
        if result.returncode != 0:
            print(f"Generation failed: {result.stderr}")
            return {
                "success": False,
                "error": result.stderr,
                "generation_time": gen_time
            }
        
        # Save generated args to file
        with open(args_file, 'w') as f:
            f.write(result.stdout)
        
        print(f"✓ Generated {num_sigs} signature(s) in {gen_time:.2f}s")
        print(f"✓ Saved to {args_file}")
        
        return {
            "success": True,
            "generation_time": gen_time,
            "args_file": str(args_file),
            "num_signatures": num_sigs,
            "seed": seed,
            "stderr": result.stderr
        }

    def build_sphincs_btc(self) -> Dict[str, Any]:
        """Build SPHINCS+ BTC package."""
        print(f"\n{'='*60}")
        print("Building sphincs-btc package...")
        print(f"{'='*60}")
        
        cmd = ["scarb", "--profile", "release", "build", "--package", "sphincs_btc"]
        
        start_time = time.time()
        result = subprocess.run(
            cmd,
            cwd=self.workspace_root,
            capture_output=True,
            text=True
        )
        build_time = time.time() - start_time
        
        if result.returncode != 0:
            print(f"Build failed: {result.stderr}")
            return {"success": False, "error": result.stderr}
        
        print(f"✓ Build completed in {build_time:.2f}s")
        
        return {
            "success": True,
            "build_time": build_time,
            "stdout": result.stdout,
            "stderr": result.stderr
        }

    def execute_program(self, args_file: str) -> Dict[str, Any]:
        """Execute Cairo program with multi-sig args."""
        print(f"\n{'='*60}")
        print("Executing sphincs-btc program...")
        print(f"{'='*60}")
        
        cmd = [
            "scarb", "--profile", "release", "execute",
            "--no-build",
            "--package", "sphincs_btc",
            "--print-resource-usage",
            "--arguments-file", args_file
        ]
        
        start_time = time.time()
        result = subprocess.run(
            cmd,
            cwd=self.workspace_root,
            capture_output=True,
            text=True
        )
        execution_time = time.time() - start_time
        
        if result.returncode != 0:
            print(f"Execution failed: {result.stderr}")
            return {"success": False, "error": result.stderr}
        
        print(f"✓ Execution completed in {execution_time:.2f}s")
        
        # Parse resource usage
        resource_usage = self._parse_resource_usage(result.stdout)
        
        return {
            "success": True,
            "execution_time": execution_time,
            "resource_usage": resource_usage,
            "stdout": result.stdout,
            "stderr": result.stderr
        }

    def _parse_resource_usage(self, output: str) -> Dict[str, int]:
        """Parse Cairo resource usage from execution output."""
        import re
        resources = {}
        
        patterns = [
            (r"n_steps:\s*(\d+)", "n_steps"),
            (r"n_memory_holes:\s*(\d+)", "n_memory_holes"),
            (r"Steps:\s*(\d+)", "steps"),
            (r"Memory holes:\s*(\d+)", "memory_holes"),
        ]
        
        for pattern, key in patterns:
            match = re.search(pattern, output)
            if match:
                resources[key] = int(match.group(1))
        
        return resources

    def run_benchmark(
        self,
        num_sigs: int,
        seed: int,
        message_prefix: str = "test"
    ) -> Dict[str, Any]:
        """Run a complete multi-sig benchmark."""
        print(f"\n{'#'*60}")
        print(f"# Multi-Sig Benchmark")
        print(f"# Signatures: {num_sigs}")
        print(f"# Seed: {seed}")
        print(f"# Timestamp: {datetime.now().isoformat()}")
        print(f"{'#'*60}")
        
        benchmark_result = {
            "timestamp": datetime.now().isoformat(),
            "num_signatures": num_sigs,
            "seed": seed,
            "message_prefix": message_prefix,
        }
        
        # Step 1: Generate signatures
        gen_metrics = self.generate_multi_sig_args(num_sigs, seed, message_prefix)
        benchmark_result["generation"] = gen_metrics
        
        if not gen_metrics["success"]:
            return benchmark_result
        
        # Step 2: Build (once)
        build_metrics = self.build_sphincs_btc()
        benchmark_result["build"] = build_metrics
        
        if not build_metrics["success"]:
            return benchmark_result
        
        # Step 3: Execute
        exec_metrics = self.execute_program(gen_metrics["args_file"])
        benchmark_result["execution"] = exec_metrics
        
        # Calculate totals
        total_time = (
            gen_metrics["generation_time"] +
            build_metrics["build_time"] +
            exec_metrics.get("execution_time", 0)
        )
        benchmark_result["total_time"] = total_time
        
        # Calculate per-signature metrics
        if exec_metrics["success"] and num_sigs > 0:
            resource_usage = exec_metrics["resource_usage"]
            steps = resource_usage.get("n_steps", resource_usage.get("steps", 0))
            if steps > 0:
                benchmark_result["per_signature_steps"] = steps / num_sigs
            benchmark_result["per_signature_time"] = exec_metrics["execution_time"] / num_sigs
        
        print(f"\n{'='*60}")
        print(f"Benchmark completed!")
        print(f"Total time: {total_time:.2f}s")
        if "per_signature_steps" in benchmark_result:
            print(f"Avg steps per signature: {benchmark_result['per_signature_steps']:,.0f}")
        print(f"{'='*60}\n")
        
        return benchmark_result

    def run_sweep(
        self,
        sig_counts: int,
        seed: int,
        message_prefix: str = "test"
    ) -> Dict[str, Any]:
        """Run benchmarks for multiple signature counts and seeds."""
        result = self.run_benchmark(sig_counts, seed, message_prefix)
        return result

    def save_results(self, results: List[Dict[str, Any]], output_file: str = None):
        """Save benchmark results to JSON file."""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.results_dir / f"multisig_benchmark_{timestamp}.json"
        else:
            output_file = Path(output_file)
        
        with open(output_file, 'w') as f:
            json.dump({"benchmarks": results}, f, indent=2)
        
        print(f"Results saved to: {output_file}")
        
        # Save human-readable summary
        summary_file = output_file.with_suffix('.txt')
        self._save_summary(results, summary_file)
        print(f"Summary saved to: {summary_file}")

    def _save_summary(self, results: List[Dict[str, Any]], output_file: Path):
        """Save human-readable summary."""
        with open(output_file, 'w') as f:
            f.write("SPHINCS+ BTC Multi-Signature Benchmark Results\n")
            f.write(f"{'='*60}\n\n")
            
            for i, result in enumerate(results):
                f.write(f"Benchmark {i+1}\n")
                f.write(f"{'-'*60}\n")
                f.write(f"Signatures: {result['num_signatures']}\n")
                f.write(f"Seed: {result['seed']}\n")
                f.write(f"Timestamp: {result['timestamp']}\n\n")
                
                if result['generation']['success']:
                    f.write(f"Generation Time: {result['generation']['generation_time']:.2f}s\n")
                
                if result['build']['success']:
                    f.write(f"Build Time: {result['build']['build_time']:.2f}s\n")
                
                if 'execution' in result and result['execution']['success']:
                    f.write(f"Execution Time: {result['execution']['execution_time']:.2f}s\n")
                    
                    res = result['execution']['resource_usage']
                    steps = res.get('n_steps', res.get('steps', 0))
                    if steps > 0:
                        f.write(f"Cairo Steps: {steps:,}\n")
                        f.write(f"Steps per Signature: {result.get('per_signature_steps', 0):,.0f}\n")
                
                f.write(f"Total Time: {result['total_time']:.2f}s\n")
                f.write(f"\n")


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark SPHINCS+ BTC with multiple signatures"
    )
    parser.add_argument(
        '--num-signatures', '-n',
        type=int,
        default=1,
        help='Number of signatures to benchmark'
    )
    parser.add_argument(
        '--seeds',
        type=int,
        default=0,
        help='RNG seed to test (default: 0)'
    )
    parser.add_argument(
        '--message-prefix',
        default='test',
        help='Prefix for generated messages (default: "test")'
    )
    parser.add_argument(
        '--output', '-o',
        help='Output file for results (default: auto-generated)'
    )
    
    args = parser.parse_args()
    
    # Find workspace root
    workspace_root = Path(__file__).parent.parent
    
    runner = MultiSigBenchmarkRunner(workspace_root)
    
    # Run benchmark sweep
    results = runner.run_sweep(
        sig_counts=args.num_signatures,
        seeds=args.seeds,
        message_prefix=args.message_prefix
    )
    
    # Save results
    runner.save_results(results, args.output)


if __name__ == "__main__":
    main()
