#!/usr/bin/env python3
"""
SPHINCS+ STARK Benchmark Suite

This script benchmarks SPHINCS+ proof generation in STARKs by measuring:
- Number of constraints generated
- Prover time (total and breakdown)
- Final proof size
- Memory usage
"""

import argparse
import json
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
import re


class BenchmarkRunner:
    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root
        self.sphincs_package = workspace_root / "packages" / "sphincs-plus"
        self.target_dir = workspace_root / "target"
        self.results_dir = workspace_root / "benchmarks" / "results"
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def build_sphincs(self, package: str = "sphincs_plus", features: Optional[list[str]] = None) -> Dict[str, Any]:
        """Build SPHINCS+ package and extract compilation metrics."""
        print(f"\n{'='*60}")
        print(f"Building {package} package...")
        print(f"{'='*60}")
        
        cmd = ["scarb", "--profile", "release", "build", "--package", package]
        if features:
            cmd.extend(["--features", ",".join(features)])
        
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
        
        # Parse build output for metrics
        metrics = {
            "success": True,
            "build_time": build_time,
            "package": package,
            "features": features or [],
            "stdout": result.stdout,
            "stderr": result.stderr
        }
        
        return metrics

    def execute_program(self, args_file: str, package: str = "sphincs_plus") -> Dict[str, Any]:
        """Execute the Cairo program and extract resource usage."""
        print(f"\n{'='*60}")
        print(f"Executing {package} program...")
        print(f"{'='*60}")
        
        cmd = [
            "scarb", "--profile", "release", "execute",
            "--no-build",
            "--package", package,
            "--print-resource-usage",
        ]
        
        # Exclude arguments file for sphincs_poseidon package
        if package == "sphincs_poseidon":
            print("Note: Skipping arguments file for sphincs_poseidon package")
        else:
            cmd.extend(["--arguments-file", args_file])
        
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
        
        # Parse resource usage from output
        resource_usage = self._parse_resource_usage(result.stdout)
        
        # Extract the raw resource usage section from output
        resource_usage_raw = self._extract_resource_usage_raw(result.stdout)
        
        metrics = {
            "success": True,
            "execution_time": execution_time,
            "resource_usage": resource_usage,
            "resource_usage_raw": resource_usage_raw,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
        
        return metrics

    def _extract_resource_usage_raw(self, output: str) -> str:
        """Extract the raw resource usage section from Cairo execution output."""
        # Try to find resource usage section in the output
        lines = output.split('\n')
        resource_lines = []
        in_resource_section = False
        
        for line in lines:
            # Look for common resource usage indicators
            if any(keyword in line.lower() for keyword in ['steps', 'memory', 'builtin', 'resource', 'n_steps', 'range_check', 'pedersen', 'bitwise', 'ec_op', 'poseidon']):
                resource_lines.append(line)
                in_resource_section = True
            elif in_resource_section and line.strip() and not line.startswith(' '):
                # End of resource section if we hit a non-indented line
                if not any(keyword in line.lower() for keyword in ['steps', 'memory', 'builtin', 'resource']):
                    in_resource_section = False
            elif in_resource_section and line.strip():
                resource_lines.append(line)
        
        return '\n'.join(resource_lines) if resource_lines else output

    def _parse_resource_usage(self, output: str) -> Dict[str, int]:
        """Parse resource usage from Cairo execution output."""
        resources = {}
        
        # Look for resource usage patterns
        patterns = [
            (r"n_steps:\s*(\d+)", "n_steps"),
            (r"n_memory_holes:\s*(\d+)", "n_memory_holes"),
            (r"builtin_instance_counter:\s*{([^}]+)}", "builtins"),
            (r"Steps:\s*(\d+)", "steps"),
            (r"Memory holes:\s*(\d+)", "memory_holes"),
        ]
        
        for pattern, key in patterns:
            match = re.search(pattern, output)
            if match:
                if key == "builtins":
                    # Parse builtin counters
                    builtin_str = match.group(1)
                    builtins = {}
                    for builtin in builtin_str.split(','):
                        builtin = builtin.strip()
                        if ':' in builtin:
                            name, count = builtin.split(':')
                            name = name.strip().strip('"')
                            count = count.strip()
                            try:
                                builtins[name] = int(count)
                            except ValueError:
                                pass
                    resources["builtins"] = builtins
                else:
                    resources[key] = int(match.group(1))
        
        return resources

    def generate_proof(self, proving_task: str, prover_params: str) -> Dict[str, Any]:
        """Generate STARK proof and measure time and size."""
        print(f"\n{'='*60}")
        print("Generating STARK proof...")
        print(f"{'='*60}")
        
        proof_name = f"proof_{int(time.time())}"
        proof_path = self.target_dir / f"{proof_name}.proof"
        
        cmd = [
            "stwo_run_and_prove",
            "--program", str(self.workspace_root / "resources" / "simple_bootloader_compiled.json"),
            "--program_input", proving_task,
            "--prover_params_json", prover_params,
            "--proof_path", str(proof_path),
            "--proof-format", "cairo-serde",
            "--verify"
        ]
        
        start_time = time.time()
        result = subprocess.run(
            cmd,
            cwd=self.workspace_root,
            capture_output=True,
            text=True
        )
        prover_time = time.time() - start_time
        
        if result.returncode != 0:
            print(f"Proof generation failed: {result.stderr}")
            return {"success": False, "error": result.stderr, "prover_time": prover_time}
        
        print(f"✓ Proof generated in {prover_time:.2f}s")
        
        # Parse prover output for detailed metrics
        prover_metrics = self._parse_prover_output(result.stdout + result.stderr)
        
        # Find and measure proof file
        proof_files = list(self.target_dir.glob("*.proof"))
        proof_size = 0
        proof_file = None
        if proof_files:
            # Get the most recent proof file
            proof_file = max(proof_files, key=lambda p: p.stat().st_mtime)
            proof_size = proof_file.stat().st_size
            print(f"✓ Proof size: {proof_size:,} bytes ({proof_size / 1024:.2f} KB)")
        
        metrics = {
            "success": True,
            "prover_time": prover_time,
            "proof_size_bytes": proof_size,
            "proof_size_kb": proof_size / 1024,
            "proof_file": str(proof_file) if proof_file else None,
            "prover_metrics": prover_metrics,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
        
        return metrics

    def _parse_prover_output(self, output: str) -> Dict[str, Any]:
        """Parse detailed metrics from prover output."""
        metrics = {}
        
        # Common patterns in STARK provers
        patterns = [
            (r"Trace length:\s*(\d+)", "trace_length"),
            (r"Number of constraints:\s*(\d+)", "num_constraints"),
            (r"Degree:\s*(\d+)", "degree"),
            (r"Log trace length:\s*(\d+)", "log_trace_length"),
            (r"Blowup factor:\s*(\d+)", "blowup_factor"),
            (r"FRI queries:\s*(\d+)", "fri_queries"),
            (r"Proof of work bits:\s*(\d+)", "pow_bits"),
        ]
        
        for pattern, key in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                metrics[key] = int(match.group(1))
        
        return metrics

    def run_benchmark(
        self,
        name: str,
        package: str = "sphincs_plus",
        features: Optional[list[str]] = None,
        args_file: Optional[str] = None,
        proving_task: Optional[str] = None,
        prover_params: Optional[str] = None
    ) -> Dict[str, Any]:
        """Run a complete benchmark."""
        print(f"\n{'#'*60}")
        print(f"# Benchmark: {name}")
        print(f"# Package: {package}")
        print(f"# Timestamp: {datetime.now().isoformat()}")
        print(f"{'#'*60}")
        
        benchmark_result = {
            "name": name,
            "timestamp": datetime.now().isoformat(),
            "package": package,
            "features": features or [],
            "args_file": args_file,
        }
        
        # Step 1: Build
        build_metrics = self.build_sphincs(package, features)
        benchmark_result["build"] = build_metrics
        
        if not build_metrics["success"]:
            return benchmark_result
        
        # Step 2: Execute (if args file provided or sphincs_poseidon package)
        if args_file or package == "sphincs_poseidon":
            execution_metrics = self.execute_program(args_file, package)
            benchmark_result["execution"] = execution_metrics
            
            if not execution_metrics["success"]:
                return benchmark_result
        
        # Step 3: Generate proof (if proving task provided)
        if proving_task and prover_params:
            proof_metrics = self.generate_proof(proving_task, prover_params)
            benchmark_result["proof"] = proof_metrics
        
        # Calculate totals
        total_time = benchmark_result["build"]["build_time"]
        if "execution" in benchmark_result:
            total_time += benchmark_result["execution"]["execution_time"]
        if "proof" in benchmark_result and benchmark_result["proof"]["success"]:
            total_time += benchmark_result["proof"]["prover_time"]
        
        benchmark_result["total_time"] = total_time
        
        print(f"\n{'='*60}")
        print(f"Benchmark '{name}' completed!")
        print(f"Total time: {total_time:.2f}s")
        print(f"{'='*60}\n")
        
        return benchmark_result

    def save_results(self, results: Dict[str, Any], output_file: Optional[str] = None):
        """Save benchmark results to a JSON file."""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.results_dir / f"benchmark_{timestamp}.json"
        else:
            output_file = Path(output_file)
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"Results saved to: {output_file}")
        
        # Also save a human-readable summary
        summary_file = output_file.with_suffix('.txt')
        self._save_summary(results, summary_file)
        print(f"Summary saved to: {summary_file}")

    def _save_summary(self, results: Dict[str, Any], output_file: Path):
        """Save a human-readable summary of the benchmark results."""
        with open(output_file, 'w') as f:
            f.write(f"SPHINCS+ STARK Benchmark Results\n")
            f.write(f"{'='*60}\n\n")
            f.write(f"Benchmark: {results['name']}\n")
            f.write(f"Package: {results.get('package', 'sphincs_plus')}\n")
            f.write(f"Timestamp: {results['timestamp']}\n")
            f.write(f"Features: {', '.join(results['features']) if results['features'] else 'None'}\n")
            f.write(f"\n{'='*60}\n")
            f.write(f"SUMMARY\n")
            f.write(f"{'='*60}\n\n")
            
            # Build metrics
            if results['build']['success']:
                f.write(f"Build Time: {results['build']['build_time']:.2f}s\n")
            
            # Execution metrics
            if 'execution' in results and results['execution']['success']:
                f.write(f"Execution Time: {results['execution']['execution_time']:.2f}s\n")
                
                res = results['execution']['resource_usage']
                if 'n_steps' in res or 'steps' in res:
                    steps = res.get('n_steps', res.get('steps', 0))
                    f.write(f"Cairo Steps: {steps:,}\n")
                
                if 'n_memory_holes' in res or 'memory_holes' in res:
                    holes = res.get('n_memory_holes', res.get('memory_holes', 0))
                    f.write(f"Memory Holes: {holes:,}\n")
                
                if 'builtins' in res:
                    f.write(f"\nBuiltin Usage:\n")
                    for name, count in res['builtins'].items():
                        f.write(f"  {name}: {count:,}\n")
                
                # Include raw resource usage output
                if 'resource_usage_raw' in results['execution'] and results['execution']['resource_usage_raw']:
                    f.write(f"\n{'='*60}\n")
                    f.write(f"RAW RESOURCE USAGE OUTPUT\n")
                    f.write(f"{'='*60}\n")
                    f.write(results['execution']['resource_usage_raw'])
                    f.write("\n")
            
            # Proof metrics
            if 'proof' in results and results['proof']['success']:
                f.write(f"\nProver Time: {results['proof']['prover_time']:.2f}s\n")
                f.write(f"Proof Size: {results['proof']['proof_size_bytes']:,} bytes ")
                f.write(f"({results['proof']['proof_size_kb']:.2f} KB)\n")
                
                if results['proof']['prover_metrics']:
                    f.write(f"\nProver Metrics:\n")
                    for key, value in results['proof']['prover_metrics'].items():
                        f.write(f"  {key}: {value:,}\n")
            
            # Total
            f.write(f"\nTotal Time: {results['total_time']:.2f}s\n")


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark SPHINCS+ STARK proof generation"
    )
    parser.add_argument(
        "--name",
        default="sphincs_benchmark",
        help="Name for this benchmark run"
    )
    parser.add_argument(
        "--config",
        help="Path to benchmark configuration JSON file"
    )
    parser.add_argument(
        "--package",
        default="sphincs_plus",
        help="Package to benchmark (e.g., sphincs_plus, sphincs_poseidon)"
    )
    parser.add_argument(
        "--features",
        nargs="+",
        help="Cairo features to enable (e.g., blake_hash sparse_addr)"
    )
    parser.add_argument(
        "--args-file",
        default="packages/sphincs-plus/tests/data/sha2_simple_128s.json",
        help="Path to arguments file for execution"
    )
    parser.add_argument(
        "--proving-task",
        default="packages/sphincs-plus/proving_task.json",
        help="Path to proving task JSON file"
    )
    parser.add_argument(
        "--prover-params",
        default="prover_params.json",
        help="Path to prover parameters JSON file"
    )
    parser.add_argument(
        "--output",
        help="Output file for results (default: auto-generated in benchmarks/results/)"
    )
    parser.add_argument(
        "--skip-execution",
        action="store_true",
        help="Skip Cairo execution step"
    )
    parser.add_argument(
        "--skip-proof",
        action="store_true",
        help="Skip proof generation step"
    )
    
    args = parser.parse_args()
    
    # Find workspace root
    workspace_root = Path(__file__).parent.parent
    
    runner = BenchmarkRunner(workspace_root)
    
    if args.config:
        # Load configuration and run multiple benchmarks
        with open(args.config, 'r') as f:
            config = json.load(f)
        
        all_results = []
        for bench_config in config.get("benchmarks", []):
            result = runner.run_benchmark(
                name=bench_config.get("name", "unnamed"),
                package=bench_config.get("package", "sphincs_plus"),
                features=bench_config.get("features"),
                args_file=bench_config.get("args_file"),
                proving_task=bench_config.get("proving_task") if not args.skip_proof else None,
                prover_params=bench_config.get("prover_params") if not args.skip_proof else None
            )
            all_results.append(result)
        
        # Save combined results
        output_file = args.output or None
        runner.save_results({"benchmarks": all_results}, output_file)
    else:
        # Run single benchmark
        result = runner.run_benchmark(
            name=args.name,
            package=args.package,
            features=args.features,
            args_file=args.args_file if not args.skip_execution else None,
            proving_task=args.proving_task if not args.skip_proof else None,
            prover_params=args.prover_params if not args.skip_proof else None
        )
        
        runner.save_results(result, args.output)


if __name__ == "__main__":
    main()
