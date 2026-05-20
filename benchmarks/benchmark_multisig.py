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
from typing import Dict, Any, List, Optional
import sys


class MultiSigBenchmarkRunner:
    # Map package names to their multi-sig executable names
    EXECUTABLE_NAMES = {
        "sphincs-btc": "main_multi",
        "sphincs-poseidon": "poseidon_multi",
        "schnorr-btc": "schnorr_btc_multi",
        "sphincs-poseidon-c" : "poseidon_tiny_multi",
    }

    # Map package names to their single-sig executable names
    SINGLE_EXECUTABLE_NAMES = {
        "sphincs-btc": "main",
        "sphincs-poseidon": "poseidon_main",
        "schnorr-btc": "schnorr_btc_main",
        "sphincs-poseidon-c": "poseidon_tiny_main",
    }

    def __init__(self, workspace_root: Path, package: str = "sphincs-btc"):
        self.workspace_root = workspace_root
        self.package = package
        self.sphincs_package = workspace_root / "packages" / package
        self.executable_name = self.EXECUTABLE_NAMES.get(package, "main_multi")
        self.single_executable_name = self.SINGLE_EXECUTABLE_NAMES.get(package, "main")
        self.target_dir = workspace_root / "target"
        self.results_dir = workspace_root / "benchmarks" / "results"
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.temp_args_dir = self.results_dir / "temp_args"
        self.temp_args_dir.mkdir(parents=True, exist_ok=True)

    def _get_or_generate_args(
        self,
        num_sigs: int,
        seed: int,
        message_prefix: str,
        reuse_args: Optional[str]
    ) -> Dict[str, Any]:
        """Get existing args file or generate new signatures."""
        if reuse_args is None:
            # No reuse requested, generate new signatures
            return self.generate_multi_sig_args(num_sigs, seed, message_prefix)

        # Determine which file to check
        if isinstance(reuse_args, str) and reuse_args not in (True, "True", "true"):
            # User specified a specific file path
            args_file = Path(reuse_args)
        else:
            # Auto-detect based on naming convention
            args_file = self.temp_args_dir / f"multisig_n{num_sigs}_seed{seed}.json"

        if args_file.exists():
            print(f"\n{'='*60}")
            print(f"Reusing existing args file: {args_file}")
            print(f"{'='*60}")
            return {
                "success": True,
                "generation_time": 0.0,
                "args_file": str(args_file),
                "num_signatures": num_sigs,
                "seed": seed,
                "reused": True,
            }
        else:
            print(f"\n{'='*60}")
            print(f"Args file not found: {args_file}")
            print(f"Generating new signatures...")
            print(f"{'='*60}")
            return self.generate_multi_sig_args(num_sigs, seed, message_prefix)

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

    def build_package(self) -> Dict[str, Any]:
        """Build the target package."""
        print(f"\n{'='*60}")
        print(f"Building {self.package} package...")
        print(f"{'='*60}")

        # Convert package name to scarb package name (e.g., sphincs-btc -> sphincs_btc)
        scarb_package = self.package.replace("-", "_")
        cmd = ["scarb", "--profile", "release", "build", "--package", scarb_package]
        
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

    def execute_program(self, args_file: str, num_sigs: int = 2) -> Dict[str, Any]:
        """Execute Cairo program with multi-sig args."""
        print(f"\n{'='*60}")
        print(f"Executing {self.package} program...")
        print(f"{'='*60}")

        # Convert package name to scarb package name (e.g., sphincs-btc -> sphincs_btc)
        scarb_package = self.package.replace("-", "_")
        executable = self.single_executable_name if num_sigs == 1 else self.executable_name
        cmd = [
            "scarb", "--profile", "release", "execute",
            "--no-build",
            "--package", scarb_package,
            "--executable-name", executable,
            "--print-resource-usage",
            "--arguments-file", args_file
        ]

        print(" ".join(cmd))
        
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

    def generate_proof(self, args_file: str, num_sigs: int = 2) -> Dict[str, Any]:
        """Generate STARK proof for the multi-sig execution."""
        print(f"\n{'='*60}")
        print("Generating STARK proof...")
        print(f"{'='*60}")
        
        bootloader_path = self.workspace_root / "resources" / "simple_bootloader_compiled.json"
        if not bootloader_path.exists():
            return {"success": False, "error": f"Bootloader not found: {bootloader_path}"}
        
        base_proving_task_path = self.sphincs_package / "proving_task.json"
        if not base_proving_task_path.exists():
            return {"success": False, "error": f"Proving task not found: {base_proving_task_path}"}

        # Override user args to point to the generated multi-sig args file
        try:
            with open(base_proving_task_path, "r") as f:
                proving_task = json.load(f)
        except Exception as exc:
            return {"success": False, "error": f"Failed to read proving task: {exc}"}

        try:
            proving_task["tasks"][0]["user_args_file"] = str(Path(args_file).resolve())
            exe_name = self.single_executable_name if num_sigs == 1 else self.executable_name
            exe_path = self.workspace_root / "target" / "release" / f"{exe_name}.executable.json"
            proving_task["tasks"][0]["path"] = str(exe_path.resolve())
        except Exception as exc:
            return {"success": False, "error": f"Failed to patch proving task: {exc}"}

        patched_task_path = self.temp_args_dir / "proving_task_multisig.json"
        with open(patched_task_path, "w") as f:
            json.dump(proving_task, f)
        
        scarb_package = self.package.replace("-", "_")
        proof_output_dir = self.target_dir / "execute" / scarb_package / "execution1" / "proof"
        proof_output_dir.mkdir(parents=True, exist_ok=True)
        proof_output_path = proof_output_dir / "proof.json"
        
        prover_params_path = self.workspace_root / "prover_params.json"
        
        cmd = [
            "stwo_run_and_prove",
            "--program", str(bootloader_path.resolve()),
            "--program_input", str(patched_task_path.resolve()),
            "--proof_path", str(proof_output_path.resolve()),
            "--proof-format", "cairo-serde",
            "--verify",
        ]
        
        if prover_params_path.exists():
            cmd.extend(["--prover_params_json", str(prover_params_path.resolve())])
        
        start_time = time.time()
        result = subprocess.run(
            cmd,
            cwd=self.workspace_root,
            capture_output=True,
            text=True
        )
        prover_time = time.time() - start_time
        
        if result.returncode != 0:
            print(f"Proof generation failed (return code: {result.returncode})")
            print(f"\n--- STDOUT ---\n{result.stdout}" if result.stdout else "\n--- STDOUT ---\n(empty)")
            print(f"\n--- STDERR ---\n{result.stderr}" if result.stderr else "\n--- STDERR ---\n(empty)")
            return {"success": False, "error": result.stderr, "stdout": result.stdout, "prover_time": prover_time}
        
        print(f"✓ Proof generated in {prover_time:.2f}s")
        
        proof_size = 0
        proof_file = None
        if proof_output_path.exists():
            proof_file = proof_output_path
            proof_size = proof_file.stat().st_size
            print(f"✓ Proof size: {proof_size:,} bytes ({proof_size / 1024:.2f} KB)")
        
        return {
            "success": True,
            "prover_time": prover_time,
            "proof_size_bytes": proof_size,
            "proof_size_kb": proof_size / 1024,
            "proof_file": str(proof_file) if proof_file else None,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    def run_benchmark(
        self,
        num_sigs: int,
        seed: int,
        message_prefix: str = "test",
        run_proof: bool = True,
        reuse_args: Optional[str] = None
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

        # Step 1: Generate signatures (or reuse existing)
        gen_metrics = self._get_or_generate_args(num_sigs, seed, message_prefix, reuse_args)
        benchmark_result["generation"] = gen_metrics

        if not gen_metrics["success"]:
            return benchmark_result
        
        # Step 2: Build (once)
        build_metrics = self.build_package()
        benchmark_result["build"] = build_metrics
        
        if not build_metrics["success"]:
            return benchmark_result
        
        # Step 3: Execute
        exec_metrics = self.execute_program(gen_metrics["args_file"], num_sigs)
        benchmark_result["execution"] = exec_metrics
        
        # Step 4: Prove
        if run_proof:
            proof_metrics = self.generate_proof(gen_metrics["args_file"], num_sigs)
            benchmark_result["proof"] = proof_metrics
            if not proof_metrics["success"]:
                return benchmark_result

        # Calculate totals
        total_time = (
            gen_metrics["generation_time"] +
            build_metrics["build_time"] +
            exec_metrics.get("execution_time", 0)
        )
        if run_proof and benchmark_result.get("proof", {}).get("success"):
            total_time += benchmark_result["proof"]["prover_time"]
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
        message_prefix: str = "test",
        run_proof: bool = True,
        reuse_args: Optional[str] = None
    ) -> Dict[str, Any]:
        """Run benchmarks for multiple signature counts and seeds."""
        result = self.run_benchmark(sig_counts, seed, message_prefix, run_proof, reuse_args)
        return result

    def save_results(self, result: Dict[str, Any], output_file: str = None):
        """Save benchmark results to JSON file."""
        # Check if any stage failed and skip writing logs if so
        for key in ("generation", "build", "execution", "proof"):
            if key in result and not result[key].get("success", True):
                print(f"Skipping result log write due to error in '{key}' stage.")
                return

        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.results_dir / f"multisig_benchmark_{timestamp}.json"
        else:
            output_file = Path(output_file)
        
        with open(output_file, 'w') as f:
            json.dump({"benchmarks": result}, f, indent=2)
        
        print(f"Results saved to: {output_file}")
        
        # Save human-readable summary
        summary_file = output_file.with_suffix('.txt')
        self._save_summary(result, summary_file)
        print(f"Summary saved to: {summary_file}")

    def _save_summary(self, result: Dict[str, Any], output_file: Path):
        """Save human-readable summary."""
        with open(output_file, 'w') as f:
            f.write(f"{self.package} Multi-Signature Benchmark Results\n")
            f.write(f"{'='*60}\n\n")
            
            f.write(f"Benchmark\n")
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
            
            if 'proof' in result and result['proof'].get('success'):
                f.write(f"Prover Time: {result['proof']['prover_time']:.2f}s\n")
                f.write(f"Proof Size: {result['proof']['proof_size_bytes']:,} bytes ({result['proof']['proof_size_kb']:.2f} KB)\n")
            
            f.write(f"Total Time: {result['total_time']:.2f}s\n")


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark SPHINCS+ BTC with multiple signatures"
    )
    parser.add_argument(
        '--num-signatures', '-n',
        type=int,
        default=2,
        help='Number of signatures to benchmark (>= 1; use 1 for single-signature baseline)'
    )
    parser.add_argument(
        '--seed',
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
    parser.add_argument(
        '--skip-proof',
        action='store_true',
        help='Skip STARK proof generation'
    )
    parser.add_argument(
        '--package', '-p',
        default='sphincs-btc',
        help='Package to benchmark (default: sphincs-btc)'
    )
    parser.add_argument(
        '--reuse-args',
        nargs='?',
        const=True,
        default=False,
        help='Skip signature generation if args file exists. Optionally specify a file path to use.'
    )

    args = parser.parse_args()

    if args.num_signatures < 1:
        print("Error: --num-signatures must be at least 1")
        sys.exit(1)

    # Find workspace root
    workspace_root = Path(__file__).parent.parent
    
    runner = MultiSigBenchmarkRunner(workspace_root, args.package)
    
    # Run benchmark sweep
    results = runner.run_sweep(
        sig_counts=args.num_signatures,
        seed=args.seed,
        message_prefix=args.message_prefix,
        run_proof=not args.skip_proof,
        reuse_args=args.reuse_args
    )
    
    # Save results
    runner.save_results(results, args.output)


if __name__ == "__main__":
    main()
