#!/usr/bin/env python3
"""
Compare multiple benchmark results to analyze performance differences.
"""

import argparse
import json
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime


def load_results(result_files: List[Path]) -> List[Dict[str, Any]]:
    """Load benchmark results from files."""
    results = []
    for file in result_files:
        with open(file, 'r') as f:
            data = json.load(f)
            # Handle both single benchmark and multi-benchmark formats
            if "benchmarks" in data:
                results.extend(data["benchmarks"])
            else:
                results.append(data)
    return results


def extract_metrics(result: Dict[str, Any]) -> Dict[str, Any]:
    """Extract key metrics from a benchmark result."""
    metrics = {
        "name": result.get("name", "unknown"),
        "timestamp": result.get("timestamp", ""),
        "features": ", ".join(result.get("features", [])) or "none",
    }
    
    # Build metrics
    if result.get("build", {}).get("success"):
        metrics["build_time"] = result["build"]["build_time"]
    
    # Execution metrics
    if result.get("execution", {}).get("success"):
        exec_data = result["execution"]
        metrics["execution_time"] = exec_data.get("execution_time", 0)
        
        res = exec_data.get("resource_usage", {})
        metrics["cairo_steps"] = res.get("n_steps", res.get("steps", 0))
        metrics["memory_holes"] = res.get("n_memory_holes", res.get("memory_holes", 0))
        
        # Sum builtin usage
        builtins = res.get("builtins", {})
        metrics["total_builtins"] = sum(builtins.values())
    
    # Proof metrics
    if result.get("proof", {}).get("success"):
        proof_data = result["proof"]
        metrics["prover_time"] = proof_data.get("prover_time", 0)
        metrics["proof_size_bytes"] = proof_data.get("proof_size_bytes", 0)
        metrics["proof_size_kb"] = proof_data.get("proof_size_kb", 0)
        
        prover_metrics = proof_data.get("prover_metrics", {})
        metrics["trace_length"] = prover_metrics.get("trace_length", 0)
        metrics["num_constraints"] = prover_metrics.get("num_constraints", 0)
        metrics["degree"] = prover_metrics.get("degree", 0)
    
    metrics["total_time"] = result.get("total_time", 0)
    
    return metrics


def format_number(value: float, unit: str = "") -> str:
    """Format a number with appropriate precision and unit."""
    if isinstance(value, str):
        return value
    if value == 0:
        return f"0{unit}"
    if value >= 1_000_000:
        return f"{value/1_000_000:.2f}M{unit}"
    if value >= 1_000:
        return f"{value/1_000:.2f}K{unit}"
    if unit == "s" or unit == "KB":
        return f"{value:.2f}{unit}"
    return f"{value:.0f}{unit}"


def calculate_change(baseline: float, current: float) -> str:
    """Calculate percentage change from baseline."""
    if baseline == 0:
        return "N/A"
    change = ((current - baseline) / baseline) * 100
    sign = "+" if change > 0 else ""
    return f"{sign}{change:.1f}%"


def print_comparison_table(results: List[Dict[str, Any]]):
    """Print a comparison table of benchmark results."""
    if not results:
        print("No results to compare.")
        return
    
    metrics_list = [extract_metrics(r) for r in results]
    
    # Get all available metric keys
    all_keys = set()
    for m in metrics_list:
        all_keys.update(m.keys())
    
    # Define display order and labels
    metric_display = {
        "name": ("Name", ""),
        "features": ("Features", ""),
        "build_time": ("Build Time", "s"),
        "execution_time": ("Execution Time", "s"),
        "cairo_steps": ("Cairo Steps", ""),
        "memory_holes": ("Memory Holes", ""),
        "total_builtins": ("Total Builtins", ""),
        "prover_time": ("Prover Time", "s"),
        "proof_size_bytes": ("Proof Size", "bytes"),
        "proof_size_kb": ("Proof Size", "KB"),
        "trace_length": ("Trace Length", ""),
        "num_constraints": ("Constraints", ""),
        "degree": ("Degree", ""),
        "total_time": ("Total Time", "s"),
    }
    
    # Print header
    print("\n" + "="*100)
    print("BENCHMARK COMPARISON")
    print("="*100)
    print()
    
    # Print table
    for key, (label, unit) in metric_display.items():
        if key not in all_keys or key in ["name", "timestamp", "features"]:
            continue
        
        values = [m.get(key, 0) for m in metrics_list]
        if all(v == 0 for v in values):
            continue
        
        print(f"{label:20}", end="")
        for m in metrics_list:
            value = m.get(key, 0)
            print(f"{format_number(value, unit):>20}", end="")
        print()
    
    print()
    
    # Print names and features for reference
    print("\nBenchmark Details:")
    print("-" * 100)
    for i, m in enumerate(metrics_list, 1):
        print(f"{i}. {m['name']:30} Features: {m['features']}")
    
    # Calculate improvements relative to first benchmark
    if len(metrics_list) > 1:
        print("\n" + "="*100)
        print("CHANGES RELATIVE TO FIRST BENCHMARK")
        print("="*100)
        print()
        
        baseline = metrics_list[0]
        
        for i, m in enumerate(metrics_list[1:], 2):
            print(f"\n{m['name']} vs {baseline['name']}:")
            print("-" * 50)
            
            for key, (label, _) in metric_display.items():
                if key in ["name", "timestamp", "features"]:
                    continue
                
                baseline_val = baseline.get(key, 0)
                current_val = m.get(key, 0)
                
                if baseline_val == 0 or current_val == 0:
                    continue
                
                change = calculate_change(baseline_val, current_val)
                print(f"  {label:20} {change:>10}")


def print_summary_stats(results: List[Dict[str, Any]]):
    """Print summary statistics across all benchmarks."""
    if not results:
        return
    
    metrics_list = [extract_metrics(r) for r in results]
    
    print("\n" + "="*100)
    print("SUMMARY STATISTICS")
    print("="*100)
    print()
    
    numeric_keys = [
        ("cairo_steps", "Cairo Steps"),
        ("prover_time", "Prover Time (s)"),
        ("proof_size_kb", "Proof Size (KB)"),
        ("total_time", "Total Time (s)"),
    ]
    
    for key, label in numeric_keys:
        values = [m.get(key, 0) for m in metrics_list if m.get(key, 0) > 0]
        if not values:
            continue
        
        min_val = min(values)
        max_val = max(values)
        avg_val = sum(values) / len(values)
        
        print(f"{label:20}")
        print(f"  Min: {format_number(min_val):>15}")
        print(f"  Max: {format_number(max_val):>15}")
        print(f"  Avg: {format_number(avg_val):>15}")
        print()


def save_comparison_report(results: List[Dict[str, Any]], output_file: Path):
    """Save a detailed comparison report."""
    metrics_list = [extract_metrics(r) for r in results]
    
    report = {
        "generated_at": datetime.now().isoformat(),
        "num_benchmarks": len(results),
        "benchmarks": metrics_list,
    }
    
    # Calculate comparisons
    if len(metrics_list) > 1:
        baseline = metrics_list[0]
        comparisons = []
        
        for m in metrics_list[1:]:
            comp = {
                "name": m["name"],
                "baseline": baseline["name"],
                "changes": {}
            }
            
            for key in ["cairo_steps", "prover_time", "proof_size_kb", "total_time"]:
                baseline_val = baseline.get(key, 0)
                current_val = m.get(key, 0)
                
                if baseline_val > 0 and current_val > 0:
                    comp["changes"][key] = {
                        "baseline": baseline_val,
                        "current": current_val,
                        "change_percent": ((current_val - baseline_val) / baseline_val) * 100
                    }
            
            comparisons.append(comp)
        
        report["comparisons"] = comparisons
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nDetailed comparison report saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Compare SPHINCS+ benchmark results"
    )
    parser.add_argument(
        "result_files",
        nargs="+",
        help="Benchmark result JSON files to compare"
    )
    parser.add_argument(
        "--output",
        help="Save detailed comparison report to this file"
    )
    
    args = parser.parse_args()
    
    # Load results
    result_files = [Path(f) for f in args.result_files]
    results = load_results(result_files)
    
    if not results:
        print("No valid results found.")
        return
    
    # Print comparisons
    print_comparison_table(results)
    print_summary_stats(results)
    
    # Save detailed report if requested
    if args.output:
        save_comparison_report(results, Path(args.output))


if __name__ == "__main__":
    main()
