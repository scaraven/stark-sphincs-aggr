# SPHINCS+ STARK Benchmark Suite

This benchmark suite allows you to measure and analyze the performance characteristics of SPHINCS+ proof generation in STARKs.

## Metrics Collected

The benchmark suite collects the following metrics:

### 1. Compilation Metrics
- **Build Time**: Time taken to compile the Cairo code
- **Features Used**: List of Cairo features enabled during compilation

### 2. Execution Metrics
- **Execution Time**: Time taken to execute the Cairo program
- **Cairo Steps**: Number of computational steps in the Cairo VM
- **Memory Holes**: Memory efficiency metric
- **Builtin Usage**: Usage of various Cairo builtins (range_check, pedersen, etc.)

### 3. Proof Generation Metrics
- **Prover Time**: Total time taken to generate the STARK proof
- **Proof Size**: Size of the generated proof in bytes/KB
- **Trace Length**: Length of the execution trace
- **Number of Constraints**: Total constraints in the STARK system
- **FRI Parameters**: FRI queries, blowup factor, etc.

## Usage

### Basic Usage

Run a single benchmark with default settings:

```bash
python benchmarks/benchmark.py --name "my_benchmark"
```

### With Specific Features

Benchmark with specific Cairo features enabled:

```bash
python benchmarks/benchmark.py \
  --name "blake_sparse_benchmark" \
  --features blake_hash sparse_addr
```

### Using Configuration File

Run multiple benchmarks from a configuration file:

```bash
python benchmarks/benchmark.py --config benchmarks/benchmark_config.json
```

### Skip Specific Steps

Skip execution (only build):
```bash
python benchmarks/benchmark.py --skip-execution --skip-proof
```

Skip proof generation (build + execute only):
```bash
python benchmarks/benchmark.py --skip-proof
```

### Custom Output Location

Specify where to save results:
```bash
python benchmarks/benchmark.py \
  --name "custom_benchmark" \
  --output benchmarks/results/custom_results.json
```

## Configuration File Format

Create a JSON configuration file to run multiple benchmarks:

```json
{
  "description": "Description of benchmark suite",
  "benchmarks": [
    {
      "name": "benchmark_name",
      "description": "What this benchmark tests",
      "features": ["feature1", "feature2"],
      "args_file": "path/to/args.json",
      "proving_task": "path/to/proving_task.json",
      "prover_params": "path/to/prover_params.json"
    }
  ]
}
```

## Output Files

The benchmark script generates two files for each run:

1. **JSON Results** (`benchmark_YYYYMMDD_HHMMSS.json`): Complete detailed results in JSON format
2. **Text Summary** (`benchmark_YYYYMMDD_HHMMSS.txt`): Human-readable summary

Both files are saved in `benchmarks/results/` by default.

## Example Workflow

1. **Run baseline benchmark:**
   ```bash
   python benchmarks/benchmark.py --name "baseline_sha2"
   ```

2. **Run with optimizations:**
   ```bash
   python benchmarks/benchmark.py \
     --name "optimized_blake" \
     --features blake_hash sparse_addr
   ```

3. **Compare results:**
   ```bash
   python benchmarks/compare_results.py \
     benchmarks/results/benchmark_*.json
   ```

## Analyzing Results

### Key Metrics to Monitor

1. **Proof Size Reduction**: Compare `proof_size_bytes` across configurations
2. **Prover Time**: Check `prover_time` for performance impact
3. **Cairo Steps**: Monitor `n_steps` for computational complexity
4. **Constraints**: Track `num_constraints` for proof complexity

### Example Analysis

```python
import json

# Load two benchmark results
with open('benchmarks/results/benchmark_baseline.json') as f:
    baseline = json.load(f)

with open('benchmarks/results/benchmark_optimized.json') as f:
    optimized = json.load(f)

# Compare proof sizes
baseline_size = baseline['proof']['proof_size_bytes']
optimized_size = optimized['proof']['proof_size_bytes']
reduction = (1 - optimized_size / baseline_size) * 100

print(f"Proof size reduction: {reduction:.2f}%")
```

## Prerequisites

- Python 3.8+
- Scarb (Cairo build tool)
- stwo_run_and_prove (STARK prover)

## Troubleshooting

### "Command not found" errors

Make sure the required tools are installed:
- `scarb --version` should work
- `stwo_run_and_prove --help` should work

### Build failures

Check that you're in the correct directory and all dependencies are installed:
```bash
cd /home/scaraven/stark-sphincs-aggr
scarb build --package sphincs_plus
```

### Proof generation fails

Verify that the proving task and prover parameters are correctly configured:
- Check `packages/sphincs-plus/proving_task.json`
- Check `prover_params.json`
- Ensure the Cairo program builds successfully first

## Advanced Usage

### Custom Prover Parameters

Create a custom prover parameters file to test different configurations:

```json
{
  "channel_hash": "blake2s",
  "pcs_config": {
    "pow_bits": 20,
    "fri_config": {
      "log_last_layer_degree_bound": 0,
      "log_blowup_factor": 2,
      "n_queries": 50
    }
  },
  "preprocessed_trace": "canonical_without_pedersen"
}
```

Then use it:
```bash
python benchmarks/benchmark.py \
  --name "custom_params" \
  --prover-params my_custom_params.json
```

### Automated Testing

Create a shell script to run multiple configurations:

```bash
#!/bin/bash
for pow_bits in 20 22 24 26; do
  # Modify prover_params.json
  # Run benchmark
  python benchmarks/benchmark.py --name "pow_${pow_bits}"
done
```

## Contributing

To add new metrics:

1. Update the parsing functions in `benchmark.py`
2. Add the metrics to the results dictionary
3. Update the summary generation to include new metrics
4. Document the new metrics in this README
