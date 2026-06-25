# Dataset Sources

The starter dataset is intentionally mixed:

- `data/base_prompts.csv`: public seed rows from `deepset/prompt-injections`
- `data/custom_prompts.csv`: hand-built rows for prompt-injection families, SOC-assistant attacks, and benign-but-suspicious false-positive traps
- `data/prompts.csv`: shuffled combined dataset used by training and evaluation

The public seed is useful for breadth, but it should not be trusted blindly. Public prompt-injection datasets are small, uneven, and sometimes mislabeled. The custom rows are what make this project read like detection engineering instead of a copied ML demo.

To refresh the public seed:

```bash
python3 scripts/download_base_dataset.py
python3 scripts/build_dataset.py
```

To add your own examples, append rows to `data/custom_prompts.csv` or directly to `data/prompts.csv`, then rerun training and evaluation.
