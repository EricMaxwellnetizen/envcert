# Dataset-file example

Clean train/test JSONL for the dataset adapter:

```bash
envicert check examples/dataset-files          # passes: no leaks, dups, overlap or degenerate labels
envicert check examples/dataset-files/train.jsonl
```

Try the failure mode by copying `test.jsonl` to `train-copy.jsonl` in a
scratch directory and adding a row whose prompt contains its answer —
EC081/EC082/EC080 will flag it.
