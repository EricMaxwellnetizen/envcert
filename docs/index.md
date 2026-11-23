# Envicert

**Integrity verification and evidence for AI training and evaluation environments.**

Envicert checks whether the thing you measure models with is trustworthy:
a task bundle (instruction, Docker environment, reference solution,
verifier) or the dataset file itself (JSONL/JSON/CSV/Parquet). Is the
answer leaked to the agent? Can agent-controlled files influence the
verifier? Would a *cheating* solution pass? Are train and test rows the
same rows? Is the build reproducible, the evidence verifiable?

```bash
pip install envicert
envicert check ./my-task
envicert check ./train.jsonl
envicert check ./my-task --execution docker   # gold + no-op + cheat battery
envicert fix ./my-task                        # deterministic remediation
envicert new ./my-new-task                    # scaffold that passes check
```

- [Quickstart](guides/QUICKSTART.md)
- [Datasets, the cheat battery, fixes and scaffolding](guides/DATASETS_AND_CHEATS.md)
- [Check catalog](architecture/CHECK_CATALOG.md)
- [Product review: is the problem real, is the gap real?](research/PRODUCT_REVIEW.md)
- [Real-world pilot (Harbor, Terminal-Bench, SWE-bench, Harbor Hub)](research/PILOT_040.md)
- [Competitive analysis](research/COMPETITIVE_ANALYSIS.md)

Envicert reports evidence about checked properties; it is not a
certification that an environment is unhackable.
