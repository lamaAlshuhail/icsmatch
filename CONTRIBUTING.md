# Contributing

Three kinds of contribution matter most, in this order.

**Vendor aliases.** If your inventory spells a vendor differently than the
advisories do, add it to `data/normalizers.yaml` and to the fallback table in
`src/icsmatch/normalize/product.py`. A test enforces that both stay in sync, so
the tool behaves identically with or without PyYAML installed.

**Labelled pairs.** A confirmed or rejected asset-to-advisory pair from a real
inventory, with identifiers stripped, strengthens `examples/labels/sample_labels.csv`.
Negatives are more valuable than positives: state what the tool got wrong.

**Version formats.** Run `icsmatch coverage --source <your CSAF directory>` and
open an issue with any range strings that land in the unparseable bucket.

## Before opening a pull request

```bash
pip install -e ".[dev]"
python -m pytest -q
ruff check src tests
mypy src
```

All three must pass. CI also runs the suite with no optional extras installed,
so do not add a hard dependency on `rapidfuzz`, `PyYAML` or `numpy`.

## Style

No em dashes. Comments are lowercase and explain a decision, not the code
beneath them. A comment that restates the next line should be deleted.
