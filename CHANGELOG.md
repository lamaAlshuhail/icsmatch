# Changelog

## 0.1.0, 2026-09-19

First public release.

### Measurement

Product identifier coverage across the CISA ICS CSAF corpus at cisagov/CSAF
commit 6f2e04f: 28 of 27,664 products carry a CPE (0.10%), 8,141 carry a model
or order number (29.43%). Reproducible with `icsmatch stats --by-year`.

### Defects found and fixed during review

Each is pinned by a regression test that fails without the fix.

- Product name normalisation stripped brand prefixes, so "SIPROTEC 5" and
  "SICAM 5" both reduced to `5` and matched at high confidence. Brand and core
  are now separate fields; a brand disagreement vetoes the match.
- Two advisories sharing one tracking id were silently overwritten on ingest.
  Both are now kept, the second under a `~n` suffix, and the collision is
  reported.
- Tier 1 asserted "affected" on a SKU match regardless of firmware version. A
  device patched past every fix was reported vulnerable by nine advisories. The
  range is now checked.
- `rapidfuzz.process.cdist` imports numpy lazily and rapidfuzz does not install
  it, so a clean install failed at match time. Switched to `process.extract`.
- Six vendor aliases existed only in the YAML file and were unreachable without
  PyYAML. Mirrored into the stdlib fallback table with a test guarding parity.
- `icsmatch search` raised on hyphens, quotes and bare `OR`. Input is now
  escaped as FTS5 phrases.
- VEX export could never emit `not_affected` because the command did not
  request those verdicts. Analyst rejections now reach the export with a
  justification.
- A `known_not_affected` leaf could displace a `known_affected` leaf for the
  same advisory. Verdict-aware tie-break added.
- The CVSS 4.0 safety check read `SC:H`, which is subsequent-system
  confidentiality. Now reads `S:P`, `MSI:S` and `MSA:S`.
- The `--min-precision` gate treated a cutoff with zero predictions as
  precision 0.0 and failed. Undefined precision now prints `n/a` and does not
  fail the gate.

### Performance

Matching rebuilt around inverted indexes with batched fuzzy scoring: 38.77 ms
per asset down to 1.04 ms against 27,664 products, measured end to end.
