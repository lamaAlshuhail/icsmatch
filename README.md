# icsmatch

**Match ICS/OT security advisories against your asset inventory.** CSAF-native, offline-capable, no server.

[![CI](https://github.com/lamaAlshuhail/icsmatch/actions/workflows/ci.yml/badge.svg)](https://github.com/lamaAlshuhail/icsmatch/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## The problem

A new CISA advisory drops. The only question that matters is: **does this affect anything I own?**

Answering it is harder than it should be, because the identifier the IT world uses, CPE, barely exists in OT data. Measured across the CISA CSAF corpus (4,021 advisories, 27,664 products, 2010 to 2026):

| Identifier | Products carrying it | Share |
|---|---:|---:|
| **CPE** | 28 | **0.10%** |
| **Model / order number** | 8,141 | **29.43%** |

Siemens stated the position at [CSAF Community Days 2024](https://www.csaf.io/events/community-days/2024/): *"CPE is not a solution for us, approach for Siemens: use order numbers."*

So `icsmatch` matches on what OT data contains: model and order numbers first, CPE second, normalised vendor and product third. Every finding states which basis it used.

Reproduce both figures with `icsmatch stats`.

## What it does

```
asset inventory (CSV)  x  CISA CSAF corpus  ->  prioritised triage report
```

- **Ingests CSAF 2.0 JSON** directly from [cisagov/CSAF](https://github.com/cisagov/CSAF), no HTML scraping
- **Six-tier match cascade** with an explicit confidence and a readable basis per finding
- **Honours `product_status`**, so a product the vendor lists as not affected or already fixed does not become a finding
- **Prioritises by exploitation, not CVSS**, using CISA KEV, FIRST EPSS and Purdue-level exposure, and emits an SSVC vector per row
- **Runs air-gapped**, SQLite on disk, `--offline` flag, cached feeds
- **Exports** markdown for the reader, structured JSON for scripts, and OpenVEX for anything downstream

## Install

```bash
pip install "git+https://github.com/lamaAlshuhail/icsmatch"                 # core, stdlib only
pip install "icsmatch[fuzzy,yaml] @ git+https://github.com/lamaAlshuhail/icsmatch"   # with rapidfuzz and YAML
```

## Quickstart

```bash
# 1. get the corpus (~200 MB, shallow clone)
git clone --depth 1 https://github.com/cisagov/CSAF.git

# 2. build the local database
icsmatch update --source ./CSAF/csaf_files

# 3. triage your inventory
icsmatch report --assets my_plant.csv --client "Plant A" --out triage.md
```

Your inventory needs a few columns. Header spellings are matched loosely, so `vendor`, `manufacturer` and `make` all work:

```csv
asset_id,vendor,product,version,model,purdue_level,site
PLC-001,Siemens,SIMATIC S7-1200,4.2.1,6ES7214-1AG40-0XB0,1,Plant-A
RTU-200,Hitachi Energy,FOXMAN-UN,R15A,,2,Plant-B
DCS-300,Schneider Electric,Modicon M580,3.20,,1,Plant-C
```

If none of the headers are recognised, the tool says so instead of silently matching nothing.

## Example output

```
$ icsmatch match --assets examples/sample_inventory.csv --max-tier 3
10 assets x 4,021 advisories -> 69 findings

[NEXT ] PLC-001    ICSA-25-044-01     CVSS  7.5  T1
          model/SKU '6ES7214-1AG40-0XB0' matches advisory identifier '6ES7214-1AG40-0XB0'
          -> CVSS 7.5, high severity, patch available
[NEXT ] RTU-200    ICSA-25-014-01     CVSS 10.0  T3
          vendor+product match; asset version R15A satisfies =R15A
          -> CVSS 10.0, critical severity
[NEXT ] HIST-400   ICSA-23-017-01     CVSS  9.8  T3
          vendor+product match; asset version 9.0 satisfies >=v7.0
          -> CVSS 9.8 at Purdue level 3, critical and exposed
```

Full markdown report: **[examples/sample_report.md](examples/sample_report.md)**

## How matching works

First tier to hit wins. Every finding states which one.

| Tier | Basis | Confidence | Verdict |
|:---:|---|---:|---|
| **0** | Analyst-confirmed alias (from `icsmatch review`) | 1.00 | AFFECTED |
| **1** | Model / SKU exact match, version in range where one is given | 1.00 | AFFECTED |
| **2** | CPE exact match | 0.95 | AFFECTED |
| **3** | Vendor + product identity, version in range | 0.85 | AFFECTED |
| **4** | Vendor + fuzzy or low-entropy product, version in range | ~0.50 | **REVIEW** |
| **5** | Vendor match only | 0.30 | MANUAL |

Five design rules:

**Tier 4 never auto-asserts.** A fuzzy hit is surfaced for a human, never reported as confirmed. A false "you're affected" costs analyst time and credibility; a flagged "verify this" costs one glance.

**A model number proves identity, not vulnerability.** A SKU match says you own the right device. Whether that device is vulnerable is the version range's job, so tier 1 still checks it: firmware past every published fix is reported not affected, and an unparseable range drops to UNKNOWN rather than asserting.

**A product key keeps its brand.** "SIPROTEC 5" and "SICAM 5" are different products. Collapsing both to `5` would match them, so brand and core are separate fields and a brand disagreement vetoes the match. A core that is short or all digits, with no brand behind it, drops to tier 4 rather than asserting. Variant lines are known: SIPLUS resolves to SIMATIC, because advisories fold them together in a scope note the normaliser has to drop.

**Unparseable means unparseable.** When a version range cannot be parsed, `contains()` returns `None`, not `False`. `False` would silently mark the asset safe. `None` routes it to a review bucket with the reason attached.

**Analyst judgement outranks every heuristic.** Tier 0 sits above exact SKU match because a human looked at it. A confirmed pair is promoted forever; a rejected pair is suppressed forever.

### What the vendor already answered

CSAF carries eight `product_status` arrays and `icsmatch` reads all of them. A product listed under `known_not_affected` or `fixed` does not become a finding, and `under_investigation` is reported as a watch rather than a confirmed hit. A clear leaf never hides an affected one: if an advisory names your product twice, once as clear and once as affected, you get the affected finding.

## The review loop

Fuzzy matches are the expensive part of triage, and every tool throws the analyst's answer away. `icsmatch` keeps it.

```
$ icsmatch review --assets plant.csv --analyst L.Alshuhail
7 product pairs to review (of 7 outstanding, covering 28 findings)
[y] confirm   [n] reject   [s] skip   [q] quit

[1/7] tier 4  x1 findings  max CVSS 9.8
  asset     : Siemens / SCALANCE X208  (e.g. SW-021)
  advisory  : Siemens / SCALANCE XF208
  seen in   : ICSA-21-103-07
  basis     : fuzzy product match 'SCALANCE X208'~'SCALANCE XF208' (ratio 0.89); <V5.2.5
  same product? [y/n/s/q]
```

The queue is ordered by impact, by tier then max CVSS then how many findings the pair covers, and bounded (`--limit`, default 25), because an unbounded review queue is a review queue nobody finishes.

Next run, the confirmed pair comes back as tier 0 with the analyst cited:

```
[NEXT ] SW-021  ICSA-21-103-07  CVSS 9.8  T0
    analyst-confirmed alias 'SCALANCE X208' = 'SCALANCE XF208' by L.Alshuhail on 2026-08-25; <V5.2.5
```

Confirming identity does **not** confirm the version, the range still has to hold. Rejecting a pair suppresses it from reports and records it as `not_affected` in VEX output, so the decision travels. `icsmatch aliases` exports your confirmed pairs, ready to contribute back to `data/normalizers.yaml`.

Decisions live in a separate file (`<db>.decisions.db`) so `icsmatch update` can rebuild the corpus without ever risking analyst work.

## Multiple inventories

Point it at a directory of inventories and it renders one report per inventory plus a rollup:

```
$ icsmatch report --all-clients ./inventories --outdir reports
  water-utility               6 assets    67 findings  -> reports/water-utility.md
  petrochem-east              3 assets    31 findings  -> reports/petrochem-east.md

portfolio summary -> reports/portfolio.md
```

The rollup ranks inventories by urgency and surfaces **shared exposure**, advisories hitting more than one site, which is what you brief in the morning stand-up. Asset identifiers never cross reports; the summary carries counts and public advisory IDs only.

## What changed since last week

Every report run is snapshotted, so the next one can answer the only question anybody asks on a Monday:

```
$ icsmatch diff refinery-north
refinery-north: 2026-08-31T06:12:04+00:00 -> 2026-09-05T06:09:41+00:00
  new       3
  resolved  7
  changed   1

  + [NOW  ] PLC-014      ICSA-26-241-02     T1
  - HIST-400     ICSA-23-017-01
  ~ RTU-200      ICSA-25-114-01     NEXT -> NOW
```

## VEX export

A triage decision is only useful once it leaves the tool. `icsmatch vex` emits an [OpenVEX](https://openvex.dev) 0.2.0 document: `affected`, `not_affected` with one of the five standard justifications, or `under_investigation`, each carrying the basis string that produced it.

```bash
icsmatch vex --assets plant.csv --author "OT Security" --out plant.vex.json
```

One CVE hitting six assets the same way becomes one statement listing six products, not six near-identical statements.

## Prioritisation

Not CVSS order. The decision is a small tree in the shape of the CISA SSVC deployer tree, walked with four inputs:

| Decision point | Derived from |
|---|---|
| Exploitation | CISA KEV listing → active. EPSS at or above the cutoff → public PoC. Otherwise none. |
| Exposure | Purdue level. 0 and 1 → small. 2 and 3 → controlled. 3.5, 4, 5 and DMZ → open. Blank → controlled. |
| Utility | CVSS 4 `AU:Y`, or a CVSS 3 network vector needing no privileges and no user interaction → efficient. |
| Human impact | CVSS band, stepped up one level at Purdue 0 and 1 when the score is 7 or higher or the CVSS 4 safety metric is present. |

The tree then yields immediate, out-of-cycle, scheduled or defer, which map to **NOW, NEXT, NEXT, LATER**. Anything not already NOW with no vendor patch is moved to **TRACK**, because it cannot be scheduled into a patch window and needs a compensating control instead.

So confirmed exploitation of a low-impact bug on an isolated asset is out-of-cycle, not immediate. And EPSS above the cutoff on a critical-severity bug goes to immediate only if the asset is also openly exposed; on an isolated asset it is out-of-cycle. The threshold ladder most tools use cannot express either.

Every row carries the vector that produced it:

```
SSVCv2/E:N/X:S/U:E/H:V/D:S
```

**What that vector is and is not.** Exploitation, exposure and utility are populated from real signals. Human impact is a default derived from CVSS and Purdue level, because nobody at the tool's end has assessed safety or mission consequence for your site, and SSVC defines that decision point as exactly that assessment. Treat `H:` as a placeholder to override, not a finding. The vector is emitted so an analyst can see which branch fired and disagree with it.

Dragos's 2026 year in review press release (17 February 2026) reports that only 2% of ICS-relevant vulnerabilities warranted immediate action, that 25% of ICS-CERT and NVD entries carried an incorrect CVSS score in 2025, and that 26% of advisories shipped with no patch or mitigation. Dragos's own blog gives slightly different figures (3% immediate, 25% no patch), so treat these as approximate. Severity alone is a poor sort key; confirmed exploitation is a much better one.

FIRST is explicit that no universal EPSS threshold exists, so the 10% cutoff is a documented default, not a law. Change it if your risk appetite differs.

## Speed

Matching runs against a prebuilt index, not a full scan. Each asset does a handful of dict lookups instead of touching every product in the corpus.

Benchmarked on a 27,664-product corpus, same machine, with `icsmatch bench`:

| Assets | Before | After |
|---:|---:|---:|
| 1,000 | 38.8 s | 1.0 s |
| 5,000 | 3 min 9 s | 5.3 s |

Both columns are measured end to end, not extrapolated: **38.77 ms per asset down to 1.04 ms**, about 37x. The index costs 0.14 s to build and is shared across every inventory in a `--all-clients` run.

`rapidfuzz` accelerates the fuzzy tier when installed. Without it the tool falls back to `difflib` and still works, which matters on a workstation with no package index access.

```bash
icsmatch bench --assets examples/sample_inventory.csv --sizes 100 1000 5000
```

## Accuracy

Matching quality is measured, not asserted, and the label set is built so the tool can fail it.

```bash
icsmatch eval --assets examples/eval_inventory.csv \
              --labels examples/labels/sample_labels.csv
```

How the labels were made matters more than the numbers. The positive labels were seeded from the tool's own tier 1 to 3 output and then hand-checked, so on those pairs tier 3 can only confirm itself. The negatives are different: 36 came from hand-reviewing tier 4 and 5 output and rejecting it, and 13 are adversarial cases written by reading the advisory ranges directly. The same PLC with firmware 9.9.9 against seven advisories whose fixes all land below 4.7. A MicroLogix 1400 against MicroLogix 1100 advisories. Each of those was a false positive in an earlier build.

Against 139 labelled pairs:

| Cutoff | Precision | Recall | F1 |
|---|---:|---:|---:|
| tier <= 1 | 1.000 | 0.096 | 0.175 |
| tier <= 3 | **1.000** | 0.777 | 0.874 |
| tier <= 4 | 0.813 | **0.926** | 0.866 |
| tier <= 5 | 0.710 | 0.989 | 0.827 |

Read the tier 3 row as "holds against every negative we could construct", not as a general precision figure. Tier 4 trades precision for recall by design, which is why it routes to a human instead of a report. `--min-precision` fails a build when a normalisation change starts inventing matches.

The set is small and inventory-specific. It is a regression guard. Contributing labelled pairs from a real inventory, with identifiers stripped, is the most useful thing you can do for it.

## What the corpus looks like

Run it yourself with `icsmatch coverage --source ./CSAF/csaf_files`.

Across **27,384** version-range strings:

| Format | Share | Example |
|---|---:|---|
| Bounded comparator | 61.22% | `<V2.9.7`, `vers:intdot/>=3.0\|<3.0.2` |
| All versions | 22.97% | `vers:all/*` |
| Exact pin | 8.21% | `R15B_PC4` |
| **Unparseable** | **7.56%** | see below |

**Parser coverage: 92.44%**, and the remaining 7.56% is refused on purpose:

```
<=The_first_5_digits_of_serial_No._"26061"     serial number, not a version
distributed  < april 1, 2018                   date-based constraint
<= 3.4.4 Build 16102416                        build-qualified
< V15.1 Upd 4                                  service-pack qualifier
```

These are not parser bugs. They are advisories that cannot be mechanically evaluated against an inventory, and pretending otherwise would produce confident wrong answers. `icsmatch` surfaces them as `UNKNOWN` with the reason attached.

## Commands

```
icsmatch update    --source PATH      ingest CSAF JSON into the local database
icsmatch search    QUERY              FTS5 full-text search over the corpus
icsmatch match     --assets CSV       match inventory, print findings
icsmatch report    --assets CSV       render a markdown triage report
icsmatch report    --all-clients DIR  one report per inventory plus a rollup
icsmatch diff      LABEL              what changed since the previous run
icsmatch vex       --assets CSV       export findings as OpenVEX
icsmatch review    --assets CSV       adjudicate fuzzy matches, decisions persist
icsmatch aliases                      export analyst-confirmed aliases
icsmatch eval      --labels CSV       precision and recall against labelled pairs
icsmatch bench     --assets CSV       matching throughput
icsmatch stats                        corpus statistics and identifier coverage
icsmatch stats     --by-year          identifier coverage broken out by year
icsmatch coverage  --source PATH      version-range parser coverage report
```

Useful flags: `--max-tier N` (drop weak matches), `--priority NOW NEXT`, `--json` (structured output), `--offline` (cached KEV and EPSS only).

## Design notes

**Why SQLite.** One file, no server, works on a locked-down analyst workstation with no egress. The full corpus is about 40 MB and FTS5 search returns in about a millisecond. Search input is escaped as FTS5 phrases, so `S7-1200` and `allen-bradley` are queries rather than syntax errors.

**Why stdlib-only core.** `rapidfuzz` and `PyYAML` are optional extras with graceful fallbacks. An OT engineering workstation frequently has no package index access.

**Why not a web UI.** This is analyst tooling. It composes with `grep`, `jq`, cron and CI. A dashboard would be a different project.

**What this is not.** Not a replacement for Claroty, Dragos, Nozomi or Tenable OT. Those do passive network discovery and build the inventory in the first place. `icsmatch` takes an inventory you already have and answers one narrow question well.

## Limitations

- Asset inventories are only as good as their last update. Stale inventory in, stale findings out.
- Tier 4 and 5 findings are leads, not conclusions.
- No compliance-framework mapping ships yet. NCA OTCC and IEC 62443 control references are planned once they can be verified against the published standards.
- Only CISA CSAF is ingested today. Siemens ProductCERT and the CERT@VDE aggregator are the next targets.
- The labelled evaluation set covers one inventory. Precision on your data will differ.

## Prior art

The BSI-funded [DINA-community](https://github.com/DINA-community) is working the same problem from the other end. [String-Sisyphos](https://github.com/DINA-community/String-Sysiphos) publishes normalisation word-books for CSAF and OT assets and is cited in the CISA and NSA joint guide on OT asset inventory, and [Matching-Agent](https://github.com/DINA-community/Matching-Agent) is a CSAF-to-asset matching service with NetBox and ISDuBA integration. Their infrastructure is further along than this tool's; their matcher is still marked work in progress. Vendor alias contributions are useful to both projects.

## Contributing

The highest-value contribution is **vendor aliases**, then **labelled pairs**, then **version formats** that land in the unparseable bucket. See [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
git clone https://github.com/lamaAlshuhail/icsmatch && cd icsmatch
pip install -e ".[dev]"
pytest -q && ruff check src tests && mypy src
```

## Write-up

**[Why CPE Doesn't Work for OT](docs/why-cpe-doesnt-work-for-ot.md)**, the measurement behind this tool: CPE coverage by year, version-range format distribution, and why refusing to answer is a feature. Every figure reproducible with `icsmatch stats` and `icsmatch coverage`.

## References

- [CISA CSAF advisory repository](https://github.com/cisagov/CSAF)
- [OASIS CSAF 2.0 specification](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html), which defines the *CSAF asset matching system* conformance target
- [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [FIRST EPSS](https://www.first.org/epss/)
- [CISA SSVC](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc)
- [OpenVEX specification](https://github.com/openvex/spec)
- T. Limmer (Siemens AG) and M. Pfurtscheller (u-blox), *Experiences in Consuming CSAFs & what is still missing?*, CSAF Community Days 2024

## License

MIT
