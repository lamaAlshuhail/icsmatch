# Why CPE Doesn't Work for OT

*What I found parsing 16 years of CISA ICS advisories.*

---

There is a question every OT security analyst asks when a new advisory lands:

> Does this affect anything I own?

In IT, the machinery for answering it is mature. NVD publishes CVEs with CPE strings, your scanner reports CPE strings, you join on CPE, done. It is not elegant, but it works often enough that an entire vulnerability-management industry is built on top of it.

I assumed OT worked roughly the same way, with more vendors and worse tooling. So before writing a matcher, I measured.

I pulled the complete CISA CSAF corpus, **4,021 advisories, 27,664 products, 12,542 CVEs, spanning 2010 to 2026**, and counted how many products carry an identifier you can match on.

| Identifier | Products | Share |
|---|---:|---:|
| **CPE** | 28 | **0.10%** |
| **Model / order number** | 8,141 | **29.43%** |

Twenty-eight. Out of twenty-seven thousand six hundred.

CPE is not a weak signal in OT advisory data. It is functionally absent, 291 times rarer than the vendor's own model number.

## This is not a backlog problem

My first assumption was that CPE coverage was a legacy artifact: old advisories lack it, newer ones have it, give it time. So I broke it out by year.

| Year | Products | With CPE | With model number |
|---|---:|---:|---:|
| 2020 | 1,673 | 0.00% | 27.5% |
| 2021 | 2,229 | 0.00% | 27.4% |
| 2022 | 4,213 | 0.00% | 50.6% |
| 2023 | 3,423 | 0.00% | 36.1% |
| 2024 | 3,340 | 0.06% | 34.8% |
| 2025 | 3,925 | 0.18% | 20.6% |
| 2026 | 3,124 | 0.61% | 34.4% |

CPE adoption is real and it is rising. It is also, in 2026, still under one percent.

If you are building an OT matcher that joins on CPE, you are building for a world that does not exist yet and may never arrive. Meanwhile model numbers held 21 to 51% coverage across the same period, never once dipping near CPE's range.

## Why the gap exists

Siemens said it plainly at [CSAF Community Days 2024](https://www.csaf.io/events/community-days/2024/):

> CPE is not a solution for us → approach for Siemens: use order numbers

CPE was designed to name software: a vendor, a product, a version, on a platform. OT assets do not decompose that way. A `6ES7214-1AG40-0XB0` is a specific S7-1200 CPU variant, DC/DC/DC, specific I/O count, specific memory. There is no CPE that expresses it, and the difference matters, because the advisory may affect one variant and not its neighbour.

The same talk notes a second problem: *"single asset scan usually not sufficient (devices do not identify themselves, e.g. due to hardening)."* The hardening you did to protect the PLC is the reason your scanner can't fingerprint it.

So the data has the vendor's own part number, and the standard has no field that respects it.

## Then the version ranges

Matching a product is half the job. The other half is deciding whether *your* version falls in the affected range. I extracted all **27,384** version-range strings and looked at what they contain.

| Format | Share | Example |
|---|---:|---|
| Bounded comparator | 61.22% | `<V2.9.7`, `vers:intdot/>=3.0\|<3.0.2` |
| All versions | 22.97% | `vers:all/*` |
| Exact pin | 8.21% | `R15B_PC4` |
| **Not machine-parseable** | **7.56%** | see below |

Three-quarters is clean and mechanically evaluable. The `vers:` scheme (OASIS's versioning URI) shows up on a quarter of ranges and is good.

Then there is the tail. These are all real strings from real advisories:

```
<=The_first_5_digits_of_serial_No._"26061"
distributed  < april 1, 2018
<= 3.4.4 Build 16102416
< V15.1 Upd 4
>=V2.3_and_<V6.30.016
<= 15.2(6)E0a
<BIOS_V1.0.212N
NMC2 <= 6.9.6
```

A serial number prefix. A calendar date. A build identifier. A service-pack qualifier. A component-scoped version where the constraint applies to the BIOS, not the product.

`packaging.version` parses none of these. Neither does anything else off the shelf, because they aren't versions in the sense any versioning library means.

## The design decision that follows

Here is where it gets interesting, and where I think most tooling gets it wrong.

When your parser hits `<=The_first_5_digits_of_serial_No._"26061"`, you have three options:

1. **Guess.** Extract `26061`, treat it as a version, compare numerically. Produces an answer. The answer is meaningless.
2. **Return "not affected."** Clean, quiet, and it silently marks the asset safe on the basis of a string you could not read.
3. **Return "I don't know," with the reason.**

Option 2 is the dangerous one, and it's the seductive one, because it makes your coverage numbers look excellent and your report look tidy.

I went with option 3. In `icsmatch`, `contains()` returns `None`, not `False`, whenever the range is unparseable, and the finding surfaces as `UNKNOWN` with the reason attached:

```
🟡 PLC-100  ICSA-23-026-06  CVSS 9.8  T3
   vendor+product match but version range '28  - 32' unparseable
   (no recognisable constraint)
```

An analyst sees that in ten seconds and makes a call. Compare it to the alternative, where that asset never appears and nobody ever learns it was skipped.

Refusing to answer is a feature. The parser reaches **92.44% coverage**, and I would rather ship that number than 100% built on guesses.

## What matching should key on instead

If CPE is absent and 7.56% of ranges are prose, what do you match on? I ended up with a tiered cascade, ordered by how much the evidence deserves to be trusted:

| Tier | Basis | Confidence | Verdict |
|:---:|---|---:|---|
| 0 | Analyst-confirmed alias | 1.00 | AFFECTED |
| 1 | Model / SKU exact match | 1.00 | AFFECTED |
| 2 | CPE exact match | 0.95 | AFFECTED |
| 3 | Canonical vendor + product, version in range | 0.85 | AFFECTED |
| 4 | Fuzzy product match | ~0.50 | **REVIEW** |
| 5 | Vendor match only | 0.30 | MANUAL |

CPE sits at tier 2, below model number. That ordering is not a philosophical position about standards. It is what the data says: 0.10% versus 29.43%.

Two rules fall out of it.

**Tier 4 never auto-asserts.** A fuzzy hit goes to a human, never to a report as confirmed. A false "you're affected" costs analyst hours and credibility; a flagged "verify this" costs one glance. The asymmetry is enormous and should be encoded in the tool, not left to the reader.

Here is a real one from my test inventory:

```
asset    : Siemens / SCALANCE X208
advisory : Siemens / SCALANCE XF208
ratio    : 0.89
```

`X208` and `XF208` are different products. A 0.89 token-set ratio does not know that. A human knows it instantly.

**Every finding states its basis in plain text.** Not a score, a sentence:

```
model/SKU '6ES7214-1AG40-0XB0' matches advisory identifier '6ES7214-1AG40-0XB0'
vendor+product match; asset version R15A satisfies =R15A
fuzzy product match 'SCALANCE X208'~'SCALANCE XF208' (ratio 0.89); <V5.2.5
```

If an analyst cannot audit a finding without opening the source JSON, the tool has failed.

## The part that surprised me: the analyst's answer is thrown away

The `X208` / `XF208` question has an answer. Someone at the plant knows it. And in every tool I looked at, once they answer it, the answer evaporates, the same fuzzy match resurfaces on the next advisory and gets triaged from scratch.

That's the actual expensive part of triage, and it's the part nobody persists.

So `icsmatch review` records the decision keyed on `(vendor, asset_product, advisory_product)` rather than on advisory ID, which means one decision generalises to every advisory naming that product. Confirm it once, and it comes back as tier 0 forever:

```
[NEXT] SW-021  ICSA-21-103-07  CVSS 9.8  T0
   analyst-confirmed alias 'SCALANCE X208' = 'SCALANCE XF208'
   by L.Alshuhail on 2026-08-25; <V5.2.5
```

Reject it once and it's suppressed forever. The tool converges on the inventory it is pointed at.

One deliberate constraint: confirming product identity does **not** confirm the version. The range still has to hold independently. Conflating those two would let one careless click mark an asset affected across every future advisory.

## While I was in there: two bugs worth naming

**Vendor splitting.** My first canonicalizer stripped `Electric` but not `Software, LLC`, so `Schneider Electric` became `schneider` while `Schneider Electric Software, LLC` became `schneidersoftware`. That silently split one vendor across two keys and orphaned 197 products. The fix was three words in a regex. Finding it required looking at raw vendor strings sorted by frequency, which is to say, it required not trusting my own normalizer.

**Component-scoped versions.** `<BIOS_V1.0.212N` is not a constraint on the product. It's a constraint on the BIOS. If your inventory tracks firmware version separately from BIOS version, and any decent OT inventory does, then comparing a BIOS constraint against a firmware column is a category error that produces confident wrong answers. `icsmatch` extracts the component as metadata and keeps it attached to the version.

Neither bug was visible from reading the spec. Both were visible immediately from reading the data.

## The prioritisation problem, briefly

Once you have findings you have to rank them, and the default, sort by CVSS descending, is wrong in a way that's now well documented.

Dragos's 2026 ICS/OT review found only ~2% of ICS-relevant vulnerabilities warranted immediate action, and that ~25% of ICS-CERT/NVD entries carried an incorrect CVSS score in 2025. SynSaber found that ~35% of ICS CVEs in one half-year window had no vendor patch at all, "forever-day" issues where a patch window is not the answer and network segmentation is.

CVSS measures theoretical severity in isolation. It does not know whether anyone is exploiting the thing, and it does not know whether the asset sits at Purdue Level 1 behind three firewalls or in the Level 3.5 DMZ.

So `icsmatch` sorts on exploitation first:

```
CVE in CISA KEV              → NOW    (confirmed exploitation in the wild)
EPSS ≥ 10% and CVSS ≥ 7.0    → NOW
CVSS ≥ 9.0                   → NEXT   (escalated if Purdue ≥ 3)
no vendor patch available    → TRACK  (compensating controls only)
CVSS ≥ 7.0                   → NEXT
otherwise                    → LATER
```

`TRACK` exists as its own bucket specifically because "no patch" is not a low-severity condition, it's a *different kind* of work.

## What I'd tell someone starting this

**Measure the corpus before you design the schema.** I nearly wrote a CPE-joining matcher. Two hours of counting saved me from building the wrong thing entirely.

**Refuse to answer more often.** Coverage numbers built on guesses are worse than gaps, because gaps are visible and guesses aren't.

**Persist human judgement.** It's the most expensive input in the pipeline and the one universally discarded.

**Read the raw strings.** Every real bug I found came from sorting actual data by frequency and looking at it, not from reading the specification.

---

## Reproduce it

Every number here is reproducible in about five minutes:

```bash
git clone --depth 1 https://github.com/cisagov/CSAF.git
pip install icsmatch
icsmatch update --source ./CSAF/csaf_files
icsmatch stats                                 # identifier coverage
icsmatch stats --by-year                       # the table above
icsmatch coverage --source ./CSAF/csaf_files   # version-range formats
```

Code: [github.com/lamaAlshuhail/icsmatch](https://github.com/lamaAlshuhail/icsmatch) · MIT

The most useful contribution is vendor aliases. If your inventory spells a vendor differently than the advisories do, that's a real gap in `data/normalizers.yaml` and a two-line PR.

---

## Sources

- [CISA CSAF advisory repository](https://github.com/cisagov/CSAF), the corpus, 2010–2026
- T. Limmer (Siemens AG) and M. Pfurtscheller (u-blox), *Experiences in Consuming CSAFs & what is still missing?*, [CSAF Community Days 2024](https://www.csaf.io/events/community-days/2024/)
- [OASIS CSAF 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html), defines the *CSAF asset matching system* conformance target
- [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [FIRST EPSS](https://www.first.org/epss/)
- Dragos ICS/OT Cybersecurity Year in Review; SynSaber ICS Vulnerability reports
