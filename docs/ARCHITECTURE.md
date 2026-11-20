# Architecture

## Current (hackathon MVP - static triage only)

```
                    ┌─────────────────────────────┐
                    │   React + Tailwind frontend │
                    │  (upload / demo samples,    │
                    │   score, IOCs, AZ/EN toggle)│
                    └──────────────┬──────────────┘
                                   │ HTTP (multipart file, JSON in/out)
                                   ▼
                    ┌─────────────────────────────┐
                    │        FastAPI backend       │
                    │                               │
   file bytes  ───► │ 1. hash (md5/sha1/sha256)     │
                    │ 2. pefile: sections, imports, │
                    │    anomalies, imphash         │
                    │ 3. strings: ASCII + UTF-16LE   │
                    │ 4. IOC extraction + defang +   │
                    │    FP filtering (allowlists,   │
                    │    TLD check, version-lookalike)│
                    │ 5. YARA scan (generic +        │
                    │    azerbaijan rule packs)      │
                    │ 6. ATT&CK mapping (confidence-  │
                    │    weighted by API combo)      │
                    │ 7. explained 0-100 score        │
                    │ 8. report render (JSON/HTML,    │
                    │    AZ/EN; STIX built client-side)│
                    └─────────────────────────────┘
```

Every stage in the backend is independent and defensive: if `yara-python` isn't installed, or
the file isn't a valid PE, or `pefile` throws, the rest of the pipeline still runs and returns a
report - it just has fewer findings. This matters because judges' machines may not have a C
compiler to build `yara-python` from source, and a competitor sample may be malformed on
purpose.

**Data flow / JSON contract**: see the JSON report shape in the root `README.md`. All modules
write into this one shared structure, which is what let four people build in parallel without
integration fights.

## Planned (capstone - the hackathon's "next steps" section)

```
┌──────────────┐     ┌────────────────────┐     ┌──────────────────────┐
│  Static engine│────►│   Sandbox (CAPEv2   │────►│  Unified case record  │
│  (this repo)  │     │   or similar) for    │     │  - static + dynamic   │
│               │     │   dynamic/behavioral │     │    findings merged    │
└──────────────┘     │   analysis: process,  │     └──────────┬───────────┘
                      │   registry, network   │                │
                      │   IOCs at runtime     │                ▼
                      └────────────────────┘     ┌──────────────────────┐
                                                   │  Analyst dashboard +  │
                                                   │  case queue           │
                                                   └──────────┬───────────┘
                                                                │
                                          ┌─────────────────────┴────────────────┐
                                          ▼                                       ▼
                                 ┌─────────────────┐                   ┌──────────────────┐
                                 │ TheHive (cases)  │                   │ MISP / STIX feed  │
                                 │                  │                   │ → shared with      │
                                 └─────────────────┘                   │ CERT.AZ / SOC peers │
                                                                         └──────────────────┘
```

The static engine built today becomes the first, always-on stage of that pipeline - samples
that score low can skip the (expensive, slow) sandbox entirely, which is itself a real
cost-saving argument for the capstone pitch.

## Key design decisions worth stating explicitly in the PDF

- **Offline-first**: no stage of the pipeline makes a network call. This is the headline
  differentiator for the Azerbaijan market (confidentiality for banks/government/telecoms).
- **Explained scoring over a bare number**: every point in `score.reasons` traces back to a
  specific signal (a YARA rule, an ATT&CK combo, an anomaly, an IOC count) - this is what makes
  the tool usable by an analyst, not just a black box.
- **False-positive discipline**: known-benign domain suffixes, a version-number-lookalike IP
  filter, and confidence-tiered ATT&CK weighting all exist specifically because the first build
  of this pipeline scored a stock Windows system binary as 94/100 "Malicious." That bug and its
  fix are the single most important integration-test story in the demo.
