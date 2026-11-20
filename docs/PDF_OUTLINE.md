# Submission PDF Outline

The scoring rubric has six criteria, each worth 10 points, and five of the six are judged from
this document (only "Demonstration of prototype" is about the running code) - likely by an AI
reviewer first pass. **Use these exact headings, in this order**, so an automated reviewer can
match them directly. Write every claim as plain text even where you also include a diagram -
diagrams can be missed by an AI reviewer, so caption each one with a short paragraph restating
what it shows.

## 1. Problem overview and relevance to cybersecurity

- Manual malware triage is slow; SOCs (in Azerbaijan and globally) are short of trained
  analysts.
- Samples frequently can't be uploaded to public sandboxes/VirusTotal by banks, government
  bodies and telecoms - that's a confidentiality leak, not just a policy preference.
- Azerbaijan context: name the actual stakeholders your tool serves (bank SOC, CERT.AZ,
  university security programs, SMEs with no dedicated SOC budget).

## 2. Proposed solution and purpose

One sentence: *Gözətçi is an offline static-triage tool that takes a suspicious Windows file
and returns, in seconds, an explained risk score, MITRE ATT&CK mapping, extracted IOCs, and a
bilingual (AZ/EN) report - without the file ever leaving the analyst's machine.*

Then: who it's for (SOC analyst doing first-pass triage; a university or SME with no SOC at
all; a national CERT wanting standardized STIX/MISP-ready output).

## 3. Conceptual design and system approach

- Paste the architecture diagram from `docs/ARCHITECTURE.md` (both the current pipeline and
  the planned sandbox/dashboard capstone extension) and explain each stage in a short
  paragraph: hashing → PE parsing → strings → IOC extraction → YARA → ATT&CK mapping → explained
  score → report.
- Include the JSON schema (from the root `README.md`) - this is your evidence that the design
  is a real contract between modules, not a demo stitched together at the last hour.
- State the offline-first decision explicitly and why (see "Problem overview").

## 4. Prototype demonstration

- Screenshots: the upload screen, a "Clean" verdict on `clean_sample.exe`, a "Malicious"
  verdict on `synthetic_suspicious.exe` with the reasons list expanded, the AZ-language toggle,
  the YARA matches panel, an exported STIX JSON snippet.
- Repo link, and exact run instructions (copy from the root `README.md` "Running it" section).
- State plainly that `backend/tests/test_pipeline.py` is a repeatable, automated check that the
  tool does not false-positive on a real clean Windows binary - this is the single most
  convincing correctness evidence you have; don't bury it in an appendix.

## 5. Key features, limitations, next steps

**Features** (use this list, it maps directly to what's implemented):
- Hashes (MD5/SHA1/SHA256/imphash), section entropy with packer detection, anomaly checks
  (future/zero timestamps, TLS callbacks, no-imports, memory-inflated sections)
- Both ASCII and UTF-16LE ("wide") string extraction
- IOC extraction with defanging, private-IP separation, TLD validation, and false-positive
  filtering (version-number lookalikes, known-benign vendor/schema domains)
- YARA scanning, including an Azerbaijan-specific pack (lure keywords, look-alike
  `.gov.az`/bank infrastructure strings)
- Confidence-weighted MITRE ATT&CK technique mapping
- An **explained** 0-100 risk score - every point has a stated reason
- Bilingual (Azerbaijani/English) HTML reports, JSON export, and a minimal STIX 2.1 export for
  MISP/TheHive ingestion

**Limitations** (state these honestly - judges trust teams that do):
- Static analysis only; a sufficiently motivated packer/obfuscator defeats it.
- Windows PE files only - no ELF/Mach-O, no macro/script-based malware.
- No sandbox/behavioral analysis in this build.
- The domain TLD list is a curated subset, not the full IANA root zone.
- Heuristic weights (ATT&CK confidence tiers, anomaly scores) are hand-tuned against two
  samples in 24 hours, not validated against a large malware corpus.

**Next steps** = your capstone plan: CAPEv2 (or similar) sandbox for dynamic analysis, mutex
and registry/network IOC extraction at runtime, an analyst case queue and dashboard, TheHive
and MISP integration, ISO 27001:2022 evidence-trail tooling built on the hashes/timestamps this
tool already produces (controls 5.25-5.26 assessment/response, 5.28 evidence collection).

## 6. Feasibility and potential impact

- Fully open-source stack (Python/FastAPI/pefile/yara-python/React/Tailwind), runs on a single
  laptop, no paid sandbox/triage platform licensing - name actual commercial-alternative price
  points if you have them.
- **Time your own manual triage of one sample** (stopwatch, same sample the tool analyzes) and
  report your real numbers against the tool's seconds-scale output. Use your measured numbers,
  not invented ones - this is the single most concrete "impact" evidence available to you in 24
  hours.
- Compliance angle: hashes + timestamped reports function as an evidence trail; connect
  explicitly to ISO 27001:2022 controls 5.25-5.26 and 5.28 if your team has GRC background to
  speak to it credibly.

---

### Mechanical reminders

- Invite Event Managers and Instructors to the GitHub repo in hour 1 - it's mandatory and easy
  to forget.
- An AI reviewer looks for headings that match the rubric wording - don't get creative with the
  section titles above.
- Keep this PDF shorter than you think it needs to be; dense plain-text claims under the right
  heading beat a long narrative.
