# 24-Hour Timetable

## Where you're starting from

A working MVP already exists in this repo: FastAPI backend (PE parsing, strings, YARA incl.
an Azerbaijan pack, IOC extraction with false-positive filtering, ATT&CK mapping, an explained
0-100 score), a React+Tailwind frontend wired to it, two safe demo samples, and a pytest smoke
suite that already catches the single biggest risk - a clean Windows binary scoring as
"Malicious". That means you are **not** starting hour 0 from an empty repo: treat the plan
below as "harden, extend, document, rehearse," not "build from scratch."

Start your real 24-hour clock the moment your team sits down together. Adjust the hours below
to that start time.

**Note**: this machine doesn't have Git installed yet, so the repo hasn't been initialized.
Hour 0 for whoever owns the repo should be: install Git, `git init` in the project root,
create the GitHub repo, push, then invite Event Managers and Instructors immediately.

## Hour-by-hour

| Hour | What happens | Who |
|---|---|---|
| 0-1 | Kickoff. Fork/clone this repo, **invite Event Managers and Instructors to the GitHub repo now** (easy to forget, mandatory), agree the scope, assign roles below | All |
| 1-2 | Everyone gets `backend` running (`uvicorn ... --reload`) and `frontend` running (`npm run dev`) locally and confirms the two demo samples work end to end. Read `README.md` and the JSON schema together so nobody duplicates work | All |
| 2-8 | Parallel build (see roles below) | Split |
| 8-9 | **Integration checkpoint 1**: run both demo samples through the full pipeline in the UI, even if a feature is half-done elsewhere | All |
| 9-14 | Differentiators: STIX/MISP export polish, more Azerbaijan YARA rules (real local bank/ministry names you're authorized to reference generically, more lure-keyword coverage), a second synthetic sample exercising packer/entropy detection, HTML report polish | A/B/C |
| 14-16 | Rest in rotation, two people at a time, 45-60 min each. A tired team gives a weak demo | - |
| 16-19 | Test on all samples, fix false positives (re-run `pytest tests -v` after every change), polish UI. **No new features after hour 19** | A/B/C |
| 19-22 | Finish the PDF (`docs/PDF_OUTLINE.md`), screenshots, architecture diagram, README polish, record a backup demo video | D + C |
| 22-23 | Rehearse the pitch twice with a timer. Prepare answers to likely judge questions (see below) | All |
| 23-24 | Upload the PDF, check repo access for judges, tag a release (`git tag v0.1-hackathon`), final demo dry-run | All |

## Team roles (4 people; with 3, merge D across everyone)

| Role | Owns | Starting point in this repo |
|---|---|---|
| A - Static engine | PE parsing, entropy, imports, anomalies | `backend/app/pe_analysis.py` |
| B - Detection & IOCs | YARA rules/scanner, strings, IOC extraction | `backend/app/yara_scan.py`, `ioc_extract.py`, `backend/rules/` |
| C - Integration & UI | Scoring, API, React frontend, reports | `backend/app/scoring.py`, `main.py`; all of `frontend/` |
| D - Docs & pitch | PDF, architecture diagram, demo script, slides, backup video | `docs/` |

## Why documentation starts in hour 2, not hour 20

Five of the six judging criteria are read from your PDF, which is reviewed by an AI first pass.
Only "Demonstration of prototype" is about the running code. Assign one person (role D) to
start writing the moment the architecture is agreed - don't wait for the build to "be ready."

## Likely judge questions to rehearse answers for

- "What stops this from being trivially evaded by a packer?" (Answer honestly: nothing fully
  does at the static layer - that's why the roadmap adds a sandbox. Entropy/packer signatures
  catch the common case, not a determined adversary.)
- "How do you avoid false positives on legitimate software?" (Point directly at
  `clean_sample.exe` and the pytest check - have this ready to run live.)
- "Why not just use VirusTotal?" (Confidentiality - a bank/government body cannot upload a
  suspicious attachment to a third party; this runs fully offline.)
- "What's the capstone scope beyond today?" (Sandbox, dashboard, MISP/TheHive - see
  `docs/ARCHITECTURE.md`.)
