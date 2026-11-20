# Demo Script (~3 minutes)

Rehearse this twice with a timer before the real pitch. Have a backup screen-recording of this
exact flow ready in case live demo breaks.

**1. The story (20 seconds)**

> "It's 2 AM. A bank SOC in Baku gets a suspicious email attachment. They can't upload it to
> VirusTotal - that would leak a potential breach indicator to a third party, and for a bank
> that's itself a confidentiality incident. They need an answer now, on their own machine."

**2. Load the suspicious sample (30 seconds)**

- Click the "Suspicious binary" demo button (or drag in a prepared packed sample).
- Report appears in seconds. Point at the score badge first: **100/100, Malicious.**

**3. Walk through the explained score (45 seconds)**

- Open "Why this score" - read two or three lines aloud, e.g. *"+30 YARA:
  Suspicious_Process_Injection_Imports, +30 ATT&CK T1055 Process Injection."*
- This is the headline differentiator: *"We don't just show a number - every point has a
  reason, so an analyst can actually act on it."*
- Point at the ATT&CK panel and the YARA matches panel, including the Azerbaijan-specific
  rule hit (look-alike `.gov.az`/bank infrastructure string, AZ lure keywords).

**4. IOCs and language toggle (30 seconds)**

- Show the defanged URL/IP/domain list (`hxxp://...`, `185[.]...`).
- Click the AZ toggle - UI and labels switch to Azerbaijani live.
- Click "Export STIX 2.1" - show the downloaded JSON briefly: *"This is ready to feed into MISP
  or TheHive for a national CERT."*

**5. Prove there's no false alarm (30 seconds)**

- Click "Clean binary" (a real Windows system binary).
- Score: **12/100, Clean.** Say explicitly: *"This is the check that matters most to judges and
  to SOC analysts - a tool that cries wolf gets ignored. We have an automated test for exactly
  this."*

**6. Close with the roadmap (15 seconds)**

- One slide: sandbox execution, analyst dashboard, MISP/TheHive integration - *"Today's build is
  the always-on first stage of that pipeline; this is the capstone."*

## If something breaks live

Switch immediately to the backup video. Don't debug on stage.
