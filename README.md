# Equifax vulnerability assurance prototype (IS4234 Group 20)

A Streamlit demonstrator for Section 4 of the report. It replays March 2017 with synthetic data: the Apache Struts advisory (CVE-2017-5638) arrives at 06:10 on 8 March, and every screen shows what the proposed controls would have done. All rules are enforced in `engine.py`; the interface only calls it.

## Run locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

Python 3.10 or later. No login, database or test account is needed; state lives in the browser session and resets on refresh or with **Reset this step**.

## Host on Streamlit Community Cloud

1. Push this folder to a public GitHub repository (keep `.streamlit/config.toml`).
2. At share.streamlit.io choose **Create app**, pick the repository and set the main file to `app.py`.
3. Optional Claude mode for the compliance assistant: in the app's **Settings > Secrets** add
   ```toml
   ANTHROPIC_API_KEY = "your-key"
   ANTHROPIC_MODEL = "claude-haiku-5-5"
   ```
   Without a key the assistant runs in grounded retrieval mode, which is deterministic and safest for a live demo.
4. Submit the app URL in the demonstrator guide.

## Presenting

The sidebar holds everything the presenter needs:

- **Demo step** loads a preset. Each preset replays a scripted timeline through the real engine up to a cut-off, then you can act live. Other owners keep working on schedule as you move the clock.
- **Acting as** switches persona. Permissions follow the persona, so you can show a control blocking the wrong person.
- **Clock**: +1 h, +4 h, +1 day, **Jump to next escalation or alert**, and **Run daily recalculation now** (the risk job normally runs at 02:00).
- **Presenter notes** shows a short prompt on each page for the loaded step.

Deep links open a step directly, which is handy for preparing one browser tab per speaker:
`https://<your-app>/tracker?step=s7&as=aisha` (add `&notes=off` to hide notes).

| Step | Key | What to show | Page | Persona |
|---|---|---|---|---|
| 1. Baseline | `s1` | Reconciliation finds an unregistered host; ingest the advisory live | Alert allocator | Helen Park |
| 2. Advisory arrives | `s2` | Three P1 tasks to named owners; none of the unknowns treated as safe | Alert allocator | Daniel Reyes |
| 3. 4-hour escalation | `s3` | Owner silent, line manager and deputy escalated | Resolution tracker | Marcus Bell |
| 4. 24-hour escalation | `s4` | Acknowledged but no decision, CIO's delegate escalated | Resolution tracker | Helen Park |
| 5. Evidence rejected | `s5` | Clean scan that excluded the portal is refused by the backend | Resolution tracker | Daniel Reyes |
| 6. Assistant | `s6` | Cited answers with case facts; cannot act; refers conflicts | Compliance assistant | Daniel Reyes |
| 7. Verification | `s7` | Owner and untrained reviewer blocked; independent reviewer closes it; run the daily job: US$1.5m to US$500k | Tracker, then Risk calculator | Aisha Rahman |
| 8. Patched but blind | `s8` | Inspection certificate expired: monitoring red, estimate back up to US$1.0m | Control health | Sam Ortiz |
| Branch A | `a` | Time-limited exception: reviewed, approved by a different person, still open | Resolution tracker | Robert Hayes |
| Branch B | `b` | Nobody decides; incident commander restricts the service at 56 hours | Resolution tracker | Jordan Blake |

Suggested split for a four-person team: allocator and dashboard (steps 1 to 2); tracker and escalation (3, 4, Branch B); evidence, verification and risk calculator (5, 7, 8); assistant, learning centre and audit (6, Branch A, evaluation tab).

## Files

| File | Contents |
|---|---|
| `app.py` | Entry point: sidebar controls, theme, page navigation |
| `engine.py` | All controls: allocator and triage categories, risk matrix and floors, quantitative model and rubric, task lifecycle, segregation of duties, training gates, Table 4.2 escalation route, exceptions, control health, daily job, audit trail |
| `scenarios.py` | Scripted timelines for each demo step and the presenter notes |
| `views.py` | The nine pages |
| `assistant.py` | Retrieval over the controlled knowledge base, citations, referral rules, optional Claude phrasing |
| `seed_data.py` | Synthetic people, assets, inventory, advisories, controls, evidence, policies, training modules |
| `tests/test_controls.py` | 13 control tests, one per rule (`pytest -q`) |

## How it maps to the report

- **4.2 Integrated dashboard**: role-specific views (owner, reviewer, compliance, CIO delegate, management, board, audit); patching and monitoring shown separately; drill-down to the record; downloadable committee pack.
- **4.3.1 Allocator**: matching against the inventory; confirmed, investigation and potentially affected categories; daily reconciliation with discovery records; coverage indicators; deadline fixed from the original alert.
- **4.3.2 Tracker**: Assigned to Verified closed; backend evidence checks; segregation of duties; four treatment decisions each with a due date; the P1 escalation route with deputies and pre-approved restriction; exceptions that stay open and re-escalate on expiry.
- **4.4 Risk calculator**: 5 by 5 matrix with reasoning, P1 floors and Unassessed; CISO-approved downward overrides; AV × EF × ARO × (1 − CE) with evidence bands, daily recalculation, sensitivity range and tolerance utilisation.
- **4.5 Assistant**: grounded answers with clause citations, no action rights, referral on conflict or no match, interaction log, approved test set.
- **4.6 Learning centre**: three-question scenario modules; verification and exception approval locked until passed at the current version; refreshers after procedure changes.
- **4.7 to 4.8 Governance and evaluation**: audit trail including blocked attempts, internal audit sampling, committee pack, 2017-versus-replay comparison, and live evaluation measures.

## Known limitations

- Synthetic data only; names and systems are invented ("ACIS-like").
- Loss assumptions and the effectiveness rubric are illustrative and uncalibrated.
- Controls depend on inventory quality; reconciliation narrows but cannot remove blind spots.
- No persistence or authentication; the production design in report 4.8 uses FastAPI, PostgreSQL, restricted evidence storage and a scheduled worker.
- P2 to P4 escalation ladders are proportional illustrations; only the P1 ladder follows Table 4.2.
