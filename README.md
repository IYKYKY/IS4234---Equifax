# Equifax vulnerability assurance prototype (IS4234 Group 20)

> **Branch `shawn/guided-demo-and-tests`.** This branch is for the team to test before anything is merged into `main`. Read this section first; the original README follows below the line.

## What this branch changes compared with `main`

Only four files differ. No rule in `engine.py` changed, so every control behaves exactly as it does on `main`.

| File | Change |
|---|---|
| `app.py` | **Back / Next buttons** in the sidebar. They load the neighbouring demo step and open the page that step is best viewed on (before, you had to change the step and the page by hand). They are disabled at the first and last step. |
| `views.py` | Three small UI fixes (below). |
| `tests/test_blocks.py` | **New.** 40 further tests (see "Automated tests"). |
| `README.md` | This section, the testing steps and updated file notes. |

The three UI fixes in `views.py`:

1. **Control health:** one expired certificate showed one identical red banner per patched application it left blind. It now shows a single banner listing those applications.
2. **Dashboard, "Patching status":** the table cut off its last column (Escalation) at half width and wrapped task IDs such as T-0002 mid-word. It now renders in full and keeps IDs on one line.
3. **Compliance assistant:** the "Answer mode" toggle was greyed out with no explanation when no API key is set. It now says Claude mode is off and answers use grounded retrieval.

Unchanged and identical to `main`: `engine.py`, `assistant.py`, `scenarios.py`, `seed_data.py`, `requirements.txt`, `.streamlit/config.toml`, `tests/test_controls.py`.

## How to run

Python 3.10 or later. No login, database or test account is needed.

```bash
git fetch origin
git checkout shawn/guided-demo-and-tests
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install pytest                 # only needed for the automated tests
streamlit run app.py
```

Streamlit prints a local URL (normally http://localhost:8501). State lives in the browser tab and resets on refresh or with **Reset this step**. If the page looks stale after you pull new code, stop the server (Ctrl+C) and start it again.

## Automated tests

```bash
pytest -q
```

Expected: `53 passed`. That is the 13 original control tests plus 40 new ones in `tests/test_blocks.py`:

- every way of bypassing a control is refused (wrong person, wrong state, missing reason, over-long exception, and so on);
- refused attempts are written to the audit trail;
- the assistant passes its own approved test set and refuses actions without changing any record;
- a randomised check (12 seeds, 120 random actions each, any persona) that no task is ever closed without a trained, independent security reviewer, and no exception is ever approved by the person who requested it.

## Manual testing steps (about 10 minutes)

You pretend to be different people, try to do things, and the system allows them or refuses with a reason. Use the sidebar for **Demo step** and **Acting as**, then open the page named in each test.

**Test 1. The advisory reaches the right owner** (step 2)
1. Set the step to *2. Struts advisory arrives*. Open **Alert allocator**, then **Triage results**.
2. Expect three tasks assigned to named owners. Systems with an unknown or stale version are not treated as safe.

**Test 2. Silence escalates** (step 3)
1. Set the step to *3. Owner silent: 4-hour escalation*. Open **Resolution tracker**.
2. The timeline shows the 4-hour escalation has fired to the line manager and the deputy.
3. Acting as **Marcus Bell**, click **Acknowledge and confirm owner**. It works, because an escalation recipient may.

**Test 3. Bad evidence is rejected; nobody approves their own work** (step 5)
1. Set the step to *5. Evidence rejected*. Open **Resolution tracker** as **Daniel Reyes**. The **Evidence** tab shows an earlier submission that failed the scope check.
2. Open **Submit remediation evidence**. Remove `A-ACIS` from "Scan scope", add `A-CREDAPI`, submit. Expect a system rejection.
3. Submit again with the default scope (it includes `A-ACIS`). It passes the automatic checks and waits for a reviewer.
4. Still as Daniel, click **Approve closure**. Expect: blocked, segregation of duties.
5. Switch to **Leo Tan** and click **Approve closure**. Expect: blocked, he has not passed training.
6. Open **Learning centre** as Leo, module `M-SEC-01`, and answer: (1) *Reject; the scan does not cover the affected application*, (2) *No, the remediator can never verify their own work*, (3) *Mitigation untested; return the request*.
7. Back on the tracker, Leo clicks **Approve closure**. Expect: *Verified closed*.

**Test 4. The estimate moves only with evidence** (continue from Test 3)
1. Open **Risk calculator**, tab **Stage 2**. The published estimate is still **US$1.5m**.
2. In the sidebar click **Run daily recalculation now**. Expect **US$500k**.

**Test 5. Patched but blind** (step 8)
1. Set the step to *8. Patched but blind: certificate expired*. Open **Control health** as **Sam Ortiz**. Expect **one** red banner.
2. Click **Run inspection test**: blocked while the certificate is expired.
3. Click **Renew certificate**: status becomes *Awaiting test*. Click **Run inspection test**: status becomes *Healthy*.

**Test 6. The assistant cannot act** (step 6)
1. Set the step to *6. Assistant explains the missing evidence*. Open **Compliance assistant**.
2. Click *Please close task T-0002 for me*. Expect a refusal and a referral to Compliance.
3. Click *Can I patch during the month-end change freeze?*. Expect two conflicting clauses and a referral.

**New in this branch: Back / Next.** From any step click **Next**. Expect the step to advance and the page to switch to the one named under the step description (for example, from step 7 to step 8 it opens **Control health** as Sam Ortiz).

**Afterwards.** Open **Audit and evaluation**: every blocked attempt from your tests is recorded with who tried it.

Please report anything that looks wrong with the step number, the person you were acting as, and what you expected.

## Merging

Changes to `app.py` and `views.py` are small and local. If someone else edits those files on `main`, expect to resolve a conflict in `app.py` (sidebar block) or in `views.py` (`patch_table`, `page_controls`, `page_assistant`). The other files are untouched.

---

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

- **Back / Next** step through the presets in order and open the page each one is best viewed on.
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
| `tests/test_controls.py` | 13 control tests, one per headline rule (`pytest -q`) |
| `tests/test_blocks.py` | 40 further tests: every way of bypassing a control is refused and logged, plus a randomised check that no sequence of actions by any persona closes a task without independent, trained verification |

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
