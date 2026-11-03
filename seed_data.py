"""
seed_data.py - synthetic data for the Group 20 Equifax prototype.

Everything here is invented for demonstration. Asset names are "ACIS-like",
people are fictional, and the clock replays March 2017 so the professor can
compare what this design would have done against the documented timeline.
"""
from datetime import datetime, timedelta

def dt(month, day, hour=0, minute=0, year=2017):
    return datetime(year, month, day, hour, minute)

# Start of the simulation. The daily risk job (02:00) and the inventory
# reconciliation (05:00) both run before the Struts advisory arrives at 06:10.
SIM_START = dt(3, 8, 1, 0)
ADVISORY_TIME = dt(3, 8, 6, 10)
ATTACK_DATE_2017 = dt(5, 13)  # date attackers first accessed ACIS in 2017 (PSI, 2019)

# ---------------------------------------------------------------------------
# People. "role" drives the dashboard view and the permission checks.
# ---------------------------------------------------------------------------
PEOPLE = {
    "daniel": {"name": "Daniel Reyes", "role": "Application owner", "title": "Owner, consumer dispute portal"},
    "priya":  {"name": "Priya Nair", "role": "Application owner", "title": "Deputy owner, consumer dispute portal"},
    "wei":    {"name": "Wei Chen", "role": "Application owner", "title": "Owner, merchant billing portal"},
    "omar":   {"name": "Omar Haddad", "role": "Application owner", "title": "Owner, HR intranet"},
    "marcus": {"name": "Marcus Bell", "role": "Line manager", "title": "Head of consumer applications"},
    "aisha":  {"name": "Aisha Rahman", "role": "Security reviewer", "title": "Vulnerability assurance analyst"},
    "leo":    {"name": "Leo Tan", "role": "Security reviewer", "title": "Security analyst, joined last month"},
    "sam":    {"name": "Sam Ortiz", "role": "Security operations", "title": "Network security engineer"},
    "helen":  {"name": "Helen Park", "role": "CIO delegate", "title": "Director, IT asset management"},
    "robert": {"name": "Robert Hayes", "role": "Executive risk owner", "title": "EVP, consumer information services"},
    "sandra": {"name": "Sandra Lowe", "role": "Executive risk owner", "title": "Deputy executive risk owner"},
    "ciso":   {"name": "Chief Information Security Officer", "role": "CISO", "title": "Reports to the CEO"},
    "ceo":    {"name": "Chief Executive Officer", "role": "CEO", "title": "Chief Executive Officer"},
    "ic":     {"name": "Jordan Blake", "role": "Incident commander", "title": "SOC duty manager, pre-approved to restrict services"},
    "grace":  {"name": "Grace Liu", "role": "Compliance officer", "title": "Head of technology compliance"},
    "audit":  {"name": "Internal audit", "role": "Internal audit", "title": "Third line"},
    "chair":  {"name": "Committee chair", "role": "Board committee", "title": "Chair, joint Audit and Technology Committee"},
}

# Holders of organisation-wide roles used by the escalation route.
DIRECTORY = {
    "cio_delegate": "helen",
    "exec": "robert",
    "exec_deputy": "sandra",
    "ceo": "ceo",
    "incident_commander": "ic",
    "committee_chair": "chair",
    "ciso": "ciso",
    "compliance": "grace",
    "secops": "sam",
}

# ---------------------------------------------------------------------------
# Asset register. Classification drives impact; internet exposure drives
# likelihood. "inventory_at" is when the software inventory was last refreshed.
# ---------------------------------------------------------------------------
ASSETS = {
    "A-ACIS": {
        "name": "Consumer dispute portal (ACIS-like)", "owner": "daniel", "deputy": "priya",
        "line_manager": "marcus", "risk_owner": "robert", "legal_entity": "Equifax Inc. (US)",
        "classification": "Bulk sensitive identity", "service_impact": 4, "internet_facing": True,
        "inventory_at": dt(3, 7, 23, 0), "host": "acis-web-01.consumer.efx", "restricted": False,
    },
    "A-CREDAPI": {
        "name": "Credit report API gateway", "owner": "wei", "deputy": "daniel",
        "line_manager": "marcus", "risk_owner": "robert", "legal_entity": "Equifax Inc. (US)",
        "classification": "Bulk sensitive identity", "service_impact": 5, "internet_facing": True,
        "inventory_at": dt(3, 7, 23, 0), "host": "api-gw-02.consumer.efx", "restricted": False,
    },
    "A-BILL": {
        "name": "Merchant billing portal", "owner": "wei", "deputy": "priya",
        "line_manager": "marcus", "risk_owner": "robert", "legal_entity": "Equifax Inc. (US)",
        "classification": "Sensitive consumer", "service_impact": 3, "internet_facing": True,
        "inventory_at": dt(3, 7, 23, 0), "host": "billing-web-01.commerce.efx", "restricted": False,
    },
    "A-HRINT": {
        "name": "HR intranet", "owner": "omar", "deputy": "marcus",
        "line_manager": "marcus", "risk_owner": "robert", "legal_entity": "Equifax Inc. (US)",
        "classification": "Internal", "service_impact": 2, "internet_facing": False,
        "inventory_at": dt(2, 24, 9, 0), "host": "hr-intra-01.corp.efx", "restricted": False,
    },
    "A-UKMIRROR": {
        "name": "UK consumer data mirror (Equifax Ltd)", "owner": "omar", "deputy": "wei",
        "line_manager": "marcus", "risk_owner": "robert", "legal_entity": "Equifax Ltd (UK)",
        "classification": "Confidential", "service_impact": 3, "internet_facing": False,
        "inventory_at": dt(3, 7, 23, 0), "host": "uk-mirror-01.efx", "restricted": False,
    },
    "A-MKTG": {
        "name": "Public marketing site", "owner": "wei", "deputy": "omar",
        "line_manager": "marcus", "risk_owner": "robert", "legal_entity": "Equifax Inc. (US)",
        "classification": "Public", "service_impact": 1, "internet_facing": True,
        "inventory_at": dt(3, 7, 23, 0), "host": "www.efx-example.com", "restricted": False,
    },
}

# Software inventory: component and version per asset. None = unknown version.
INVENTORY = [
    {"asset_id": "A-ACIS", "component": "apache-struts2", "version": "2.3.31"},
    {"asset_id": "A-ACIS", "component": "openjdk", "version": "1.8.0_121"},
    {"asset_id": "A-CREDAPI", "component": "apache-struts2", "version": "2.5.10.1"},
    {"asset_id": "A-CREDAPI", "component": "openssl", "version": "1.0.2k"},
    {"asset_id": "A-BILL", "component": "apache-struts2", "version": None},
    {"asset_id": "A-HRINT", "component": "apache-struts2", "version": "2.3.20"},
    {"asset_id": "A-HRINT", "component": "openssl", "version": "1.0.1u"},
    {"asset_id": "A-UKMIRROR", "component": "openssl", "version": "1.0.2h"},
    {"asset_id": "A-MKTG", "component": "openssl", "version": "1.0.2j"},
    {"asset_id": "A-MKTG", "component": "nginx", "version": "1.10.3"},
]

# Network discovery and deployment records. A host with no asset_id is not in
# the register, which is the blind spot that left ACIS unpatched in 2017.
DISCOVERY = [
    {"host": "acis-web-01.consumer.efx", "source": "Network discovery", "asset_id": "A-ACIS", "internet_facing": True},
    {"host": "api-gw-02.consumer.efx", "source": "Network discovery", "asset_id": "A-CREDAPI", "internet_facing": True},
    {"host": "billing-web-01.commerce.efx", "source": "Deployment record", "asset_id": "A-BILL", "internet_facing": True},
    {"host": "hr-intra-01.corp.efx", "source": "Network discovery", "asset_id": "A-HRINT", "internet_facing": False},
    {"host": "uk-mirror-01.efx", "source": "Network discovery", "asset_id": "A-UKMIRROR", "internet_facing": False},
    {"host": "www.efx-example.com", "source": "Network discovery", "asset_id": "A-MKTG", "internet_facing": True},
    {"host": "dispute-archive-03.consumer.efx", "source": "Network discovery", "asset_id": None, "internet_facing": True,
     "fingerprint": "nginx 1.10.3 serving static exports; no Java runtime observed"},
]

# ---------------------------------------------------------------------------
# Advisory feed (vulnerability intelligence). Ranges are inclusive.
# ---------------------------------------------------------------------------
ADVISORIES = {
    "CVE-2017-5638": {
        "title": "Apache Struts 2 Jakarta Multipart parser remote code execution",
        "component": "apache-struts2", "cvss": 10.0,
        "affected": [("2.3.5", "2.3.31"), ("2.5", "2.5.10")], "fixed": "2.3.32 or 2.5.10.1",
        "public_exploit": True, "exploited_in_wild": True,
        "source": "Apache Software Foundation S2-045, US-CERT alert",
    },
    "CVE-2017-3731": {
        "title": "OpenSSL truncated packet denial of service",
        "component": "openssl", "cvss": 7.5,
        "affected": [("1.0.2", "1.0.2j"), ("1.1.0", "1.1.0c")], "fixed": "1.0.2k or 1.1.0d",
        "public_exploit": False, "exploited_in_wild": False,
        "source": "OpenSSL security advisory (synthetic entry for prioritisation contrast)",
    },
}

# ---------------------------------------------------------------------------
# Monitoring controls. Health is tracked separately from patching.
# ---------------------------------------------------------------------------
CONTROLS = {
    "SSLI-CONSUMER": {
        "name": "SSL inspection device, consumer-apps segment", "type": "Encrypted traffic inspection",
        "covers": ["A-ACIS", "A-BILL"], "cert_expires": dt(3, 10, 12, 0),
        "last_test": dt(3, 6, 9, 0), "test_max_age_days": 30, "heartbeat_ok": True, "awaiting_test": False,
    },
    "SSLI-CORE": {
        "name": "SSL inspection device, core network", "type": "Encrypted traffic inspection",
        "covers": ["A-CREDAPI", "A-HRINT", "A-UKMIRROR"], "cert_expires": dt(9, 30, 0, 0),
        "last_test": dt(3, 6, 9, 30), "test_max_age_days": 30, "heartbeat_ok": True, "awaiting_test": False,
    },
    "IDS-PERIM": {
        "name": "Perimeter intrusion detection sensor", "type": "Intrusion detection",
        "covers": ["A-MKTG", "A-ACIS", "A-BILL", "A-CREDAPI"], "cert_expires": None,
        "last_test": dt(3, 7, 10, 0), "test_max_age_days": 30, "heartbeat_ok": True, "awaiting_test": False,
    },
    "SIEM-FWD": {
        "name": "Log forwarder to SIEM", "type": "Log collection",
        "covers": ["A-ACIS", "A-CREDAPI", "A-BILL", "A-HRINT", "A-UKMIRROR", "A-MKTG"], "cert_expires": dt(12, 31, 0, 0),
        "last_test": dt(3, 7, 11, 0), "test_max_age_days": 30, "heartbeat_ok": True, "awaiting_test": False,
    },
}
CERT_WARNING_DAYS = [30, 7, 1]

# ---------------------------------------------------------------------------
# Stored control evidence for the quantitative model. Patch verification and
# detection readiness are derived live from tasks and control health.
# ---------------------------------------------------------------------------
EVIDENCE = {
    "A-ACIS": {
        "patch": {"status": "Passed", "ref": "February 2017 patch cycle verified (PV-0217)", "tested_at": dt(2, 28), "max_age_days": 45},
        "coverage": {"status": "Unknown", "ref": "No authenticated scan covering this application in the last 30 days", "tested_at": None, "max_age_days": 30},
        "priv": {"status": "Failed", "ref": "AR-0301 access review: service-account passwords stored in plaintext config", "tested_at": dt(3, 1), "max_age_days": 90},
        "network": {"status": "Passed", "ref": "RT-0306 reachability test: portal cannot reach unrelated databases", "tested_at": dt(3, 6), "max_age_days": 30},
    },
    "A-CREDAPI": {
        "patch": {"status": "Passed", "ref": "February 2017 patch cycle verified (PV-0217)", "tested_at": dt(2, 28), "max_age_days": 45},
        "coverage": {"status": "Passed", "ref": "Authenticated scan SC-0303 covered gateway and components", "tested_at": dt(3, 3), "max_age_days": 30},
        "priv": {"status": "Passed", "ref": "AR-0301 access review complete; keys rotated", "tested_at": dt(3, 1), "max_age_days": 90},
        "network": {"status": "Passed", "ref": "RT-0306 reachability test passed", "tested_at": dt(3, 6), "max_age_days": 30},
    },
    "A-HRINT": {
        "patch": {"status": "Passed", "ref": "January 2017 patch cycle verified", "tested_at": dt(1, 31), "max_age_days": 45},
        "coverage": {"status": "Unknown", "ref": "Inventory stale; scan scope not reconciled", "tested_at": None, "max_age_days": 30},
        "priv": {"status": "Passed", "ref": "AR-0301 access review complete", "tested_at": dt(3, 1), "max_age_days": 90},
        "network": {"status": "Unknown", "ref": "No reachability test on record", "tested_at": None, "max_age_days": 30},
    },
    "A-UKMIRROR": {
        "patch": {"status": "Passed", "ref": "February 2017 patch cycle verified", "tested_at": dt(2, 28), "max_age_days": 45},
        "coverage": {"status": "Passed", "ref": "Authenticated scan SC-0303", "tested_at": dt(3, 3), "max_age_days": 30},
        "priv": {"status": "Unknown", "ref": "Group access review not shared with UK entity", "tested_at": None, "max_age_days": 90},
        "network": {"status": "Passed", "ref": "RT-0306 reachability test passed", "tested_at": dt(3, 6), "max_age_days": 30},
    },
    "A-BILL": {
        "patch": {"status": "Passed", "ref": "February 2017 patch cycle verified", "tested_at": dt(2, 28), "max_age_days": 45},
        "coverage": {"status": "Passed", "ref": "Authenticated scan SC-0303", "tested_at": dt(3, 3), "max_age_days": 30},
        "priv": {"status": "Passed", "ref": "AR-0301 access review complete", "tested_at": dt(3, 1), "max_age_days": 90},
        "network": {"status": "Passed", "ref": "RT-0306 reachability test passed", "tested_at": dt(3, 6), "max_age_days": 30},
    },
}

# Business assumptions for the quantitative model (approved by Finance and the
# business owner). A-BILL has no approved asset value on purpose, so the model
# shows "Assessment incomplete" instead of a misleading zero.
ASSUMPTIONS = {
    "A-ACIS": {"scenario": "Attacker exploits an unpatched component in the dispute portal to reach consumer identity data",
               "av": 10_000_000, "ef": 0.40, "aro": 0.5, "tolerance": 1_000_000,
               "approved_by": "Finance (CFO office) and business owner", "approved_on": dt(1, 15)},
    "A-CREDAPI": {"scenario": "Attacker abuses the API gateway to extract credit files in bulk",
                  "av": 25_000_000, "ef": 0.20, "aro": 0.2, "tolerance": 1_500_000,
                  "approved_by": "Finance (CFO office) and business owner", "approved_on": dt(1, 15)},
    "A-HRINT": {"scenario": "Insider or intruder reaches employee records through the intranet",
                "av": 2_000_000, "ef": 0.30, "aro": 0.3, "tolerance": 250_000,
                "approved_by": "Finance (CFO office) and HR", "approved_on": dt(1, 15)},
    "A-UKMIRROR": {"scenario": "Compromise of UK consumer records held by the group mirror",
                   "av": 4_000_000, "ef": 0.30, "aro": 0.2, "tolerance": 400_000,
                   "approved_by": "Equifax Ltd finance and data protection officer", "approved_on": dt(1, 20)},
    "A-BILL": {"scenario": "Merchant billing data exposed through the billing portal",
               "av": None, "ef": 0.25, "aro": 0.3, "tolerance": 300_000,
               "approved_by": "Pending: asset value not yet approved", "approved_on": None},
}

# Ground truth for evaluating the allocator (what a perfect triage would find).
GROUND_TRUTH_AFFECTED = {
    "CVE-2017-5638": {"A-ACIS", "A-HRINT"},
    "CVE-2017-3731": {"A-MKTG", "A-UKMIRROR"},
}

# ---------------------------------------------------------------------------
# Controlled knowledge base for the compliance assistant. Internal documents
# are synthetic; regulatory summaries paraphrase sources cited in the report.
# ---------------------------------------------------------------------------
KNOWLEDGE_BASE = [
    {"id": "VM-3.1", "doc": "POL-VM-01", "title": "Vulnerability and Patch Management Policy", "version": "3.2", "section": "3.1",
     "heading": "Treatment deadlines",
     "text": "Exposures are prioritised by the risk matrix. P1 (score 20 to 25) must be treated within 48 calendar hours, P2 (12 to 19) within 7 calendar days, P3 (6 to 11) within 30 business days and P4 (1 to 5) within 90 business days. A confirmed critical vulnerability on an internet-facing service, or any vulnerability with known exploitation, is at least P1.",
     "summary": "P1 means 48 calendar hours; known exploitation or a critical internet-facing flaw is always at least P1.",
     "keywords": "deadline sla p1 p2 p3 p4 48 hours seven days priority how long patch time"},
    {"id": "VM-3.4", "doc": "POL-VM-01", "title": "Vulnerability and Patch Management Policy", "version": "3.2", "section": "3.4",
     "heading": "Deadline anchoring",
     "text": "The treatment deadline is fixed by the time the advisory was received. Reassigning a task, refreshing an inventory or reclassifying an asset does not restart the clock.",
     "summary": "The clock starts when the advisory arrives and never restarts.",
     "keywords": "clock restart reassign reassignment reset deadline extend inventory refresh"},
    {"id": "VM-3.6", "doc": "POL-VM-01", "title": "Vulnerability and Patch Management Policy", "version": "3.2", "section": "3.6",
     "heading": "Inventory completeness",
     "text": "An asset whose component version is unknown receives an investigation task and can only be closed as not affected with supporting evidence. An asset whose software inventory is older than seven days, or missing, is treated as potentially affected until its data is refreshed. Neither category counts as safe by default.",
     "summary": "Unknown or stale inventory never counts as safe; it creates an investigation or potentially-affected task.",
     "keywords": "unknown version stale inventory seven days investigation not affected potentially affected safe"},
    {"id": "VM-4.2", "doc": "POL-VM-01", "title": "Vulnerability and Patch Management Policy", "version": "3.2", "section": "4.2",
     "heading": "Evidence required for closure",
     "text": "A remediation task closes only when an independent security reviewer confirms all of the following: the running version is outside the affected range; an authenticated scan covered the affected application and the affected component; and the scan was performed after the change was deployed. A scan whose scope excludes the affected application is not evidence of remediation.",
     "summary": "Closure needs a corrected running version, an authenticated scan that covers the application and component, run after deployment, confirmed by an independent reviewer.",
     "keywords": "evidence close closing closure verify verification scan authenticated scope rejected reject submission excluded proof required"},
    {"id": "VM-4.3", "doc": "POL-VM-01", "title": "Vulnerability and Patch Management Policy", "version": "3.2", "section": "4.3",
     "heading": "Segregation of duties",
     "text": "The person who performed or submitted the remediation may not verify it. The verifying reviewer must hold the security reviewer role and have passed the current version of training module M-SEC-01.",
     "summary": "You cannot verify your own fix; reviewers must be independent and trained.",
     "keywords": "approve own work segregation duties self approval independent reviewer training verify myself"},
    {"id": "ESC-2.1", "doc": "PRC-ESC-02", "title": "Escalation and Treatment Decision Procedure", "version": "1.4", "section": "2.1",
     "heading": "Escalation route for P1 exposures",
     "text": "An unacknowledged P1 task escalates to the line manager and deputy owner after 4 hours. With no treatment decision after 24 hours it escalates to the CIO's delegate. If not verified closed and without an approved exception after 48 hours it escalates to the executive risk decision-maker, then to the named deputy at 52 hours and to the CEO with the incident commander at 56 hours. An exposure open after 7 days goes to the chair of the joint Audit and Technology Committee. P1 clocks run in calendar hours including nights and weekends.",
     "summary": "4h line manager, 24h CIO delegate, 48h executive, 52h deputy, 56h CEO and incident commander, 7 days committee chair.",
     "keywords": "escalation escalate ladder route who 4 hours 24 hours 48 hours executive ceo committee unanswered weekend"},
    {"id": "ESC-2.3", "doc": "PRC-ESC-02", "title": "Escalation and Treatment Decision Procedure", "version": "1.4", "section": "2.3",
     "heading": "Treatment decisions",
     "text": "Each escalation requires a recorded treatment decision, not an acknowledgement. The options are: remediate; apply a verified temporary protection such as a tested web application firewall rule; restrict or withdraw the service; or approve a time-limited exception of no more than seven days for P1. Each decision carries its own due date, and failure to evidence the chosen action by that date resumes escalation.",
     "summary": "Pick one of four decisions; each has a due date and lapses back into escalation if not evidenced.",
     "keywords": "treatment decision options remediate temporary protection waf restrict withdraw exception due date"},
    {"id": "ESC-2.5", "doc": "PRC-ESC-02", "title": "Escalation and Treatment Decision Procedure", "version": "1.4", "section": "2.5",
     "heading": "Restriction authority",
     "text": "The executive committee pre-approves the incident commander to restrict or withdraw a service when no decision has been recorded 56 hours after a P1 alert, so a decision is always reached even if every decision-maker is unavailable.",
     "summary": "The incident commander can restrict the service at 56 hours without waiting for anyone.",
     "keywords": "incident commander restrict service offline authority unavailable nobody decides"},
    {"id": "EXC-1.2", "doc": "PRC-EXC-03", "title": "Risk Exception Procedure", "version": "2.0", "section": "1.2",
     "heading": "Approving an exception",
     "text": "Security reviews the proposed mitigation before the authorised business executive decides whether to accept the remaining risk. The approver can never be the requester. P1 exceptions last at most seven days. Approved exceptions remain open exposures, and their expiry triggers renewed escalation.",
     "summary": "Security reviews first, an executive who is not the requester approves, maximum seven days, and it stays open.",
     "keywords": "exception approve approval requester accept risk waiver seven days expiry open mitigation"},
    {"id": "EXC-1.4", "doc": "PRC-EXC-03", "title": "Risk Exception Procedure", "version": "2.0", "section": "1.4",
     "heading": "Exceptions and the risk estimate",
     "text": "Approving an exception records a decision to accept risk. It never reduces the estimated financial exposure, because it does not change the evidence about control effectiveness.",
     "summary": "An approved exception does not lower the estimate.",
     "keywords": "exception estimate reduce lower exposure accept"},
    {"id": "RQ-2.1", "doc": "STD-RQ-04", "title": "Risk Quantification Standard", "version": "1.2", "section": "2.1",
     "heading": "Estimated annual loss",
     "text": "Estimated annual loss equals asset value times exposure factor times annual rate of occurrence times control deficiency, where control deficiency is one minus control effectiveness. Control effectiveness is one of four bands: Minor 25 percent, Moderate 50 percent, Significant 75 percent or Nearly complete 95 percent, assigned by a CISO-approved rubric from collected evidence.",
     "summary": "Loss = AV x EF x ARO x (1 - control effectiveness), with effectiveness set by evidence bands.",
     "keywords": "estimate formula asset value exposure factor aro control effectiveness band calculation loss money"},
    {"id": "RQ-2.4", "doc": "STD-RQ-04", "title": "Risk Quantification Standard", "version": "1.2", "section": "2.4",
     "heading": "Daily recalculation",
     "text": "Estimates are recalculated once every 24 hours at 02:00. A verified patch, an expired certificate or a failed access test moves the estimate at the next run; the passage of time alone does not. Unknown never counts as a pass, and a stale or failed mandatory test removes the credit it supported. Missing assumptions display Assessment incomplete rather than zero. Urgent events still raise immediate alerts.",
     "summary": "The estimate updates at the next 02:00 run, and only when verified evidence changes.",
     "keywords": "estimate not fallen why still daily recalculation update next run fall drop changed unknown stale"},
    {"id": "MON-3.2", "doc": "STD-MON-05", "title": "Monitoring Control Standard", "version": "1.1", "section": "3.2",
     "heading": "Inspection device certificates",
     "text": "Certificates on traffic inspection devices are tracked with warnings at 30, 7 and 1 days before expiry. An expired certificate marks the control as failed immediately. A restored control stays flagged until an inspection test passes. Monitoring health is reported separately from patch status, so a patched application can still show a failed detection control.",
     "summary": "An expired inspection certificate fails the control at once, and it stays flagged until retested.",
     "keywords": "certificate expired ssl inspection monitoring detection blind renew test control health red"},
    {"id": "TRN-1.1", "doc": "POL-TRN-06", "title": "Training and Approval Authority Policy", "version": "1.0", "section": "1.1",
     "heading": "Training before approval",
     "text": "Permission to verify fixes requires the current version of module M-SEC-01, and permission to approve risk exceptions requires M-RISK-01. Employees may report issues and acknowledge urgent tasks before completing training. A material procedure change triggers a refresher.",
     "summary": "Verifying needs M-SEC-01 and approving exceptions needs M-RISK-01; acknowledging needs no training.",
     "keywords": "training module required approve verify permission blocked learning refresher"},
    {"id": "CAL-1.0", "doc": "NOT-CAL-07", "title": "Q1 Change Freeze Notice", "version": "1.0", "section": "1",
     "heading": "Month-end change freeze",
     "text": "No production changes may be made to consumer-facing systems during the month-end freeze from 28 March to 3 April except with emergency change board approval.",
     "summary": "Production changes are frozen 28 March to 3 April without emergency approval.",
     "keywords": "change freeze month end production deploy patch during freeze emergency",
     "conflicts_with": "VM-3.1"},
    {"id": "REG-GLBA-1", "doc": "REG-SAFEGUARDS", "title": "FTC Safeguards Rule (16 CFR 314), summary", "version": "2024 amendment", "section": "314.4",
     "heading": "Safeguards programme duties",
     "text": "A financial institution must designate a Qualified Individual, base its programme on a written risk assessment, design safeguards for identified risks, regularly test or monitor their effectiveness, and report in writing to its board at least annually. Without effective continuous monitoring it must run annual penetration tests and vulnerability assessments at least every six months.",
     "summary": "The Safeguards Rule requires a risk-based programme, tested safeguards and at least annual board reporting.",
     "keywords": "glba safeguards rule ftc regulation law qualified individual board report penetration test requirement"},
    {"id": "REG-GLBA-2", "doc": "REG-SAFEGUARDS", "title": "FTC Safeguards Rule (16 CFR 314), summary", "version": "2024 amendment", "section": "314.4(j)",
     "heading": "Notification to the FTC",
     "text": "A notification event involving unencrypted information of at least 500 consumers must be reported to the FTC as soon as possible and no later than 30 days after discovery.",
     "summary": "Report breaches affecting 500 or more consumers to the FTC within 30 days.",
     "keywords": "breach notification report ftc 30 days 500 consumers disclose"},
    {"id": "REG-SEC-1", "doc": "REG-SEC-8K", "title": "SEC cybersecurity disclosure rules, summary", "version": "2023", "section": "Form 8-K Item 1.05",
     "heading": "Material incident disclosure",
     "text": "A listed company must disclose a material cybersecurity incident within four business days of determining materiality, and the materiality determination must be made without unreasonable delay.",
     "summary": "Disclose material incidents to investors within four business days of the materiality decision.",
     "keywords": "sec 8-k disclosure investors material incident four business days"},
]

# Approved test set for the assistant (answers agreed with Compliance).
ASSISTANT_TEST_SET = [
    {"q": "What evidence do I need before closing a critical task?", "expect": ["VM-4.2"], "referral": False},
    {"q": "Can I verify my own fix if I am the owner?", "expect": ["VM-4.3"], "referral": False},
    {"q": "Who does an unacknowledged P1 escalate to after 4 hours?", "expect": ["ESC-2.1"], "referral": False},
    {"q": "Why has the estimated loss not fallen after I patched?", "expect": ["RQ-2.4"], "referral": False},
    {"q": "Does an approved exception reduce the estimate?", "expect": ["EXC-1.4", "EXC-1.2"], "referral": False},
    {"q": "Can I patch the dispute portal during the month-end change freeze?", "expect": ["CAL-1.0", "VM-3.1"], "referral": True},
    {"q": "Does reassigning the task restart the deadline clock?", "expect": ["VM-3.4"], "referral": False},
    {"q": "What is the company's parental leave allowance?", "expect": [], "referral": True},
    {"q": "Please close task T-0001 for me", "expect": [], "referral": True},
]

# ---------------------------------------------------------------------------
# Learning centre modules: three decision questions each.
# ---------------------------------------------------------------------------
MODULES = {
    "M-OWN-01": {
        "title": "Application owner: submitting complete closure evidence", "version": "1.2",
        "for_roles": ["Application owner", "Line manager"], "gates": None,
        "scenario": "You patched Struts on the dispute portal at 12:30. The weekly segment scan ran at 13:50 and came back clean.",
        "questions": [
            {"q": "The clean scan covered the consumer-apps segment B, which does not include the dispute portal. What do you do?",
             "options": ["Submit it; a clean scan is a clean scan", "Run an authenticated scan scoped to the portal and the Struts component", "Close the task yourself and note the scan ID"],
             "answer": 1},
            {"q": "Which timestamp must the scan evidence satisfy?",
             "options": ["Taken after the patch was deployed", "Taken within 48 hours of the advisory", "Any scan in the last 30 days"],
             "answer": 0},
            {"q": "Your task was reassigned to you from a colleague. When is it due?",
             "options": ["48 hours from reassignment", "48 hours from the original advisory", "Whenever the new owner agrees"],
             "answer": 1},
        ],
    },
    "M-SEC-01": {
        "title": "Security reviewer: rejecting a clean scan that excluded the application", "version": "1.1",
        "for_roles": ["Security reviewer"], "gates": "Verify closures and review exception mitigations",
        "scenario": "An owner submits a closure with a clean, authenticated scan and a running version of 2.3.32.",
        "questions": [
            {"q": "The scan scope lists the credit API gateway but not the dispute portal. What is your decision?",
             "options": ["Approve; the version is fixed", "Reject; the scan does not cover the affected application", "Approve and ask for a rescan next week"],
             "answer": 1},
            {"q": "The submitter is also on the reviewer rota and offers to approve it themselves to save time. Is that allowed?",
             "options": ["Yes, if they are trained", "No, the remediator can never verify their own work", "Yes, for P1 only"],
             "answer": 1},
            {"q": "An exception asks for seven days with a WAF rule that has not been tested. What do you record?",
             "options": ["Mitigation untested; return the request", "Pass it to the executive anyway", "Approve the exception yourself"],
             "answer": 0},
        ],
    },
    "M-RISK-01": {
        "title": "Business risk owner: assessing an exception with an untested mitigation", "version": "1.0",
        "for_roles": ["Executive risk owner", "CEO"], "gates": "Approve risk exceptions",
        "scenario": "The dispute portal team asks for a seven-day exception because the patch breaks document uploads.",
        "questions": [
            {"q": "Security has not yet reviewed the WAF rule. Can you approve?",
             "options": ["Yes, the business need is urgent", "No, security must review the mitigation first", "Yes, for 48 hours"],
             "answer": 1},
            {"q": "After approval, how should the dashboard show this exposure?",
             "options": ["Closed", "Still open, with the exception and its expiry visible", "Hidden until expiry"],
             "answer": 1},
            {"q": "Will approving the exception reduce the estimated annual loss?",
             "options": ["Yes, the risk is now accepted", "No, accepting risk does not change control evidence", "Only for seven days"],
             "answer": 1},
        ],
    },
    "M-MGR-01": {
        "title": "Manager: responding to an overdue exposure", "version": "1.0",
        "for_roles": ["Line manager", "CIO delegate", "Executive risk owner"], "gates": None,
        "scenario": "A P1 task on your team was escalated to you at 24 hours with no treatment decision.",
        "questions": [
            {"q": "What does the escalation require from you?",
             "options": ["An acknowledgement", "One of the four recorded treatment decisions", "A reply-all email"],
             "answer": 1},
            {"q": "You choose to remediate. What happens if the fix is not evidenced by the due date?",
             "options": ["Nothing, the decision stands", "Escalation resumes", "The task closes automatically"],
             "answer": 1},
            {"q": "Nobody above you responds by 56 hours. Who can still act?",
             "options": ["No one until Monday", "The incident commander, pre-approved to restrict the service", "The application owner, by closing the task"],
             "answer": 1},
        ],
    },
}

# Training records at the start of the simulation.
TRAINING = {
    "daniel": {"M-OWN-01": {"version": "1.2", "date": dt(2, 10), "score": 3, "passed": True}},
    "priya":  {"M-OWN-01": {"version": "1.2", "date": dt(2, 11), "score": 3, "passed": True}},
    "wei":    {"M-OWN-01": {"version": "1.2", "date": dt(2, 12), "score": 3, "passed": True}},
    "omar":   {"M-OWN-01": {"version": "1.1", "date": dt(1, 5), "score": 3, "passed": True}},
    "aisha":  {"M-SEC-01": {"version": "1.1", "date": dt(2, 3), "score": 3, "passed": True}},
    "robert": {"M-RISK-01": {"version": "1.0", "date": dt(2, 6), "score": 3, "passed": True},
               "M-MGR-01": {"version": "1.0", "date": dt(2, 6), "score": 3, "passed": True}},
    "sandra": {"M-RISK-01": {"version": "1.0", "date": dt(2, 7), "score": 3, "passed": True}},
    "ceo":    {"M-RISK-01": {"version": "1.0", "date": dt(2, 9), "score": 3, "passed": True}},
    "helen":  {"M-MGR-01": {"version": "1.0", "date": dt(2, 14), "score": 3, "passed": True}},
}

# Earlier certificate warnings that were sent before the simulation starts.
PRIOR_AUDIT = [
    {"at": dt(2, 8, 12, 0), "actor": "system", "action": "Monitoring alert", "object": "SSLI-CONSUMER",
     "detail": "Certificate expires in 30 days. Sent to Security operations.", "outcome": "System"},
    {"at": dt(3, 3, 12, 0), "actor": "system", "action": "Monitoring alert", "object": "SSLI-CONSUMER",
     "detail": "Certificate expires in 7 days. Sent to Security operations and the CISO.", "outcome": "System"},
]
