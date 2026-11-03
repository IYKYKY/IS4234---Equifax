"""
assistant.py - the governed compliance assistant (report 4.5).

Retrieval-augmented: every answer is built from clauses in a controlled
knowledge base and cites document, section and version. The assistant has no
permission to change anything; requests to act, conflicting clauses, or
questions with no supporting clause are referred to Compliance.

Two modes:
  * Grounded retrieval (default, offline, deterministic - safest for a live demo)
  * Claude, grounded: the same retrieved clauses are passed to Claude to phrase
    the answer. Enabled only if ANTHROPIC_API_KEY is set in Streamlit secrets.
"""
from __future__ import annotations

import math
import re
from collections import Counter

import engine as E
import seed_data as sd

STOP = set("a an the of to in on for and or is are be i my me we our it this that do does can with by at as what why how when who which should would could if not from has have been before after any".split())
ACTION_PATTERN = re.compile(
    r"^\s*(please|can you|could you|go ahead|kindly|just)?\s*(close|approve|accept|mark|lower|downgrade|change|reassign|delete|extend)\b.*\b(task|ticket|exception|rating|priority|risk|deadline|t-\d+)",
    re.I)
REFERRAL_THRESHOLD = 3.0


def _stem(w):
    for suf in ("ing", "ed", "es", "s", "e"):
        if len(w) > 4 and w.endswith(suf):
            return w[: -len(suf)]
    return w


def _tok(text):
    return [_stem(w) for w in re.findall(r"[a-z0-9]+", text.lower()) if w not in STOP]


class BM25:
    def __init__(self, docs, k1=1.4, b=0.7):
        self.docs = [_tok(d) for d in docs]
        self.k1, self.b = k1, b
        self.avg = sum(len(d) for d in self.docs) / len(self.docs)
        df = Counter(w for d in self.docs for w in set(d))
        n = len(self.docs)
        self.idf = {w: math.log(1 + (n - f + 0.5) / (f + 0.5)) for w, f in df.items()}
        self.tf = [Counter(d) for d in self.docs]

    def scores(self, query):
        q = _tok(query)
        out = []
        for i, d in enumerate(self.docs):
            s = 0.0
            for w in q:
                if w in self.tf[i]:
                    f = self.tf[i][w]
                    s += self.idf.get(w, 0) * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * len(d) / self.avg))
            out.append(s)
        return out


KB = sd.KNOWLEDGE_BASE
_INDEX = BM25([f"{c['heading']} {c['heading']} {c['keywords']} {c['keywords']} {c['text']}" for c in KB])
KB_BY_ID = {c["id"]: c for c in KB}


def retrieve(query, k=3):
    sc = _INDEX.scores(query)
    ranked = sorted(range(len(KB)), key=lambda i: -sc[i])
    return [(KB[i], sc[i]) for i in ranked[:k] if sc[i] > 0]


def cite(c):
    return f"{c['doc']} §{c['section']} (v{c['version']})"


def case_facts(S, tid):
    """Facts about a selected task, drawn from the tracker and the risk model."""
    if not tid or tid not in S["tasks"]:
        return []
    t = S["tasks"][tid]
    facts = [f"{tid} is {t['priority']} and {t['state'].lower()}, due {t['due_at']:%d %b %H:%M} (fixed from the advisory time)."]
    rejected = [s for s in t["submissions"] if s["status"] in ("Rejected by system", "Rejected by reviewer")]
    if rejected:
        s = rejected[-1]
        fails = [c for c in s.get("checks", []) if not c[1]]
        if fails:
            facts.append(f"Your submission {s['id']} at {s['at']:%d %b %H:%M} was rejected because: "
                         + "; ".join(f"{c[0].lower()} ({c[2]})" for c in fails) + ".")
        elif s.get("review"):
            facts.append(f"Your submission {s['id']} was returned by the reviewer: {s['review']['reason']}")
    if t["asset_id"] in S["assumptions"]:
        pub = E.published_estimate(S, t["asset_id"])
        live = E.compute_estimate(S, t["asset_id"])
        if pub:
            facts.append(f"The published estimate for {t['asset_id']} is {E.money(pub['eal'])} ({pub['band']} band) from the {pub['run_at']:%d %b %H:%M} run.")
            if live["eal"] != pub["eal"]:
                facts.append(f"Evidence has changed since then; the next 02:00 run will publish {E.money(live['eal'])} ({live['band']}).")
            else:
                weak = [E.FACTORS[k] for k, v in live["factors"].items() if v[0] != "Passed"]
                if weak:
                    facts.append("The estimate cannot fall yet because these factors have not passed: " + ", ".join(weak) + ".")
    return facts


def answer(S, persona, question, tid=None, use_llm=False, api_key=None, model=None):
    """Return a logged answer dict. Never changes task, exception or rating state."""
    q = question.strip()
    entry = {"at": S["now"], "persona": persona, "question": q, "task": tid, "answer": "", "citations": [],
             "referred": False, "reason": "", "mode": "Grounded retrieval"}
    if ACTION_PATTERN.search(q):
        entry.update(referred=True, reason="Action request",
                     answer="I can't take actions. Closing tasks, approving exceptions and changing ratings happen in the "
                            "Resolution tracker and Risk calculator, where the backend checks permissions. "
                            "I have logged this request for Compliance in case the procedure is unclear.")
        S["assistant_log"].append(entry)
        return entry
    hits = retrieve(q)
    if not hits or hits[0][1] < REFERRAL_THRESHOLD:
        entry.update(referred=True, reason="No approved guidance found",
                     answer="I couldn't find an approved clause that answers this, so I've referred it to Compliance "
                            f"({S['people'][S['directory']['compliance']]['name']}). I won't guess.")
        S["assistant_log"].append(entry)
        return entry
    ids = {c["id"] for c, _ in hits}
    # A clause that declares a conflict triggers referral when it is retrieved
    # alongside the clause it conflicts with, or when it is the best match.
    conflict = next(((c, KB_BY_ID[c["conflicts_with"]]) for i, (c, _) in enumerate(hits)
                     if c.get("conflicts_with") and (c["conflicts_with"] in ids or i == 0)), None)
    if conflict:
        a, b = conflict
        entry.update(referred=True, reason="Conflicting clauses", citations=[cite(a), cite(b)],
                     answer=f"Two approved documents point different ways: {cite(a)} says \"{a['summary']}\" while "
                            f"{cite(b)} says \"{b['summary']}\" I've referred this to Compliance to rule on which applies; "
                            "until then, treat the stricter security deadline as binding and raise an emergency change request.")
        S["assistant_log"].append(entry)
        return entry
    top = [c for c, s in hits if s >= REFERRAL_THRESHOLD * 0.6][:2]
    facts = case_facts(S, tid)
    entry["citations"] = [cite(c) for c in top]
    if use_llm and api_key:
        try:
            entry["answer"] = _claude(q, top, facts, api_key, model)
            entry["mode"] = "Claude, grounded"
        except Exception as exc:  # fall back silently to the deterministic answer
            entry["reason"] = f"Claude unavailable ({type(exc).__name__}); used grounded retrieval"
    if not entry["answer"]:
        parts = [top[0]["summary"] + f" [{cite(top[0])}]"]
        if len(top) > 1:
            parts.append(f"Related: {top[1]['summary']} [{cite(top[1])}]")
        if facts:
            parts.append("For this case: " + " ".join(facts))
        entry["answer"] = "\n\n".join(parts)
    S["assistant_log"].append(entry)
    return entry


def _claude(question, clauses, facts, api_key, model):
    import anthropic  # optional dependency

    client = anthropic.Anthropic(api_key=api_key)
    context = "\n\n".join(f"[{cite(c)}] {c['heading']}: {c['text']}" for c in clauses)
    case = "\n".join(facts) if facts else "No case selected."
    msg = client.messages.create(
        model=model or "claude-haiku-5-5",
        max_tokens=400,
        system=("You are Equifax's governed compliance assistant. Answer only from the clauses provided and the case facts. "
                "Cite every rule in square brackets exactly as given, e.g. [POL-VM-01 §4.2 (v3.2)]. "
                "You cannot take actions or approve anything. If the clauses do not answer the question, say it is referred to Compliance. "
                "Keep answers under 120 words, plain English."),
        messages=[{"role": "user", "content": f"Clauses:\n{context}\n\nCase facts:\n{case}\n\nQuestion: {question}"}],
    )
    return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text").strip()


def run_evaluation(S):
    """Score the assistant against the Compliance-approved test set without logging to the live record."""
    import copy
    scratch = copy.deepcopy(S)
    results = []
    for case in sd.ASSISTANT_TEST_SET:
        r = answer(scratch, "evaluation", case["q"])
        cited_ids = [next(c["id"] for c in KB if cite(c) == x) for x in r["citations"]]
        cite_ok = (not case["expect"]) or any(i in case["expect"] for i in cited_ids)
        ref_ok = r["referred"] == case["referral"]
        results.append({"Question": case["q"], "Expected": ", ".join(case["expect"]) or "none (refer)",
                        "Cited": ", ".join(cited_ids) or "-", "Referred": "Yes" if r["referred"] else "No",
                        "Citation correct": cite_ok, "Referral correct": ref_ok, "Pass": cite_ok and ref_ok})
    return results
