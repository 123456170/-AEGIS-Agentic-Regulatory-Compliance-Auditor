"""
AEGIS — Agentic Regulatory Compliance Auditor
Single-file Streamlit demo. Auto-seeds realistic data, auto-starts a live
four-agent simulation (plan -> act -> observe -> reflect), fully interactive.
No API keys. No external calls. All connectors simulated read-only.
"""
from __future__ import annotations

import csv
import hashlib
import html
import inspect
import io
import json
import random
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

import plotly.graph_objects as go
import streamlit as st

# ----------------------------------------------------------------------------- compat
RERUN = getattr(st, "rerun", None) or getattr(st, "experimental_rerun")
HAS_FRAGMENT = hasattr(st, "fragment")
S = st.session_state
esc = html.escape


def wide_chart(fig, key):
    if "width" in inspect.signature(st.plotly_chart).parameters:
        st.plotly_chart(fig, width="stretch", key=key, config={"displayModeBar": False})
    else:
        st.plotly_chart(fig, use_container_width=True, key=key, config={"displayModeBar": False})


# ----------------------------------------------------------------------------- palette
INK, DIM, LINE = "#0F172A", "#5B6B82", "#D9E1EE"
CYAN, VIOLET, GREEN, EMERALD = "#0891B2", "#7C3AED", "#65A30D", "#059669"
AMBER, ROSE, BLUE, MAGENTA = "#D97706", "#E11D48", "#2563EB", "#DB2777"
SEV_C = {"critical": ROSE, "high": AMBER, "medium": VIOLET, "low": BLUE}
PH_C = {"PLAN": VIOLET, "ACT": CYAN, "OBSERVE": BLUE, "REFLECT": EMERALD, "IDLE": "#64748B", "FEED": AMBER}
PHASES = ["PLAN", "ACT", "OBSERVE", "REFLECT"]

DEFAULTS = dict(speed=0.8, volatility=0.45, autonomy="Act with approval", model="Balanced",
                conf=0.72, depth=2, max_steps=8, budget_k=600, defense=True, stale_guard=True, seed=42)
AUTONOMY = ["Suggest only", "Act with approval", "Act & notify", "Fully autonomous"]
PROFILES = {
    "Fast":     dict(p_correct=0.86, p_fp=0.12, wrong_mu=0.68, cost=0.7, passes=1, p_false=0.10),
    "Balanced": dict(p_correct=0.93, p_fp=0.06, wrong_mu=0.66, cost=1.0, passes=1, p_false=0.07),
    "Strict":   dict(p_correct=0.97, p_fp=0.02, wrong_mu=0.60, cost=1.6, passes=2, p_false=0.04),
}
PROFILE_LABEL = {"Fast": "Fast · 0.7× cost · lower precision",
                 "Balanced": "Balanced · router default",
                 "Strict": "Strict · 1.6× cost · double-pass verify"}

# ----------------------------------------------------------------------------- seed corpus
REGS = [
    dict(id="DORA", short="DORA", name="Digital Operational Resilience Act", juris="EU 🇪🇺", weight=5, ver="RTS 2024/1774", obs=[
        ("Art. 6(1)", "Maintain a documented ICT risk-management framework approved by the management body.", ["CM-01", "IR-01", "BC-02"], 5),
        ("Art. 19(4)", "Report major ICT incidents to the competent authority within 4 hours of classification.", ["IR-02", "LG-01"], 5),
        ("Art. 28(3)", "Maintain a register of ICT third-party providers with contractual risk assessments.", ["TP-01"], 4)]),
    dict(id="GDPR", short="GDPR", name="General Data Protection Regulation", juris="EU 🇪", weight=5, ver="Art. 32 guidance", obs=[
        ("Art. 32(1)(a)", "Encrypt personal data at rest and in transit using state-of-the-art cryptography.", ["CR-01", "CR-02"], 5),
        ("Art. 32(1)(b)", "Restrict and regularly review access to personal data processing systems.", ["AC-01", "AC-02"], 4),
        ("Art. 5(1)(e)", "Enforce retention limits and verified deletion of personal data.", ["DS-01"], 4)]),
    dict(id="NIS2", short="NIS2", name="NIS2 Directive", juris="EU 🇪🇺", weight=4, ver="2022/2555", obs=[
        ("Art. 23(4)(a)", "Submit an early warning to the CSIRT within 24 hours of a significant incident.", ["IR-02", "LG-01"], 5),
        ("Art. 21(2)(d)", "Apply supply-chain security controls to direct suppliers and service providers.", ["TP-01"], 4),
        ("Art. 21(2)(j)", "Enforce multi-factor authentication for privileged and remote access.", ["AC-01", "AC-02"], 4)]),
    dict(id="PCI", short="PCI DSS", name="PCI DSS 4.0.1", juris="Global 🌐", weight=5, ver="4.0.1", obs=[
        ("Req. 10.5.1", "Retain audit logs for at least 12 months with 3 months immediately available.", ["LG-02", "LG-01"], 5),
        ("Req. 7.2.4", "Review all user accounts and privileges at least quarterly.", ["AC-02"], 4),
        ("Req. 6.5.1", "Route all production changes through documented change control.", ["CM-01"], 4)]),
    dict(id="SOC2", short="SOC 2", name="SOC 2 Trust Services Criteria", juris="US 🇺🇸", weight=3, ver="CC series 2022", obs=[
        ("CC6.1", "Enforce MFA and logical access controls over protected information assets.", ["AC-01"], 4),
        ("CC7.4", "Test the incident response program at least annually.", ["IR-01"], 3),
        ("CC9.1", "Verify backup restoration through periodic restore testing.", ["BC-01"], 3)]),
    dict(id="ISO", short="ISO 27001", name="ISO/IEC 27001:2022 Amd 1", juris="Global 🌐", weight=3, ver="2022/Amd1:2024", obs=[
        ("A.8.24", "Manage cryptographic keys with documented rotation and custodianship.", ["CR-01"], 3),
        ("A.6.3", "Deliver security awareness training and track completion.", ["TR-01"], 3),
        ("A.8.14", "Evidence redundancy and failover meeting the declared RTO.", ["BC-02"], 4)]),
    dict(id="HIPAA", short="HIPAA", name="HIPAA Security Rule NPRM", juris="US 🇺", weight=4, ver="NPRM 2025", obs=[
        ("§164.312(b)", "Maintain audit controls and tamper-evident log retention for ePHI systems.", ["LG-02"], 4),
        ("§164.312(a)(2)(iv)", "Encrypt ePHI at rest with managed key lifecycle.", ["CR-01"], 5),
        ("§164.308(a)(5)", "Train the workforce on security procedures and evidence completion.", ["TR-01"], 3)]),
    dict(id="AIAct", short="EU AI Act", name="EU AI Act — high-risk obligations", juris="EU 🇪", weight=3, ver="Art. 15", obs=[
        ("Art. 12", "Enable automatic logging of high-risk AI system operation over its lifetime.", ["LG-01"], 3),
        ("Art. 15(4)", "Apply change management and resilience testing to model releases.", ["CM-01"], 3),
        ("Art. 15(5)", "Assess third-party model and data provider risk.", ["TP-01"], 3)]),
    dict(id="NYDFS", short="NYDFS 500", name="NYDFS Part 500 Cybersecurity", juris="US-NY 🇺🇸", weight=4, ver="Amend. 2023", obs=[
        ("§500.12", "Require MFA for any individual accessing internal networks.", ["AC-01"], 5),
        ("§500.17(a)", "Notify the superintendent within 72 hours of a cybersecurity event.", ["IR-02"], 5),
        ("§500.5", "Perform annual penetration testing and controlled remediation changes.", ["CM-01", "BC-01"], 4)]),
]
REG_BY = {r["id"]: r for r in REGS}

CONTROLS = [
    dict(id="AC-01", name="MFA enforcement", owner="Priya Raman", team="IAM", domain="Access", src="Okta policy export", kind="config", ttl=42),
    dict(id="AC-02", name="Privileged access review", owner="Marcus Webb", team="IAM", domain="Access", src="Okta access-review report", kind="attestation", ttl=42),
    dict(id="CM-01", name="Change management", owner="Elena Sorensen", team="Platform", domain="Change", src="Jira change tickets", kind="log", ttl=36),
    dict(id="CR-01", name="Encryption at rest + key rotation", owner="Diego Fuentes", team="SecEng", domain="Crypto", src="AWS KMS rotation report", kind="config", ttl=48),
    dict(id="CR-02", name="TLS in transit", owner="Diego Fuentes", team="SecEng", domain="Crypto", src="Load-balancer TLS config", kind="config", ttl=48),
    dict(id="LG-01", name="Centralized audit logging", owner="Amara Okafor", team="SecOps", domain="Logging", src="Splunk ingest config", kind="config", ttl=36),
    dict(id="LG-02", name="Log retention ≥ 365 days", owner="Amara Okafor", team="SecOps", domain="Logging", src="S3 lifecycle policy", kind="config", ttl=48),
    dict(id="IR-01", name="Incident response runbook + drills", owner="Sofia Petrov", team="SecOps", domain="Response", src="PagerDuty drill log", kind="drill", ttl=60),
    dict(id="IR-02", name="Breach notification ≤ 24h", owner="Sofia Petrov", team="SecOps", domain="Response", src="Incident timeline export", kind="log", ttl=36),
    dict(id="BC-01", name="Backup & restore testing", owner="Tom Aldana", team="SRE", domain="Resilience", src="Veeam restore-test report", kind="drill", ttl=60),
    dict(id="BC-02", name="DR runbook · RTO 4h", owner="Tom Aldana", team="SRE", domain="Resilience", src="DR failover drill log", kind="drill", ttl=60),
    dict(id="TP-01", name="Vendor risk assessments", owner="Hannah Liu", team="GRC", domain="Third-party", src="OneTrust vendor register", kind="policy", ttl=60),
    dict(id="TR-01", name="Security awareness training", owner="Rachel Kim", team="PeopleOps", domain="People", src="LMS completion export", kind="attestation", ttl=90),
    dict(id="DS-01", name="Data retention & deletion", owner="Hannah Liu", team="GRC", domain="Data", src="Data-catalog retention rules", kind="policy", ttl=60),
]
CTL_BY = {c["id"]: c for c in CONTROLS}

AGENTS = {
    "mon": dict(name="Regulation Change Monitor", icon="📡", short="MON"),
    "map": dict(name="Control Mapping Engine", icon="🧭", short="MAP"),
    "evi": dict(name="Evidence Collection Agent", icon="🗄️", short="EVI"),
    "gap": dict(name="Gap Analysis & Remediation", icon="🩺", short="GAP"),
}
PLANS = {
    "UNMAPPED": ("Design or map control", ["Review obligation text against control objectives", "Map {ctrl} or document a compensating control", "Route to {owner} for design sign-off"], 14),
    "NO_EVIDENCE": ("Collect missing evidence", ["Grant read-only scope to {src}", "Schedule collection job for {ctrl}", "Attach sealed artefact to obligation {ob}"], 7),
    "STALE_EVIDENCE": ("Refresh stale evidence", ["Re-collect {src} — artefact older than TTL", "Verify sha256 seal and provenance chain", "Re-score coverage for {ctrl}"], 3),
    "PARTIAL_EVIDENCE": ("Complete evidence set", ["Extend sampling window to 90 days", "Add missing artefacts (config + logs)", "Request owner attestation from {owner}"], 10),
}
TYPE_W = {"UNMAPPED": 0.90, "NO_EVIDENCE": 0.80, "STALE_EVIDENCE": 0.55, "PARTIAL_EVIDENCE": 0.50}
PHASE_TOK = {"PLAN": 380, "ACT": 920, "OBSERVE": 240, "REFLECT": 410}

# ----------------------------------------------------------------------------- engine helpers
def nid(w, p):
    w["seq"][p] += 1
    return f"{p}-{w['seq'][p]:03d}"


def emit(w, agent, phase, msg, tool="", tok=0, kind="info"):
    w["events"].appendleft(dict(t=w["clock"].strftime("%H:%M"), tick=w["tick"], agent=agent,
                                phase=phase, msg=msg, tool=tool, tok=tok, kind=kind))


def spend(w, cfg, phase, scale=1.0):
    tok = int(PHASE_TOK[phase] * PROFILES[cfg["model"]]["cost"] * w["rng"].uniform(0.85, 1.15) * scale)
    w["tokens"] += tok
    return tok


def clamp(x, lo, hi):
    return max(lo, min(hi, x))


def evi_state(w, ctrl):
    e = w["store"].get(ctrl)
    if not e:
        return "none", None
    if w["tick"] - e["tick"] > e["ttl"]:
        return "stale", e
    return e["suff"], e


def add_approval(w, kind, payload, conf, reason):
    ap = dict(id=nid(w, "A"), kind=kind, payload=payload, conf=conf, reason=reason,
              tick=w["tick"], status="pending")
    w["approvals"].append(ap)
    return ap


def make_gap(w, ob, ctrl, gtype, hidden_false=False):
    for g in w["gaps"]:
        if g["ob"] == ob["id"] and g["ctrl"] == ctrl and g["type"] == gtype and \
           g["status"] in ("open", "task_created", "pending_recheck"):
            return None
    score = round(TYPE_W[gtype] * ob["crit"] / 5 * 100)
    sev = "critical" if score >= 75 else "high" if score >= 55 else "medium" if score >= 35 else "low"
    c = CTL_BY[ctrl]
    title, steps, days = PLANS[gtype]
    g = dict(id=nid(w, "G"), ob=ob["id"], ctrl=ctrl, type=gtype, sev=sev, score=score,
             status="open", false=hidden_false, revealed=False, owner=c["owner"],
             due=(w["clock"] + timedelta(days=days)).strftime("%d %b"),
             title=f"{title} · {ctrl}",
             plan=[s.format(ctrl=ctrl, src=c["src"], owner=c["owner"], ob=ob["id"]) for s in steps],
             tick=w["tick"], task=None)
    w["gaps"].append(g)
    return g


def create_task(w, g):
    t = dict(id=nid(w, "T"), gap=g["id"], title=g["title"], owner=g["owner"], prio=g["sev"],
             status="todo", due=g["due"], steps=g["plan"], tick=w["tick"])
    w["tasks"].append(t)
    g["status"] = "task_created"
    g["task"] = t["id"]
    return t


def route_gap(w, cfg, g):
    a = cfg["autonomy"]
    if a == "Suggest only" or (a == "Act with approval" and g["sev"] in ("critical", "high")) \
       or (a == "Act & notify" and g["sev"] == "critical"):
        add_approval(w, "gap", {"gap": g["id"]}, g["score"] / 100,
                     f"{g['sev'].upper()} severity requires human sign-off ({a})")
        return "approval"
    create_task(w, g)
    if a == "Act & notify":
        emit(w, "gap", "REFLECT", f"notify: #compliance-alerts ← {g['id']} task auto-drafted", kind="ok")
    return "task"


def enqueue_update(w, forced=False):
    rng = w["rng"]
    reg = rng.choices(REGS, weights=[r["weight"] for r in REGS])[0]
    kind = rng.choices(["AMENDMENT", "GUIDANCE", "NEW"], weights=[0.5, 0.3, 0.2])[0]
    st_ = w["regs"][reg["id"]]
    st_["updates"] += 1
    ver = f"{reg['ver']} · rev{st_['updates']}" if kind == "AMENDMENT" else reg["ver"]
    templates = rng.sample(reg["obs"], k=rng.randint(1, min(3, len(reg["obs"]))))
    u = dict(id=nid(w, "U"), reg=reg["id"], kind=kind, ver=ver, tick=w["tick"], stale=False,
             status="detected", obs=[])
    u["title"] = {"AMENDMENT": f"{reg['short']}: amendment to {templates[0][0]}",
                  "GUIDANCE": f"{reg['short']}: supervisory guidance issued",
                  "NEW": f"{reg['short']}: delegated act published"}[kind]
    u["summary"] = {"AMENDMENT": f"Changed text detected in {reg['name']} — obligation scope or deadline shifted.",
                    "GUIDANCE": f"Regulator clarified expectations under {reg['name']}; evidentiary bar raised.",
                    "NEW": f"New binding instrument under {reg['name']} enters the monitoring perimeter."}[kind]
    for ref, text, ctrls, crit in templates:
        ob = dict(id=nid(w, "O"), reg=reg["id"], ref=ref, text=text, crit=crit, true=list(ctrls),
                  status="extracted", tick=w["tick"], ver=ver, stale=False)
        w["obligations"][ob["id"]] = ob
        u["obs"].append(ob["id"])
    w["updates"].append(u)
    w["queues"]["mon"].append(u)
    emit(w, "sys", "FEED", f"📡 {u['title']} · {reg['juris']} · {len(u['obs'])} candidate obligations",
         tool="watch.sources", kind="warn" if forced else "info")
    return u


def pull_queue(w, key):
    if key == "evi" and w["rechecks"]:
        return w["rechecks"].popleft()
    q = w["queues"][key]
    if not q:
        return None
    if key == "gap":
        for i, it in enumerate(q):
            if it["ready"] <= w["tick"]:
                del q[i]
                return it
        return None
    return q.popleft()


def preds_of(w, ob_id, decided_only=True):
    return [m for m in w["mappings"] if m["ob"] == ob_id and
            (not decided_only or m["status"] in ("auto", "approved"))]


def item_label(w, key, item):
    if item is None:
        return "Standing by — queue empty"
    if key == "mon":
        return item["title"]
    if key == "map":
        ob = w["obligations"][item["ob"]]
        return f"{ob['id']} · {ob['ref']} ({REG_BY[ob['reg']]['short']})"
    if key == "evi":
        tag = " · re-verify" if item.get("recheck") else ""
        return f"{item['ctrl']} · {CTL_BY[item['ctrl']]['src']}{tag}"
    ob = w["obligations"][item["ob"]]
    return f"{ob['id']} · coverage assessment"


# ----------------------------------------------------------------------------- phase handlers
def h_mon_plan(w, cfg, a, it):
    return (f"Plan diff strategy for {it['id']} · {len(it['obs'])} candidate sections", "plan.parse", "info")


def h_mon_act(w, cfg, a, it):
    reg = REG_BY[it["reg"]]
    kb = w["rng"].randint(60, 480)
    msg, kind = f"Fetched {reg['short']} source · 200 OK · {kb} KB · ver {it['ver']}", "info"
    if w["rng"].random() < 0.07:
        if cfg["stale_guard"]:
            w["security"]["refreshed"] += 1
            msg += " · cache stale → canonical re-fetch (guard)"
            kind = "ok"
        else:
            it["stale"] = True
            w["security"]["stale_src"] += 1
            for oid in it["obs"]:
                w["obligations"][oid]["stale"] = True
            msg += " · served 34-day cached copy"
            kind = "warn"
    return (msg, "fetch_source", kind)


def h_mon_obs(w, cfg, a, it):
    n = w["rng"].randint(1, 6)
    return (f"Diff vs prior version: {n} sections changed · {len(it['obs'])} obligations affected", "diff_versions", "info")


def h_mon_ref(w, cfg, a, it):
    it["status"] = "processed"
    for oid in it["obs"]:
        w["queues"]["map"].append({"ob": oid})
    return (f"Extracted {len(it['obs'])} obligations → Control Mapping queue", "extract_obligations", "ok")


def h_map_plan(w, cfg, a, it):
    ob = w["obligations"][it["ob"]]
    return (f"Embed {ob['ref']} · retrieve top-8 candidate controls (semantic memory)", "vector_search", "info")


def h_map_act(w, cfg, a, it):
    rng, prof = w["rng"], PROFILES[cfg["model"]]
    ob = w["obligations"][it["ob"]]
    p_miss = (1 - prof["p_correct"]) + (0.15 if ob["stale"] else 0)
    preds = []
    for ctrl in ob["true"]:
        if rng.random() >= p_miss:
            preds.append((ctrl, clamp(rng.gauss(0.90, 0.05), 0.55, 0.99), True))
    others = [c["id"] for c in CONTROLS if c["id"] not in ob["true"]]
    for ctrl in rng.sample(others, 2):
        if rng.random() < prof["p_fp"]:
            preds.append((ctrl, clamp(rng.gauss(prof["wrong_mu"], 0.10), 0.40, 0.90), False))
            break
    it["preds"] = preds
    best = max((p[1] for p in preds), default=0)
    return (f"rank_controls → {len(preds)} candidates · best confidence {best:.2f}", "rank_controls", "info")


def h_map_obs(w, cfg, a, it):
    return (f"Schema v1.2 valid · provenance attached · {len(it.get('preds', []))} links staged", "validate_schema", "info")


def h_map_ref(w, cfg, a, it):
    ob = w["obligations"][it["ob"]]
    reg = REG_BY[ob["reg"]]
    thr = cfg["conf"] + (0.08 if cfg["autonomy"] == "Suggest only" else 0)
    review = 0
    for ctrl, conf, correct in it.get("preds", []):
        m = dict(id=nid(w, "M"), ob=ob["id"], ctrl=ctrl, conf=round(conf, 2), correct=correct,
                 status="auto", tick=w["tick"],
                 why=f"Objective overlap {conf:.0%} · domain {CTL_BY[ctrl]['domain']}",
                 prov=f"{reg['short']} {ob['ref']} ⇄ {ctrl} · ranker v2.1")
        if cfg["autonomy"] != "Fully autonomous" and conf < thr:
            m["status"] = "needs_review"
            review += 1
            add_approval(w, "mapping", {"map": m["id"]}, conf, f"Confidence {conf:.2f} below floor {thr:.2f}")
        elif conf < thr:
            emit(w, "map", "REFLECT", f"low-confidence link {m['id']} auto-accepted under full autonomy", kind="warn")
        w["mappings"].append(m)
        state, _ = evi_state(w, ctrl)
        if m["status"] in ("auto", "approved") and state == "sufficient":
            emit(w, "evi", "OBSERVE", f"cache hit · {ctrl} evidence fresh — collection skipped", tool="cache.lookup", kind="ok")
        else:
            w["queues"]["evi"].append(dict(ctrl=ctrl, ob=ob["id"], gap=None, recheck=False))
    ob["status"] = "mapped"
    w["queues"]["gap"].append(dict(ob=ob["id"], ready=w["tick"] + 2))
    return (f"{len(it.get('preds', []))} links committed · {review} routed to human review", "commit_links",
            "warn" if review else "ok")


def h_evi_plan(w, cfg, a, it):
    return (f"Scoped read-only credential for {CTL_BY[it['ctrl']]['src']} · least privilege · ttl 15m",
            "scope_credentials", "info")


def h_evi_act(w, cfg, a, it):
    rng = w["rng"]
    src = CTL_BY[it["ctrl"]]["src"]
    p_ok = min(0.98, 0.86 + 0.04 * cfg["depth"] + (0.05 if it.get("recheck") else 0))
    if rng.random() > p_ok:
        a["retry"] += 1
        a["hold"] = True
        if a["retry"] >= 3:
            add_approval(w, "collection", {"item": dict(it)}, 0.30, f"{src} unreachable after 3 retries")
            a["item"], a["status"], a["phase"] = None, "idle", -1
            return (f"Timeout pulling {src} · retries exhausted → human review", "pull_config", "warn")
        return (f"Timeout pulling {src} · retry {a['retry']}/3", "pull_config", "warn")
    it["poisoned"] = False
    if not it.get("recheck") and rng.random() < 0.05:
        if cfg["defense"]:
            w["security"]["inj_blocked"] += 1
            return (f"🛡 Prompt-injection quarantined in {src} — instructions stripped, content sandboxed",
                    "pull_config", "inj")
        w["security"]["inj_hit"] += 1
        it["poisoned"] = True
        if it.get("ob"):
            other = rng.choice([c["id"] for c in CONTROLS if c["id"] != it["ctrl"]])
            w["mappings"].append(dict(id=nid(w, "M"), ob=it["ob"], ctrl=other, conf=0.50, correct=False,
                                      status="auto", tick=w["tick"],
                                      why="⚠ influenced by untrusted retrieved content", prov="UNTRUSTED"))
            return (f"⚠ Injected instruction executed from {src} — rogue link → {other}", "pull_config", "inj")
        return (f"⚠ Injected instruction executed from {src} — plan altered", "pull_config", "inj")
    kb = rng.randint(40, 900)
    it["kb"] = kb
    return (f"Pulled {src} · {kb} KB · read-only · depth {cfg['depth']}", "pull_config", "info")


def h_evi_obs(w, cfg, a, it):
    rng = w["rng"]
    if it.get("poisoned"):
        suff = "insufficient"
    elif it.get("recheck"):
        suff = "sufficient" if rng.random() < 0.95 else "partial"
    else:
        r = rng.random()
        suff = "sufficient" if r < 0.78 else "partial" if r < 0.95 else "insufficient"
    c = CTL_BY[it["ctrl"]]
    sha = hashlib.sha256(f"{it['ctrl']}{w['tick']}{rng.random()}".encode()).hexdigest()
    it["rec"] = dict(id=nid(w, "E"), ctrl=it["ctrl"], src=c["src"], kind=c["kind"], sha=sha,
                     short=sha[:12], tick=w["tick"], ttl=c["ttl"], suff=suff, kb=it.get("kb", 120),
                     prov=f"{c['src']} · read-only · evi-agent · tick {w['tick']}")
    return (f"Sealed sha256:{sha[:10]}… · sufficiency={suff}", "hash_seal",
            "ok" if suff == "sufficient" else "warn")


def h_evi_ref(w, cfg, a, it):
    rec = it.get("rec")
    if rec is None:
        return ("No artefact to commit — collection aborted", "commit", "warn")
    w["store"][rec["ctrl"]] = rec
    w["evidence_log"].append(rec)
    w["evidence_log"] = w["evidence_log"][-240:]
    if it.get("gap"):
        g = next((x for x in w["gaps"] if x["id"] == it["gap"]), None)
        if g:
            if rec["suff"] == "sufficient":
                g["status"] = "closed"
                return (f"🔁 Re-verified {rec['ctrl']} → gap {g['id']} CLOSED", "commit", "ok")
            g["status"] = "open"
            return (f"Re-verification insufficient — gap {g['id']} reopened", "commit", "warn")
    return (f"Evidence stored for {rec['ctrl']} · coverage updated", "commit", "ok")


def h_gap_plan(w, cfg, a, it):
    ob = w["obligations"][it["ob"]]
    return (f"Assembling coverage picture for {ob['ref']} · {len(preds_of(w, ob['id']))} mapped controls",
            "plan.assess", "info")


def h_gap_act(w, cfg, a, it):
    ob = w["obligations"][it["ob"]]
    preds = {m["ctrl"] for m in preds_of(w, ob["id"])}
    findings = []
    for ctrl in ob["true"]:
        if ctrl not in preds:
            findings.append((ctrl, "UNMAPPED", False))
            continue
        state, _ = evi_state(w, ctrl)
        if state == "none":
            findings.append((ctrl, "NO_EVIDENCE", False))
        elif state == "stale":
            findings.append((ctrl, "STALE_EVIDENCE", False))
        elif state in ("partial", "insufficient"):
            findings.append((ctrl, "PARTIAL_EVIDENCE", False))
    for ctrl in preds - set(ob["true"]):
        state, _ = evi_state(w, ctrl)
        if state in ("none", "stale"):
            findings.append((ctrl, "NO_EVIDENCE" if state == "none" else "STALE_EVIDENCE", True))
    if not findings and preds and w["rng"].random() < PROFILES[cfg["model"]]["p_false"]:
        findings.append((w["rng"].choice(sorted(preds)), "PARTIAL_EVIDENCE", True))
    it["findings"] = findings
    return (f"score_gap → {len(findings)} findings · exposure {ob['crit']}/5", "score_gap", "info")


def h_gap_obs(w, cfg, a, it):
    crit = sum(1 for c, t, f in it.get("findings", []) if TYPE_W[t] * w["obligations"][it["ob"]]["crit"] / 5 >= 0.75)
    return (f"Severity banding: {crit} critical-tier · false-gap prior {PROFILES[cfg['model']]['p_false']:.0%}",
            "calibrate", "info")


def h_gap_ref(w, cfg, a, it):
    ob = w["obligations"][it["ob"]]
    n = t = r = 0
    for ctrl, gtype, hidden in it.get("findings", []):
        g = make_gap(w, ob, ctrl, gtype, hidden)
        if g is None:
            continue
        n += 1
        if route_gap(w, cfg, g) == "task":
            t += 1
        else:
            r += 1
    ob["status"] = "assessed"
    return (f"{n} gaps filed · {t} remediation tasks drafted · {r} awaiting approval", "draft_plan",
            "warn" if n else "ok")


HANDLERS = {
    "mon": dict(zip(PHASES, [h_mon_plan, h_mon_act, h_mon_obs, h_mon_ref])),
    "map": dict(zip(PHASES, [h_map_plan, h_map_act, h_map_obs, h_map_ref])),
    "evi": dict(zip(PHASES, [h_evi_plan, h_evi_act, h_evi_obs, h_evi_ref])),
    "gap": dict(zip(PHASES, [h_gap_plan, h_gap_act, h_gap_obs, h_gap_ref])),
}


def step_agent(w, cfg, key):
    a = w["agents"][key]
    if a["status"] == "idle":
        item = pull_queue(w, key)
        if item is None:
            return
        a.update(item=item, phase=0, steps=0, sub=0, retry=0, status="running", hold=False)
    phase = PHASES[a["phase"]]
    prof = PROFILES[cfg["model"]]
    a["hold"] = False
    if prof["passes"] == 2 and a["sub"] == 0:
        a["sub"] = 1
        a["steps"] += 1
        tok = spend(w, cfg, phase, 0.5)
        emit(w, key, phase, f"deep verification pass 1/2 · {item_label(w, key, a['item'])}", tok=tok)
    else:
        a["sub"] = 0
        tok = spend(w, cfg, phase)
        msg, tool, kind = HANDLERS[key][phase](w, cfg, a, a["item"])
        a["steps"] += 1
        emit(w, key, phase, msg, tool=tool, tok=tok, kind=kind)
    if a["status"] != "running":
        return
    if a["steps"] > cfg["max_steps"]:
        add_approval(w, "loop", {"agent": key, "item": a["item"]}, 0.4,
                     f"Step budget exceeded ({a['steps']}/{cfg['max_steps']})")
        emit(w, key, "REFLECT", f"loop guard: step budget exceeded → parked for review", kind="warn")
        a.update(item=None, status="idle", phase=-1)
        return
    if a["hold"]:
        return
    if phase == "REFLECT":
        a["processed"] += 1
        a.update(item=None, status="idle", phase=-1)
    else:
        a["phase"] += 1


def recompute(w):
    tp = fp = fn = 0
    mapped_ctrls = set()
    finalized = 0
    for ob in w["obligations"].values():
        if ob["status"] not in ("mapped", "assessed"):
            continue
        finalized += 1
        pred = {m["ctrl"] for m in preds_of(w, ob["id"])}
        true = set(ob["true"])
        tp += len(pred & true)
        fp += len(pred - true)
        fn += len(true - pred)
        mapped_ctrls |= pred
    covered = sum(1 for c in mapped_ctrls if evi_state(w, c)[0] == "sufficient")
    n_gaps = len(w["gaps"])
    n_false = sum(1 for g in w["gaps"] if g["false"])
    cost = w["tokens"] * 8e-6
    w["m"] = dict(
        p=tp / (tp + fp) if tp + fp else 1.0,
        r=tp / (tp + fn) if tp + fn else 1.0,
        cov=covered / len(mapped_ctrls) if mapped_ctrls else 0.0,
        fr=n_false / n_gaps if n_gaps else 0.0,
        tp=tp, fp=fp, fn=fn, covered=covered, mapped=len(mapped_ctrls),
        saved=finalized * 5.42, finalized=finalized, cost=cost, n_gaps=n_gaps, n_false=n_false,
        open_gaps=sum(1 for g in w["gaps"] if g["status"] in ("open", "task_created", "pending_recheck")),
        pending=sum(1 for a in w["approvals"] if a["status"] == "pending"),
    )


def advance(w, cfg):
    w["tick"] += 1
    w["clock"] += timedelta(minutes=2)
    if w["rng"].random() < cfg["volatility"] and len(w["queues"]["mon"]) < 3:
        enqueue_update(w)
    for key in ("mon", "map", "evi", "gap"):
        step_agent(w, cfg, key)
    recompute(w)
    m = w["m"]
    w["history"].append(dict(tick=w["tick"], p=m["p"], r=m["r"], c=m["cov"], f=m["fr"], cost=m["cost"]))
    w["history"] = w["history"][-90:]
    if w["tokens"] >= cfg["budget_k"] * 1000 and w["running"]:
        w["running"] = False
        w["halt_reason"] = "budget"
        emit(w, "sys", "FEED", "⛔ KILL SWITCH — token budget exhausted, all agents paused", kind="kill")


# ----------------------------------------------------------------------------- world build
def build_world(seed):
    w = dict(seed=seed, rng=random.Random(seed), tick=0, clock=datetime(2026, 11, 13, 8, 0),
             running=True, halt_reason=None, last_adv=0.0, step_request=False,
             regs={r["id"]: dict(updates=0) for r in REGS},
             updates=[], obligations={}, mappings=[], gaps=[], tasks=[], approvals=[],
             events=deque(maxlen=160), history=[], store={}, evidence_log=[],
             queues={k: deque() for k in ("mon", "map", "evi", "gap")}, rechecks=deque(),
             agents={k: dict(phase=-1, item=None, steps=0, sub=0, retry=0, processed=0,
                             status="idle", hold=False) for k in AGENTS},
             tokens=0, seq=defaultdict(int), decided=0,
             security=dict(inj_blocked=0, inj_hit=0, stale_src=0, refreshed=0), m={})
    emit(w, "sys", "FEED", "Workspace initialised · 9 regulatory sources · 14 controls · tenant demo-eu-1")
    emit(w, "sys", "FEED", "Read-only connectors registered: Okta · AWS · Splunk · Jira · PagerDuty · Veeam · OneTrust · LMS")
    emit(w, "sys", "FEED", "Policy loaded · autonomy='Act with approval' · confidence floor 0.72")
    baseline = [("DORA", 0), ("GDPR", 0), ("PCI", 0), ("SOC2", 0)]
    for rid, oi in baseline:
        reg = REG_BY[rid]
        ref, text, ctrls, crit = reg["obs"][oi]
        ob = dict(id=nid(w, "O"), reg=rid, ref=ref, text=text, crit=crit, true=list(ctrls),
                  status="assessed", tick=0, ver=reg["ver"], stale=False)
        w["obligations"][ob["id"]] = ob
        for ctrl in ctrls:
            c = CTL_BY[ctrl]
            w["mappings"].append(dict(id=nid(w, "M"), ob=ob["id"], ctrl=ctrl, conf=0.94, correct=True,
                                      status="auto", tick=0,
                                      why="Objective overlap 94% · historical audit import",
                                      prov=f"{reg['short']} {ref} ⇄ {ctrl} · ranker v2.1"))
            suff = "partial" if ctrl == "LG-02" else "sufficient"
            tick = -999 if ctrl == "BC-02" else -5
            sha = hashlib.sha256(f"base{ctrl}".encode()).hexdigest()
            w["store"][ctrl] = dict(id=nid(w, "E"), ctrl=ctrl, src=c["src"], kind=c["kind"], sha=sha,
                                    short=sha[:12], tick=tick, ttl=c["ttl"], suff=suff, kb=210,
                                    prov=f"{c['src']} · read-only · baseline import")
            w["evidence_log"].append(w["store"][ctrl])
    ob0 = next(o for o in w["obligations"].values() if "BC-02" in o["true"])
    g = make_gap(w, ob0, "BC-02", "STALE_EVIDENCE")
    create_task(w, g)
    emit(w, "mon", "FEED", "Historical baseline imported · 4 obligations · 8 evidence artefacts · 1 stale drill log", kind="ok")
    return w


def ensure_richness(w, cfg):
    if not any(a["status"] == "pending" for a in w["approvals"]):
        m = next((m for m in w["mappings"] if m["status"] == "auto"), None)
        if m:
            m["status"] = "needs_review"
            m["conf"] = round(min(m["conf"], cfg["conf"] - 0.06), 2)
            add_approval(w, "mapping", {"map": m["id"]}, m["conf"],
                         f"Confidence {m['conf']:.2f} below floor {cfg['conf']:.2f}")
    if not w["tasks"]:
        g = next((g for g in w["gaps"] if g["status"] == "open"), None)
        if g:
            create_task(w, g)
    if w["tasks"] and all(t["status"] == "todo" for t in w["tasks"]):
        w["tasks"][0]["status"] = "in_progress"
    recompute(w)


def rebuild(seed):
    w = build_world(int(seed))
    for _ in range(14):
        advance(w, DEFAULTS)
    ensure_richness(w, DEFAULTS)
    w["last_adv"] = time.time()
    S["world"] = w


# ----------------------------------------------------------------------------- exports
def gap_report_md(w, cfg):
    m = w["m"]
    lines = [f"# Aegis — Control-Gap Report",
             f"_Generated {w['clock'].strftime('%a %d %b %Y %H:%M UTC')} · tick {w['tick']} · tenant demo-eu-1 (synthetic demo)_",
             "", "## 1. Executive metrics",
             "| Metric | Value | Target |", "|---|---|---|",
             f"| Mapping precision | {m['p']:.1%} | ≥ 92% |",
             f"| Mapping recall | {m['r']:.1%} | ≥ 90% |",
             f"| Evidence coverage | {m['cov']:.1%} ({m['covered']}/{m['mapped']} controls) | ≥ 85% |",
             f"| False-gap rate | {m['fr']:.1%} ({m['n_false']}/{m['n_gaps']}) | ≤ 8% |",
             f"| Audit prep time saved | {m['saved']:.1f} h (≈ {m['saved']/8:.1f} audit-days) | — |",
             f"| Run cost | ${m['cost']:.2f} · {w['tokens']/1000:.0f}K tokens | budget {cfg['budget_k']}K |",
             "", "## 2. Configuration",
             f"- Autonomy: **{cfg['autonomy']}** · confidence floor **{cfg['conf']:.2f}** · model profile **{cfg['model']}**",
             f"- Prompt-injection defence: **{'on' if cfg['defense'] else 'off'}** · stale-source guard: **{'on' if cfg['stale_guard'] else 'off'}**",
             f"- Security events: {w['security']['inj_blocked']} injections blocked · {w['security']['inj_hit']} hits · {w['security']['stale_src']} stale sources used",
             "", "## 3. Regulatory updates processed"]
    for u in w["updates"][-8:][::-1]:
        lines.append(f"- **{u['title']}** ({u['kind']}, {u['ver']}) — {len(u['obs'])} obligations · {u['status']}")
    lines += ["", "## 4. Gap register", "| ID | Obligation | Control | Type | Severity | Score | Status | Owner | Due |",
              "|---|---|---|---|---|---|---|---|---|"]
    for g in sorted(w["gaps"], key=lambda x: -x["score"]):
        lines.append(f"| {g['id']} | {g['ob']} | {g['ctrl']} | {g['type']} | {g['sev']} | {g['score']} | {g['status']} | {g['owner']} | {g['due']} |")
    lines += ["", "## 5. Remediation tasks"]
    for t in w["tasks"]:
        lines.append(f"- **{t['id']}** [{t['status']}] {t['title']} — {t['owner']} · due {t['due']}")
        for s in t["steps"]:
            lines.append(f"  - {s}")
    lines += ["", "## 6. Method & provenance",
              "All mappings carry provenance (source clause ⇄ control · ranker version). All evidence was collected",
              "read-only under least-privilege credentials and sealed with sha256. Low-confidence work was routed",
              "to human review per the configured autonomy policy. Synthetic demonstration data — no external calls."]
    return "\n".join(lines)


def evidence_package(w):
    items = [dict(id=e["id"], control=e["ctrl"], source=e["src"], kind=e["kind"], sha256=e["sha"],
                  collected_tick=e["tick"], ttl_ticks=e["ttl"], sufficiency=e["suff"],
                  size_kb=e["kb"], provenance=e["prov"], read_only=True)
           for e in w["store"].values()]
    manifest = hashlib.sha256(json.dumps(items, sort_keys=True).encode()).hexdigest()
    return json.dumps(dict(generated=w["clock"].isoformat(), tenant="demo-eu-1",
                           manifest_sha256=manifest, items=items), indent=2)


def tasks_csv(w):
    buf = io.StringIO()
    wr = csv.writer(buf)
    wr.writerow(["id", "gap", "title", "owner", "priority", "status", "due", "steps"])
    for t in w["tasks"]:
        wr.writerow([t["id"], t["gap"], t["title"], t["owner"], t["prio"], t["status"], t["due"],
                     " | ".join(t["steps"])])
    return buf.getvalue()


# ----------------------------------------------------------------------------- CSS
CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');
:root{--bg:#F4F7FB;--panel:#FFFFFF;--line:#D9E1EE;--ink:#0F172A;--dim:#5B6B82;
--cyan:#0891B2;--violet:#7C3AED;--green:#65A30D;--emerald:#059669;--amber:#D97706;--rose:#E11D48;}
.stApp{background:
 radial-gradient(1100px 500px at 85% -10%, rgba(124,58,237,.09), transparent 60%),
 radial-gradient(900px 420px at -10% 0%, rgba(8,145,178,.09), transparent 55%),
 radial-gradient(700px 500px at 50% 110%, rgba(217,119,6,.06), transparent 60%),
 repeating-linear-gradient(0deg, rgba(15,23,42,.025) 0 1px, transparent 1px 42px),
 repeating-linear-gradient(90deg, rgba(15,23,42,.025) 0 1px, transparent 1px 42px),
 #F4F7FB; color:var(--ink);}
#MainMenu,footer,[data-testid="stDecoration"],[data-testid="stToolbar"]{display:none;}
[data-testid="stHeader"]{background:transparent;}
.block-container{padding-top:1.1rem;padding-bottom:2rem;max-width:1500px;}
html,body,[class*="css"]{font-family:'Space Grotesk',system-ui,sans-serif;}
*{scrollbar-width:thin;scrollbar-color:#C3CEDF #EEF2F8;}
::-webkit-scrollbar{width:10px;height:10px;}
::-webkit-scrollbar-track{background:#EEF2F8;}
::-webkit-scrollbar-thumb{background:#C3CEDF;border-radius:8px;border:2px solid #EEF2F8;}
::-webkit-scrollbar-thumb:hover{background:#0891B2;}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#FFFFFF,#F1F5FB);border-right:1px solid var(--line);}
[data-testid="stSidebar"] .block-container{padding-top:1rem;}
.brand{font-weight:700;font-size:30px;line-height:1.05;letter-spacing:.02em;
 background:linear-gradient(90deg,#0891B2,#7C3AED 55%,#D97706);-webkit-background-clip:text;background-clip:text;color:transparent;}
.tagline{font-family:'IBM Plex Mono',monospace;font-size:10.5px;letter-spacing:.22em;color:#5B6B82;text-transform:uppercase;margin-top:2px;}
.hdr-right{display:flex;justify-content:flex-end;align-items:center;gap:12px;font-family:'IBM Plex Mono',monospace;font-size:12px;color:#5B6B82;padding-top:8px;flex-wrap:wrap;}
.badge{display:inline-flex;align-items:center;gap:7px;padding:4px 12px;border-radius:999px;border:1px solid var(--line);background:#FFFFFF;font-weight:600;font-size:11px;letter-spacing:.1em;color:var(--ink);box-shadow:0 1px 2px rgba(15,23,42,.05);}
.dot{width:9px;height:9px;border-radius:50%;background:#65A30D;box-shadow:0 0 0 0 rgba(101,163,13,.5);animation:pulse 1.6s infinite;}
.dot.paused{background:#D97706;animation:none;box-shadow:none;}
@keyframes pulse{70%{box-shadow:0 0 0 9px rgba(101,163,13,0)}100%{box-shadow:0 0 0 0 rgba(101,163,13,0)}}
.kpi{background:linear-gradient(160deg,#FFFFFF,#F7FAFD);border:1px solid var(--line);border-radius:14px;padding:12px 14px 10px;min-height:128px;transition:border-color .2s,box-shadow .2s;box-shadow:0 1px 3px rgba(15,23,42,.05);}
.kpi:hover{border-color:#A9B9D0;box-shadow:0 4px 14px rgba(15,23,42,.08);}
.kpi-top{display:flex;justify-content:space-between;align-items:center;gap:6px;}
.kpi-label{font-family:'IBM Plex Mono',monospace;font-size:9.5px;letter-spacing:.14em;color:#5B6B82;text-transform:uppercase;}
.kpi-value{font-weight:700;font-size:27px;margin:4px 0 2px;color:var(--ink);}
.kpi-value .unit{font-size:15px;color:#5B6B82;font-weight:600;}
.kpi-sub{font-family:'IBM Plex Mono',monospace;font-size:10px;color:#66758C;margin-top:3px;}
.delta{font-family:'IBM Plex Mono',monospace;font-size:9px;padding:2px 7px;border-radius:999px;white-space:nowrap;}
.delta.ok{color:#4D7C0F;background:rgba(101,163,13,.1);border:1px solid rgba(101,163,13,.35);}
.delta.bad{color:#BE123C;background:rgba(225,29,72,.08);border:1px solid rgba(225,29,72,.3);}
.delta.live{color:#0E7490;background:rgba(8,145,178,.08);border:1px solid rgba(8,145,178,.3);}
.spark{width:100%;height:30px;display:block;}
.agent{background:#FFFFFF;border:1px solid var(--line);border-left:3px solid var(--ac,#0891B2);border-radius:12px;padding:10px 12px;min-height:118px;box-shadow:0 1px 3px rgba(15,23,42,.05);}
.a-top{display:flex;justify-content:space-between;align-items:center;font-weight:600;font-size:12.5px;gap:6px;color:var(--ink);}
.a-item{font-family:'IBM Plex Mono',monospace;font-size:10.5px;color:#3B4A63;margin:7px 0 8px;min-height:28px;line-height:1.35;}
.a-meta{font-family:'IBM Plex Mono',monospace;font-size:9.5px;color:#66758C;margin-top:7px;}
.agent-bar{height:4px;background:#E3E9F3;border-radius:2px;overflow:hidden;}
.agent-bar>i{display:block;height:100%;width:40%;background:linear-gradient(90deg,#0891B2,#7C3AED);animation:slide 1.5s linear infinite;}
.agent-bar>i.idle{animation:none;width:0;}
@keyframes slide{0%{transform:translateX(-110%)}100%{transform:translateX(280%)}}
.ph{font-family:'IBM Plex Mono',monospace;font-size:9px;font-weight:600;letter-spacing:.1em;padding:2px 8px;border-radius:999px;border:1px solid;}
.chip{display:inline-block;font-family:'IBM Plex Mono',monospace;font-size:10px;padding:2px 9px;border-radius:999px;border:1px solid;margin:1px 2px 1px 0;white-space:nowrap;}
.trace{max-height:365px;overflow-y:auto;border:1px solid var(--line);border-radius:12px;background:#FFFFFF;padding:6px;}
.ev{display:flex;gap:8px;align-items:baseline;padding:5px 8px;border-left:2px solid #C3CEDF;margin:3px 0;border-radius:0 8px 8px 0;font-family:'IBM Plex Mono',monospace;font-size:10.5px;line-height:1.4;}
.ev-t{color:#6B7A91;min-width:36px;}
.ev-a{color:#5B6B82;min-width:44px;font-weight:600;}
.ev-m{color:#1E293B;flex:1;}
.ev-m em{color:#6B7A91;font-style:normal;}
.ev-m code{color:#0E7490;background:none;font-size:10px;}
.ev-inj{background:rgba(219,39,119,.07);border-left-color:#DB2777;}
.ev-kill{background:rgba(225,29,72,.08);border-left-color:#E11D48;}
.ev-warn{border-left-color:#D97706;}
.ev-ok{border-left-color:#059669;}
.tbl{max-height:340px;overflow:auto;border:1px solid var(--line);border-radius:12px;background:#FFFFFF;}
.tbl table{width:100%;border-collapse:collapse;font-family:'IBM Plex Mono',monospace;font-size:11px;}
.tbl th{position:sticky;top:0;background:#EEF2F8;color:#5B6B82;text-transform:uppercase;font-size:9px;letter-spacing:.1em;padding:8px 10px;text-align:left;border-bottom:1px solid var(--line);z-index:2;}
.tbl td{padding:7px 10px;border-bottom:1px solid #E5EBF4;color:#1E293B;vertical-align:top;}
.tbl tr:hover td{background:#F4F8FD;}
.cbar{display:inline-block;width:64px;height:6px;background:#E3E9F3;border-radius:3px;overflow:hidden;vertical-align:middle;margin-right:6px;}
.cbar>i{display:block;height:100%;}
.card{background:#FFFFFF;border:1px solid var(--line);border-left:3px solid var(--ac,#0891B2);border-radius:12px;padding:11px 13px;margin-bottom:6px;box-shadow:0 1px 3px rgba(15,23,42,.05);}
.card h4{margin:0 0 4px;font-size:13.5px;font-weight:600;color:var(--ink);}
.card .meta{font-family:'IBM Plex Mono',monospace;font-size:10px;color:#5B6B82;line-height:1.5;}
.card .plan{font-size:11px;color:#3B4A63;margin-top:6px;line-height:1.45;}
.meter{height:8px;background:#E3E9F3;border-radius:4px;overflow:hidden;margin:5px 0 3px;}
.meter>i{display:block;height:100%;background:linear-gradient(90deg,#0891B2,#7C3AED);}
.meter-l{font-family:'IBM Plex Mono',monospace;font-size:10px;color:#5B6B82;}
.empty{border:1px dashed #B8C5DA;border-radius:14px;padding:26px;text-align:center;color:#5B6B82;background:#FFFFFF;}
.empty .big{font-size:30px;}
.stButton>button{background:#FFFFFF;border:1px solid #CBD5E4;color:#0F172A;border-radius:10px;font-weight:600;font-family:'Space Grotesk',sans-serif;font-size:12.5px;transition:all .15s;width:100%;box-shadow:0 1px 2px rgba(15,23,42,.05);}
.stButton>button:hover{border-color:#0891B2;color:#0891B2;transform:translateY(-1px);box-shadow:0 4px 14px rgba(8,145,178,.18);}
.stButton>button[kind="primary"],[data-testid="stBaseButton-primary"]{background:linear-gradient(90deg,#0891B2,#7C3AED);border:none;color:#fff;}
.stButton>button[kind="primary"]:hover,[data-testid="stBaseButton-primary"]:hover{color:#fff;box-shadow:0 4px 20px rgba(124,58,237,.3);}
.stDownloadButton>button{background:#FFFFFF;border:1px solid #CBD5E4;color:#4D7C0F;border-radius:10px;font-weight:600;font-size:12px;width:100%;}
.stDownloadButton>button:hover{border-color:#65A30D;color:#3F6212;box-shadow:0 4px 14px rgba(101,163,13,.18);}
.stTabs [data-baseweb="tab-list"]{gap:4px;background:#FFFFFF;padding:6px;border-radius:12px;border:1px solid var(--line);flex-wrap:wrap;}
.stTabs [data-baseweb="tab"]{color:#5B6B82;font-weight:600;font-size:12.5px;border-radius:8px;padding:6px 14px;background:transparent;}
.stTabs [data-baseweb="tab"]:hover{color:#0F172A;background:#EEF2F8;}
.stTabs [aria-selected="true"]{color:#FFFFFF !important;background:#0891B2 !important;}
.stTabs [data-baseweb="tab-highlight"],.stTabs [data-baseweb="tab-border"]{display:none;}
[data-testid="stExpander"]{border:1px solid var(--line);border-radius:12px;background:#FFFFFF;}
.stTextInput input,.stNumberInput input{background:#FFFFFF !important;border:1px solid #CBD5E4 !important;color:#0F172A !important;border-radius:10px !important;font-family:'IBM Plex Mono',monospace !important;font-size:12px !important;}
[data-baseweb="select"]>div{background:#FFFFFF !important;border-color:#CBD5E4 !important;border-radius:10px !important;color:#0F172A !important;}
.stSlider [data-baseweb="slider"] div[role="slider"]{background:#0891B2 !important;border-color:#0891B2 !important;}
hr{border-color:#D9E1EE !important;}
.sec-title{font-family:'IBM Plex Mono',monospace;font-size:10px;letter-spacing:.2em;color:#5B6B82;text-transform:uppercase;margin:14px 0 8px;}
@media (max-width:900px){
 [data-testid="stHorizontalBlock"]{flex-wrap:wrap;}
 [data-testid="column"]{min-width:calc(50% - 8px) !important;flex:1 1 calc(50% - 8px) !important;}
 .kpi-value{font-size:22px;}
}
</style>
"""

# ----------------------------------------------------------------------------- UI atoms
def chip(text, color):
    return f'<span class="chip" style="color:{color};border-color:{color}55;background:{color}14">{esc(str(text))}</span>'


def ph_chip(phase):
    c = PH_C.get(phase, DIM)
    return f'<span class="ph" style="color:{c};border-color:{c}66;background:{c}14">{phase}</span>'


def conf_bar(c):
    col = EMERALD if c >= 0.85 else AMBER if c >= 0.7 else ROSE
    return f'<span class="cbar"><i style="width:{c*100:.0f}%;background:{col}"></i></span>{c:.2f}'


def spark(vals, color):
    if len(vals) < 2:
        return '<svg class="spark"></svg>'
    lo, hi = min(vals), max(vals)
    rg = (hi - lo) or 1
    pts = " ".join(f"{i/(len(vals)-1)*118+1:.1f},{30-(v-lo)/rg*26+2:.1f}" for i, v in enumerate(vals))
    lx, ly = pts.rsplit(" ", 1)[1].split(",")
    return (f'<svg class="spark" viewBox="0 0 120 34" preserveAspectRatio="none">'
            f'<polyline points="{pts}" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" opacity="0.9"/>'
            f'<circle cx="{lx}" cy="{ly}" r="2.6" fill="{color}"/></svg>')


def kpi(label, value, unit, sub, vals, color, ok):
    d = '<span class="delta live">● live</span>' if ok is None else \
        ('<span class="delta ok">● on target</span>' if ok else '<span class="delta bad">● attention</span>')
    st.markdown(f'<div class="kpi"><div class="kpi-top"><span class="kpi-label">{label}</span>{d}</div>'
                f'<div class="kpi-value">{value}<span class="unit">{unit}</span></div>'
                f'{spark(vals, color)}<div class="kpi-sub">{sub}</div></div>', unsafe_allow_html=True)


def htable(cols, rows):
    head = "".join(f"<th>{c}</th>" for c in cols)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<div class="tbl"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def empty(icon, title, sub):
    st.markdown(f'<div class="empty"><div class="big">{icon}</div><b>{title}</b><br>'
                f'<span style="font-size:12px">{sub}</span></div>', unsafe_allow_html=True)


def fig_base(fig, h):
    fig.update_layout(height=h, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      font=dict(family="IBM Plex Mono, monospace", color=DIM, size=11),
                      margin=dict(l=10, r=10, t=30, b=10))
    return fig


# ----------------------------------------------------------------------------- action handlers
def decide(w, ap, approve):
    ap["status"] = "approved" if approve else "rejected"
    w["decided"] += 1
    k, p = ap["kind"], ap["payload"]
    if k == "mapping":
        m = next((x for x in w["mappings"] if x["id"] == p["map"]), None)
        if m:
            m["status"] = "approved" if approve else "rejected"
            if approve:
                state, _ = evi_state(w, m["ctrl"])
                if state != "sufficient":
                    w["queues"]["evi"].append(dict(ctrl=m["ctrl"], ob=m["ob"], gap=None, recheck=False))
            emit(w, "sys", "FEED", f"Human {'approved' if approve else 'rejected'} link {m['id']} ({m['ob']} → {m['ctrl']})",
                 kind="ok" if approve else "warn")
    elif k == "gap":
        g = next((x for x in w["gaps"] if x["id"] == p["gap"]), None)
        if g:
            if approve:
                t = create_task(w, g)
                emit(w, "sys", "FEED", f"Gap {g['id']} approved → task {t['id']} drafted", kind="ok")
            else:
                g["status"] = "dismissed"
                emit(w, "sys", "FEED", f"Gap {g['id']} dismissed by reviewer", kind="warn")
    elif k == "collection":
        if approve:
            w["rechecks"].append(p["item"])
            emit(w, "sys", "FEED", "Collection retry authorised by operator", kind="ok")
        else:
            emit(w, "sys", "FEED", "Collection abandoned — gap will persist", kind="warn")
    elif k == "loop":
        if approve:
            w["queues"][p["agent"]].appendleft(p["item"])
            emit(w, "sys", "FEED", f"Parked work re-queued to {AGENTS[p['agent']]['short']}", kind="ok")
        else:
            emit(w, "sys", "FEED", "Parked work dropped by operator", kind="warn")
    st.toast(f"{'✅ Approved' if approve else '🚫 Rejected'} · {ap['id']}")


# ----------------------------------------------------------------------------- live render
def render_live():
    w, cfg = S["world"], S["cfg"]
    interval = 1.0 / cfg["speed"]
    now = time.time()
    was_running = w["running"]
    if w["step_request"]:
        advance(w, cfg)
        w["step_request"] = False
        w["last_adv"] = now
    elif w["running"] and now - w["last_adv"] >= interval * 0.92:
        advance(w, cfg)
        w["last_adv"] = now
    recompute(w)
    m = w["m"]
    hist = w["history"]

    # header
    hc1, hc2 = st.columns([5, 4])
    hc1.markdown('<div class="brand">AEGIS</div><div class="tagline">Agentic Regulatory Compliance Auditor</div>',
                 unsafe_allow_html=True)
    badge = '<span class="badge"><span class="dot"></span>SIMULATION LIVE</span>' if w["running"] else \
            '<span class="badge"><span class="dot paused"></span>PAUSED</span>'
    hc2.markdown(f'<div class="hdr-right">{badge}<span>{w["clock"].strftime("%a %d %b · %H:%M UTC")}</span>'
                 f'<span>tick {w["tick"]}</span></div>', unsafe_allow_html=True)
    st.caption("Four agents run **plan → act → observe → reflect** under step & token budgets. "
               "Route low-confidence work in **Approvals**, verify remediation to close gaps, export audit artefacts anytime.")
    if w["halt_reason"] == "budget":
        st.error("⛔ Token budget exhausted — kill switch engaged. Raise the budget in the sidebar, then press Resume.")
    elif w["halt_reason"] == "manual":
        st.warning("⛔ Agents halted by operator. In-flight work was re-queued. Press Resume to continue.")
    if was_running and not w["running"]:
        RERUN()

    # KPI row
    cols = st.columns(6, gap="small")
    with cols[0]:
        kpi("Mapping precision", f"{m['p']*100:.1f}", "%", f"TP {m['tp']} · FP {m['fp']} · target ≥ 92%",
            [h["p"] for h in hist], CYAN, m["p"] >= 0.92)
    with cols[1]:
        kpi("Mapping recall", f"{m['r']*100:.1f}", "%", f"missed {m['fn']} · target ≥ 90%",
            [h["r"] for h in hist], VIOLET, m["r"] >= 0.90)
    with cols[2]:
        kpi("Evidence coverage", f"{m['cov']*100:.1f}", "%", f"{m['covered']}/{m['mapped']} controls · target ≥ 85%",
            [h["c"] for h in hist], GREEN, m["cov"] >= 0.85)
    with cols[3]:
        kpi("False-gap rate", f"{m['fr']*100:.1f}", "%", f"{m['n_false']}/{m['n_gaps']} flagged · target ≤ 8%",
            [h["f"] for h in hist], AMBER, m["fr"] <= 0.08)
    with cols[4]:
        kpi("Audit prep saved", f"{m['saved']:.1f}", "h", f"≈ {m['saved']/8:.1f} audit-days · {m['finalized']} obligations",
            [h["tick"] * 0 + m["saved"] for h in hist[-2:]] if hist else [], EMERALD, None)
    with cols[5]:
        kpi("Run cost", f"${m['cost']:.2f}", "", f"{w['tokens']/1000:.0f}K / {cfg['budget_k']}K tokens",
            [h["cost"] for h in hist], BLUE, w["tokens"] < 0.85 * cfg["budget_k"] * 1000)

    tabs = st.tabs(["🛰 Mission Control", "📜 Regulatory Feed", "🧭 Control Mapping",
                    "🗄 Evidence Vault", "⚠️ Gaps & Remediation", "✅ Approvals", "📦 Audit Report"])

    # ---------------- Mission Control ----------------
    with tabs[0]:
        lanes = st.columns(4, gap="small")
        for i, key in enumerate(AGENTS):
            a = w["agents"][key]
            phase = PHASES[a["phase"]] if a["status"] == "running" else "IDLE"
            pc = PH_C[phase]
            qlen = len(w["queues"][key]) + (len(w["rechecks"]) if key == "evi" else 0)
            anim = "" if a["status"] == "running" else "idle"
            lanes[i].markdown(
                f'<div class="agent" style="--ac:{pc}"><div class="a-top"><span>{AGENTS[key]["icon"]} {AGENTS[key]["short"]}</span>{ph_chip(phase)}</div>'
                f'<div class="a-item">{esc(item_label(w, key, a["item"])[:76])}</div>'
                f'<div class="agent-bar"><i class="{anim}"></i></div>'
                f'<div class="a-meta">steps {a["steps"]}/{cfg["max_steps"]} · done {a["processed"]} · queue {qlen}</div></div>',
                unsafe_allow_html=True)
        st.markdown('<div class="sec-title">Live agent trace — newest first</div>', unsafe_allow_html=True)
        left, right = st.columns([3, 2], gap="medium")
        with left:
            rows = []
            for e in list(w["events"])[:30]:
                cls = {"inj": "ev-inj", "kill": "ev-kill", "warn": "ev-warn", "ok": "ev-ok"}.get(e["kind"], "")
                pc = PH_C.get(e["phase"], DIM)
                tool = f'<code>{esc(e["tool"])}</code> → ' if e["tool"] else ""
                tok = f' <em>· {e["tok"]} tok</em>' if e["tok"] else ""
                short = AGENTS[e["agent"]]["short"] if e["agent"] in AGENTS else "SYS"
                rows.append(f'<div class="ev {cls}" style="border-left-color:{pc}">'
                            f'<span class="ev-t">{e["t"]}</span><span class="ev-a">{short}</span>'
                            f'{ph_chip(e["phase"])}<span class="ev-m">{tool}{esc(e["msg"])}{tok}</span></div>')
            st.markdown(f'<div class="trace">{"".join(rows)}</div>', unsafe_allow_html=True)
        with right:
            if len(hist) >= 2:
                fig = go.Figure()
                for k, name, col in [("p", "precision", CYAN), ("r", "recall", VIOLET), ("c", "coverage", GREEN)]:
                    fig.add_trace(go.Scatter(x=[h["tick"] for h in hist], y=[h[k] for h in hist],
                                             name=name, mode="lines", line=dict(color=col, width=2)))
                fig.add_hline(y=0.9, line_dash="dot", line_color=AMBER, opacity=0.5)
                fig.update_layout(yaxis=dict(range=[0, 1.02], tickformat=".0%", gridcolor=LINE),
                                  xaxis=dict(showgrid=False), legend=dict(orientation="h", y=1.18))
                wide_chart(fig_base(fig, 240), "trend_fig")
            pct = min(1.0, w["tokens"] / (cfg["budget_k"] * 1000))
            barcol = ROSE if pct >= 1 else AMBER if pct > 0.85 else ""
            style = f' style="background:{barcol}"' if barcol else ""
            st.markdown(f'<div class="meter-l">TOKEN BUDGET · {w["tokens"]/1000:.0f}K / {cfg["budget_k"]}K · ${m["cost"]:.2f}</div>'
                        f'<div class="meter"><i{style} style="width:{pct*100:.0f}%"></i></div>'
                        f'<div class="meter-l">profile {cfg["model"]} · {PROFILES[cfg["model"]]["cost"]}× cost · autonomy {esc(cfg["autonomy"])}</div>',
                        unsafe_allow_html=True)
            sec = w["security"]
            st.markdown(
                chip(f"🛡 injections blocked {sec['inj_blocked']}", MAGENTA) +
                chip(f"☣ injection hits {sec['inj_hit']}", ROSE) +
                chip(f"🕒 stale sources {sec['stale_src']}", AMBER) +
                chip(f"♻ canonical refreshes {sec['refreshed']}", EMERALD), unsafe_allow_html=True)
            st.caption("Kill switches: token budget, per-item step cap, operator halt. All tool output treated as untrusted.")

    # ---------------- Regulatory Feed ----------------
    with tabs[1]:
        c1, c2 = st.columns([2, 5])
        if c1.button("⚡ Inject regulatory update", key="inject_feed"):
            enqueue_update(w, forced=True)
            st.toast("📡 Update injected into the monitor queue")
        c2.caption(f"{len(w['updates'])} updates detected · volatility {cfg['volatility']:.0%}/tick · stale-source guard {'ON' if cfg['stale_guard'] else 'OFF'}")
        ups = w["updates"][-6:][::-1]
        if ups:
            kc = {"NEW": GREEN, "AMENDMENT": AMBER, "GUIDANCE": VIOLET}
            grid = st.columns(2, gap="small")
            for i, u in enumerate(ups):
                reg = REG_BY[u["reg"]]
                stale = chip("STALE SOURCE", ROSE) if u["stale"] else ""
                grid[i % 2].markdown(
                    f'<div class="card" style="--ac:{kc[u["kind"]]}"><h4>{esc(u["title"])}</h4>'
                    f'<div class="meta">{chip(u["kind"], kc[u["kind"]])}{chip(reg["juris"], BLUE)}{chip(u["ver"], DIM)}{stale}</div>'
                    f'<div class="plan">{esc(u["summary"])}</div>'
                    f'<div class="meta">{len(u["obs"])} obligations · {u["status"]} · {u["id"]}</div></div>',
                    unsafe_allow_html=True)
        else:
            empty("📡", "No updates yet", "Raise volatility or inject an update.")
        st.markdown('<div class="sec-title">Extracted obligations</div>', unsafe_allow_html=True)
        obs = list(w["obligations"].values())[-24:][::-1]
        rows = [[esc(o["id"]), chip(REG_BY[o["reg"]]["short"], VIOLET), esc(o["ref"]), esc(o["text"]),
                 "★" * o["crit"], chip(o["status"], EMERALD if o["status"] == "assessed" else CYAN)] for o in obs]
        st.markdown(htable(["ID", "Regulation", "Ref", "Obligation", "Crit", "Status"], rows), unsafe_allow_html=True)

    # ---------------- Control Mapping ----------------
    with tabs[2]:
        z, custom = [], []
        for reg in REGS:
            row, crow = [], []
            for c in CONTROLS:
                best, has = 0.0, False
                for ob in w["obligations"].values():
                    if ob["reg"] != reg["id"] or ob["status"] not in ("mapped", "assessed"):
                        continue
                    if any(mm["ctrl"] == c["id"] for mm in preds_of(w, ob["id"])):
                        has = True
                        state, _ = evi_state(w, c["id"])
                        score = {"sufficient": 1.0, "partial": 0.6, "stale": 0.35, "insufficient": 0.25, "none": 0.15}[state]
                        best = max(best, score)
                row.append(best if has else None)
                crow.append(f"{best:.0%} coverage" if has else "no mapping")
            z.append(row)
            custom.append(crow)
        fig = go.Figure(go.Heatmap(z=z, x=[c["id"] for c in CONTROLS], y=[r["short"] for r in REGS],
                                   customdata=custom, hoverongaps=False,
                                   hovertemplate="%{y} × %{x}<br>%{customdata}<extra></extra>",
                                   colorscale=[[0, "#CBD5E1"], [0.25, ROSE], [0.55, AMBER], [0.8, GREEN], [1, EMERALD]],
                                   zmin=0, zmax=1, xgap=2, ygap=2,
                                   colorbar=dict(thickness=10, tickformat=".0%", outlinewidth=0)))
        fig.update_layout(xaxis=dict(tickangle=-40, side="bottom"), yaxis=dict(autorange="reversed"))
        st.markdown('<div class="sec-title">Regulation × Control coverage matrix</div>', unsafe_allow_html=True)
        wide_chart(fig_base(fig, 380), "heat_fig")
        f1, f2, f3 = st.columns([2, 2, 3])
        status_f = f1.selectbox("Status", ["All", "auto", "needs_review", "approved", "rejected"], key="map_status")
        sort_f = f2.selectbox("Sort", ["Confidence ↓", "Newest"], key="map_sort")
        q = f3.text_input("Search obligation / control / rationale", key="map_q", placeholder="e.g. encryption, AC-01, Art. 32…")
        ms = list(w["mappings"])
        if status_f != "All":
            ms = [x for x in ms if x["status"] == status_f]
        if q:
            ql = q.lower()
            ms = [x for x in ms if ql in x["ctrl"].lower() or ql in CTL_BY[x["ctrl"]]["name"].lower()
                  or ql in w["obligations"][x["ob"]]["ref"].lower() or ql in w["obligations"][x["ob"]]["text"].lower()
                  or ql in x["why"].lower()]
        ms.sort(key=lambda x: -x["conf"] if sort_f == "Confidence ↓" else -x["tick"])
        st.caption(f"{len(ms)} links · showing up to 40 · confidence floor {cfg['conf']:.2f}")
        sc = {"auto": CYAN, "approved": EMERALD, "needs_review": AMBER, "rejected": ROSE}
        rows = [[esc(x["id"]), esc(f"{x['ob']} · {w['obligations'][x['ob']]['ref']}"),
                 chip(x["ctrl"], VIOLET) + esc(" " + CTL_BY[x["ctrl"]]["name"]),
                 conf_bar(x["conf"]), chip(x["status"], sc[x["status"]]),
                 esc(x["why"]), f'<span style="color:#66758C">{esc(x["prov"])}</span>'] for x in ms[:40]]
        if rows:
            st.markdown(htable(["Link", "Obligation", "Control", "Confidence", "Status", "Rationale", "Provenance"], rows),
                        unsafe_allow_html=True)
        else:
            empty("🧭", "No links match", "Clear the search or status filter.")

    # ---------------- Evidence Vault ----------------
    with tabs[3]:
        store = list(w["store"].values())
        fresh = sum(1 for e in store if evi_state(w, e["ctrl"])[0] == "sufficient")
        stale = [e for e in store if evi_state(w, e["ctrl"])[0] == "stale"]
        st.markdown(chip(f"artefacts {len(store)}", CYAN) + chip(f"fresh & sufficient {fresh}", EMERALD) +
                    chip(f"stale {len(stale)}", AMBER) + chip("100% read-only · sha256 sealed", VIOLET),
                    unsafe_allow_html=True)
        if st.button(f"🔄 Re-collect stale evidence ({len(stale)})", key="recollect"):
            n = 0
            for e in stale[:6]:
                w["rechecks"].append(dict(ctrl=e["ctrl"], ob=None, gap=None, recheck=True))
                n += 1
            emit(w, "sys", "FEED", f"Operator queued {n} stale-artefact re-collections", kind="ok")
            st.toast(f"🔄 {n} re-collections queued to the Evidence Agent")
        rows = []
        for e in sorted(store, key=lambda x: -x["tick"]):
            state, _ = evi_state(w, e["ctrl"])
            scol = {"sufficient": EMERALD, "partial": AMBER, "insufficient": ROSE, "stale": AMBER}.get(state, DIM)
            age = w["tick"] - e["tick"]
            rows.append([esc(e["id"]), chip(e["ctrl"], VIOLET), esc(e["src"]), esc(e["kind"]),
                         f'<span style="color:#0E7490">sha256:{e["short"]}…</span>',
                         f"{age}t / {e['ttl']}t", chip(state, scol), chip(e["suff"], DIM),
                         f'<span style="color:#66758C">{esc(e["prov"])}</span>'])
        if rows:
            st.markdown(htable(["ID", "Control", "Source", "Type", "Seal", "Age", "Freshness", "Sufficiency", "Provenance"], rows),
                        unsafe_allow_html=True)
        st.caption("Credentials are scoped per task (least privilege, 15-min TTL). Retrieved content is sandboxed; "
                   f"injection defence is {'ON — hostile instructions are stripped' if cfg['defense'] else 'OFF — try toggling it on and watch the trace'}.")

    # ---------------- Gaps & Remediation ----------------
    with tabs[4]:
        active = [g for g in w["gaps"] if g["status"] in ("open", "task_created", "pending_recheck")]
        d1, d2 = st.columns([2, 3], gap="medium")
        with d1:
            if active:
                counts = {s: sum(1 for g in active if g["sev"] == s) for s in SEV_C}
                fig = go.Figure(go.Pie(labels=list(counts), values=list(counts.values()), hole=0.62,
                                       marker=dict(colors=[SEV_C[s] for s in counts], line=dict(color="#FFFFFF", width=2)),
                                       textinfo="label+value", textfont=dict(size=11)))
                fig.add_annotation(text=f"{len(active)}<br>active", showarrow=False,
                                   font=dict(size=16, color=INK, family="Space Grotesk"))
                fig.update_layout(showlegend=False)
                wide_chart(fig_base(fig, 230), "donut_fig")
            else:
                empty("🎉", "No active gaps", "Coverage is clean — inject an update to stress the system.")
        with d2:
            closed = sum(1 for g in w["gaps"] if g["status"] == "closed")
            fps = sum(1 for g in w["gaps"] if g["status"] == "false_positive")
            st.markdown(chip(f"active {len(active)}", AMBER) + chip(f"closed via remediation {closed}", EMERALD) +
                        chip(f"human-flagged false positives {fps}", MAGENTA) +
                        chip(f"total filed {len(w['gaps'])}", CYAN), unsafe_allow_html=True)
            st.caption(f"Routing under **{cfg['autonomy']}**: critical/high gaps go to Approvals; the rest draft tasks. "
                       "Marking a false positive feeds the false-gap metric. Verifying a task re-collects evidence and closes the gap.")
            show = sorted([g for g in w["gaps"] if g["status"] in ("open", "false_positive", "dismissed")],
                          key=lambda x: -x["score"])[:6]
            grid = st.columns(2, gap="small")
            for i, g in enumerate(show):
                col = grid[i % 2]
                statc = {"open": AMBER, "false_positive": MAGENTA, "dismissed": DIM}[g["status"]]
                col.markdown(
                    f'<div class="card" style="--ac:{SEV_C[g["sev"]]}"><h4>{esc(g["title"])}</h4>'
                    f'<div class="meta">{chip(g["sev"], SEV_C[g["sev"]])}{chip(g["type"], CYAN)}{chip(g["status"], statc)}'
                    f' score {g["score"]} · {g["ob"]} · owner {esc(g["owner"])} · due {g["due"]}</div>'
                    f'<div class="plan">1. {esc(g["plan"][0])}<br>2. {esc(g["plan"][1])}</div></div>',
                    unsafe_allow_html=True)
                if g["status"] == "open":
                    b1, b2 = col.columns(2)
                    if b1.button("🛠 Create task", key=f"g_task_{g['id']}"):
                        t = create_task(w, g)
                        emit(w, "sys", "FEED", f"Operator drafted task {t['id']} for gap {g['id']}", kind="ok")
                        st.toast(f"🛠 Task {t['id']} created")
                    if b2.button("🚫 False positive", key=f"g_fp_{g['id']}"):
                        g["status"] = "false_positive"
                        g["false"] = True
                        g["revealed"] = True
                        emit(w, "sys", "FEED", f"Gap {g['id']} marked false positive — feedback logged", kind="warn")
                        st.toast("🚫 Flagged — false-gap metric updated")
                else:
                    if col.button("↩ Reopen", key=f"g_reopen_{g['id']}"):
                        g["status"] = "open"
                        st.toast(f"↩ {g['id']} reopened")
        st.markdown('<div class="sec-title">Remediation board</div>', unsafe_allow_html=True)
        board = st.columns(3, gap="small")
        for bi, status in enumerate(["todo", "in_progress", "verified"]):
            ts = [t for t in w["tasks"] if t["status"] == status]
            head = {"todo": "📥 To do", "in_progress": "🔧 In progress", "verified": "✅ Verified"}[status]
            board[bi].markdown(f"**{head}** · {len(ts)}")
            for t in ts[-4:][::-1]:
                board[bi].markdown(
                    f'<div class="card" style="--ac:{SEV_C[t["prio"]]}"><h4>{esc(t["id"])} · {esc(t["title"])}</h4>'
                    f'<div class="meta">{chip(t["prio"], SEV_C[t["prio"]])}{esc(t["owner"])} · due {t["due"]} · gap {t["gap"]}</div>'
                    f'<div class="plan">{esc(t["steps"][0])}</div></div>', unsafe_allow_html=True)
                if status == "todo" and board[bi].button("▶ Start", key=f"t_start_{t['id']}"):
                    t["status"] = "in_progress"
                    emit(w, "sys", "FEED", f"Task {t['id']} started by {t['owner']}", kind="ok")
                    st.toast(f"▶ {t['id']} in progress")
                if status == "in_progress" and board[bi].button("✅ Verify fix", key=f"t_verify_{t['id']}"):
                    t["status"] = "verified"
                    g = next((x for x in w["gaps"] if x["id"] == t["gap"]), None)
                    if g:
                        g["status"] = "pending_recheck"
                        w["rechecks"].append(dict(ctrl=g["ctrl"], ob=g["ob"], gap=g["id"], recheck=True))
                    emit(w, "sys", "FEED", f"Task {t['id']} verified → evidence re-collection queued", kind="ok")
                    st.toast("✅ Verified — Evidence Agent is re-checking the control")
            if not ts:
                board[bi].markdown('<div class="empty" style="padding:14px"><span style="font-size:11px">Queue clear ✨</span></div>',
                                   unsafe_allow_html=True)

    # ---------------- Approvals ----------------
    with tabs[5]:
        pend = [a for a in w["approvals"] if a["status"] == "pending"]
        st.caption(f"Human-in-the-loop inbox · confidence floor {cfg['conf']:.2f} · autonomy {cfg['autonomy']} · {w['decided']} decisions logged")
        if not pend:
            empty("✅", "Inbox zero", "Agents are operating above the confidence floor. Lower the floor or switch to 'Suggest only' to route more work here.")
        icons = {"mapping": "🧭", "gap": "⚠️", "collection": "🗄️", "loop": "🔁"}
        for ap in pend[:6]:
            p = ap["payload"]
            if ap["kind"] == "mapping":
                mm = next((x for x in w["mappings"] if x["id"] == p["map"]), None)
                summ = f"{mm['ob']} → {mm['ctrl']} ({CTL_BY[mm['ctrl']]['name']})" if mm else p["map"]
            elif ap["kind"] == "gap":
                g = next((x for x in w["gaps"] if x["id"] == p["gap"]), None)
                summ = f"{g['id']} · {g['type']} · {g['ctrl']} · {g['sev']}" if g else p["gap"]
            elif ap["kind"] == "collection":
                summ = f"{CTL_BY[p['item']['ctrl']]['src']} for {p['item']['ctrl']}"
            else:
                summ = f"{AGENTS[p['agent']]['name']} · {item_label(w, p['agent'], p['item'])}"
            st.markdown(f'<div class="card" style="--ac:{AMBER}"><h4>{icons[ap["kind"]]} {ap["id"]} · {esc(ap["kind"].upper())}</h4>'
                        f'<div class="meta">{esc(summ)}</div><div class="plan">{esc(ap["reason"])}</div>'
                        f'<div class="meta">{conf_bar(ap["conf"])}</div></div>', unsafe_allow_html=True)
            b1, b2, _ = st.columns([1, 1, 4])
            if b1.button("✅ Approve", key=f"ap_ok_{ap['id']}", type="primary"):
                decide(w, ap, True)
            if b2.button("🚫 Reject", key=f"ap_no_{ap['id']}"):
                decide(w, ap, False)
        if len(pend) > 6:
            st.caption(f"+ {len(pend)-6} more waiting — decisions are processed oldest first.")

    # ---------------- Audit Report ----------------
    with tabs[6]:
        stamp = w["clock"].strftime("%Y-%m-%d")
        r1, r2, r3 = st.columns(3)
        r1.download_button("📄 Gap report (.md)", gap_report_md(w, cfg),
                           file_name=f"aegis_gap_report_{stamp}.md", mime="text/markdown", key="rp_md")
        r2.download_button("🗄 Evidence package (.json)", evidence_package(w),
                           file_name=f"aegis_evidence_package_{stamp}.json", mime="application/json", key="rp_json")
        r3.download_button("🛠 Remediation tasks (.csv)", tasks_csv(w),
                           file_name=f"aegis_tasks_{stamp}.csv", mime="text/csv", key="rp_csv")
        st.caption("Exports reflect the live state at click time — evidence package includes a sha256 manifest and per-artefact provenance.")
        with st.expander("📄 Preview live report", expanded=True):
            st.markdown(gap_report_md(w, cfg))

    st.caption("AEGIS demo · synthetic data · simulated read-only connectors · no external calls · no API keys")


# ----------------------------------------------------------------------------- sidebar
def render_sidebar():
    with st.sidebar:
        st.markdown('<div class="brand" style="font-size:22px">AEGIS</div>'
                    '<div class="tagline">Control room</div>', unsafe_allow_html=True)
        w = S["world"]
        st.caption(f"{'🟢 running' if w['running'] else '🟠 paused'} · tick {w['tick']} · seed {w['seed']}")
        b1, b2 = st.columns(2)
        if b1.button("⏸ Pause" if w["running"] else "▶ Resume", key="run_toggle", type="primary"):
            w["running"] = not w["running"]
            if w["running"]:
                w["halt_reason"] = None
                w["last_adv"] = time.time()
        if b2.button("⏭ Step", key="step_btn"):
            w["step_request"] = True
        if st.button("⛔ Halt all agents (kill switch)", key="halt_btn"):
            w["running"] = False
            w["halt_reason"] = "manual"
            for key, a in w["agents"].items():
                if a["item"] is not None:
                    w["queues"][key].appendleft(a["item"])
                    a.update(item=None, status="idle", phase=-1)
            emit(w, "sys", "FEED", "⛔ KILL SWITCH — operator halt, in-flight work re-queued", kind="kill")
        st.divider()
        st.markdown("**Simulation**")
        speed = st.slider("Speed (ticks / sec)", 0.25, 3.0, DEFAULTS["speed"], 0.25, key="w_speed",
                          help="How fast the agent loop advances.")
        volatility = st.slider("Regulatory volatility", 0.0, 1.0, DEFAULTS["volatility"], 0.05, key="w_vol",
                               help="Chance a new regulatory update lands each tick.")
        seed = st.number_input("Scenario seed", 1, 9999, DEFAULTS["seed"], key="w_seed")
        s1, s2 = st.columns(2)
        if s1.button("🎲 Randomize", key="rand_btn"):
            S["_pending_seed"] = random.randint(1, 9999)
            RERUN()
        if s2.button("↺ Reset", key="reset_btn"):
            rebuild(S["cfg"]["seed"])
            st.toast("↺ Simulation reset & re-seeded")
        if st.button("⚡ Inject regulatory update", key="inject_sb"):
            enqueue_update(S["world"], forced=True)
            st.toast("📡 Update injected")
        st.divider()
        st.markdown("**Agent policy**")
        autonomy = st.selectbox("Autonomy level", AUTONOMY, index=1, key="w_auto",
                                help="Who signs off on mappings, gaps and tasks.")
        model = st.selectbox("Model router profile", list(PROFILES), index=1,
                             format_func=lambda k: PROFILE_LABEL[k], key="w_model")
        conf = st.slider("Confidence floor", 0.50, 0.95, DEFAULTS["conf"], 0.01, key="w_conf",
                         help="Below this, work is routed to the human approval inbox.")
        depth = st.slider("Evidence sampling depth", 1, 3, DEFAULTS["depth"], key="w_depth",
                          help="Deeper sampling → higher collection success, more tokens.")
        max_steps = st.slider("Max steps per item", 4, 12, DEFAULTS["max_steps"], key="w_steps",
                              help="Loop guard — items exceeding this are parked for review.")
        budget_k = st.slider("Token budget (K)", 100, 2000, DEFAULTS["budget_k"], 50, key="w_budget",
                             help="Kill switch fires when the run exceeds this budget.")
        defense = st.toggle("🛡 Prompt-injection defence", DEFAULTS["defense"], key="w_def",
                            help="Sandbox retrieved content and strip embedded instructions.")
        stale_guard = st.toggle("🕒 Stale-source guard", DEFAULTS["stale_guard"], key="w_stale",
                                help="Re-fetch canonical regulation text when the cache is old.")
        S["cfg"] = dict(speed=speed, volatility=volatility, autonomy=autonomy, model=model, conf=conf,
                        depth=depth, max_steps=max_steps, budget_k=budget_k, defense=defense,
                        stale_guard=stale_guard, seed=int(seed))
        if int(seed) != S["world"]["seed"]:
            rebuild(int(seed))
        st.divider()
        st.markdown("**Exports**")
        w = S["world"]
        stamp = w["clock"].strftime("%Y-%m-%d")
        st.download_button("📄 Gap report (.md)", gap_report_md(w, S["cfg"]),
                           file_name=f"aegis_gap_report_{stamp}.md", mime="text/markdown", key="sb_md")
        st.download_button("🗄 Evidence package (.json)", evidence_package(w),
                           file_name=f"aegis_evidence_package_{stamp}.json", mime="application/json", key="sb_json")
        st.download_button("🛠 Tasks (.csv)", tasks_csv(w),
                           file_name=f"aegis_tasks_{stamp}.csv", mime="text/csv", key="sb_csv")
        with st.expander("ℹ️ About this demo"):
            st.markdown(
                "**📡 Regulation Change Monitor** — diffs DORA, GDPR, NIS2, PCI DSS, SOC 2, ISO 27001, HIPAA, EU AI Act, NYDFS.\n\n"
                "**🧭 Control Mapping Engine** — links obligations to 14 controls with confidence & provenance.\n\n"
                "**🗄 Evidence Collection Agent** — read-only pulls, sha256 seals, freshness TTLs.\n\n"
                "**🩺 Gap Planner** — scores gaps, drafts remediation, routes to humans.\n\n"
                "Metrics: precision · recall · coverage · false-gap rate · hours saved · cost.")
        st.caption("Synthetic demo · read-only connectors · no external calls")


# ----------------------------------------------------------------------------- main
def main():
    st.set_page_config(page_title="AEGIS — Agentic Compliance Auditor", page_icon="🛡️",
                       layout="wide", initial_sidebar_state="expanded")
    st.markdown(CSS, unsafe_allow_html=True)
    if "cfg" not in S:
        S["cfg"] = dict(DEFAULTS)
    if S.get("_pending_seed"):
        s = S.pop("_pending_seed")
        S["w_seed"] = s
        rebuild(s)
        st.toast(f"🎲 Scenario re-seeded (#{s}) — world rebuilt")
    if "world" not in S:
        rebuild(DEFAULTS["seed"])
    render_sidebar()
    w = S["world"]
    interval = 1.0 / S["cfg"]["speed"]
    if HAS_FRAGMENT:
        st.fragment(run_every=interval if w["running"] else None)(render_live)()
    else:
        render_live()
        if S["world"]["running"]:
            time.sleep(min(interval, 2.0))
            RERUN()


main()