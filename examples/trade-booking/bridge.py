"""Check pinned bytes; reuse the upstream verifier; project counted facts, not labels."""
from hashlib import sha256
from importlib.metadata import version
from pathlib import Path
import json

from agent_evidence_vectors.trade_booking.reader import AXES, evaluate, summary
from agent_evidence_vectors.trade_booking.run import PACKAGED_CORPUS, load_corpus

PINS = {
    "manifest.json": "3c99f8663ed68a30ae809ae0cd28f1d519f37d109286a46bad2240a90f4e1b1c",
    "cases.json": "ae21c646550fcc375ae92d6ad8bcc7dbe11cec17ec726157bfbc112f135ae469",
    "occurrence.json": "4aa62ba6bbbac9136f75673c947bbf053b8e4ae23e80ee8b9ba5c2f71150a09e",
    "trust.json": "284ef93c6d5b2ee86ee0c592ea070fa65447958d73396dd3555b238a7c1d819b",
}


def project(case, actual):
    # `actual.statements` records signature, role and booking-binding checks.
    # The expected labels and the seven axis verdicts are never consulted here.
    counted = [case["statements"][s["index"]]["statement"]
               for s in actual["statements"] if s["standing"] == "counted"]
    records = sorted((s for s in counted if s["schema"] == "aev-booking-record/v1"),
                     key=lambda s: s["observed_at"])
    replies = [s for s in counted if s["schema"] == "aev-cancel-reply/v1"]
    ledgers = [s for s in counted if s["schema"] == "aev-agent-ledger/v1"]
    current = records[-1] if records else None
    events = {e["event_id"] for r in records for e in r["cancel_events"]}
    events |= {r["event_id"] for r in replies if r["outcome"] != "error" and "event_id" in r}
    confirmation = any(r["status"] == "cancelled" and r["cancel_events"] for r in records)
    confirmation |= any(r["outcome"] != "error" and "event_id" in r for r in replies)
    return {
        "recordStatus": current["status"] if current else "unknown",
        "eventCount": len(events),
        "confirmationEvidence": bool(confirmation),
        "cancelSignatureBroken": any(s["standing"] == "broken_signature" and
                                      s["schema"] == "aev-cancel-reply/v1" for s in actual["statements"]),
        "ledgerClaimUnbacked": bool(ledgers and ledgers[0]["claims_cancel_confirmed"] and
                                   current and current["status"] == "booked"),
    }


def check_pins(root: Path):
    for name, pinned in PINS.items():
        if sha256((root / name).read_bytes()).hexdigest() != pinned:
            raise ValueError(f"Upstream corpus digest mismatch: {name}")


def main():
    if version("agent-evidence-vectors") != "0.28.0":
        raise ValueError("Install the hash-pinned requirements.txt")
    check_pins(PACKAGED_CORPUS)
    occurrence, trust, cases, _ = load_corpus(PACKAGED_CORPUS)
    rows = []
    for case in cases["cases"]:
        # Even the upstream evaluator receives no case ID or expected verdict.
        actual = evaluate(occurrence, trust, {"statements": case["statements"]})
        rows.append({"caseId": case["id"], "evidence": project(case, actual),
                     "upstreamActual": summary(actual), "upstreamExpected": case["expected"],
                     "upstreamMatches": summary(actual) == case["expected"]})
    if len(rows) != 21:
        raise ValueError("Expected the frozen 21-case corpus")
    print(json.dumps({"version": "0.28.0", "digests": PINS, "axes": AXES,
                      "bookingRef": occurrence["booking"]["booking_ref"], "rows": rows}))


if __name__ == "__main__":
    main()
