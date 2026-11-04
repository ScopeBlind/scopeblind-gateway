"""Independent mutations of valid evidence; expected fixture labels never drive projection."""
import copy
from pathlib import Path
import tempfile
import unittest

from bridge import check_pins, project, PINS
from agent_evidence_vectors.trade_booking.reader import booking_binding, canonical, evaluate
from agent_evidence_vectors.trade_booking.run import PACKAGED_CORPUS, load_corpus
from agent_evidence_vectors.w3cintake import ed25519_verify


class EvidenceBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.occurrence, cls.trust, cls.corpus, _ = load_corpus(PACKAGED_CORPUS)
        # Select by statement shape, not expected verdict or case identifier.
        cls.reply = next(copy.deepcopy(s) for c in cls.corpus["cases"] for s in c["statements"]
                         if s["statement"]["schema"] == "aev-cancel-reply/v1"
                         and s["statement"].get("event_id") and s["statement"]["outcome"] == "confirmed")
        records = [s for c in cls.corpus["cases"] for s in c["statements"]
                   if s["statement"]["schema"] == "aev-booking-record/v1"]
        cls.other_booking = next(copy.deepcopy(s) for s in records
                                 if s["statement"]["binding"] != booking_binding(cls.occurrence))
        cls.agent_record = next(copy.deepcopy(s) for s in records
                                if s["keyid"] in cls.trust["roles"]["agent_system"])

    def facts(self, reply):
        case = {"statements": [reply]}
        return project(case, evaluate(self.occurrence, self.trust, case))

    def assert_valid_signature(self, envelope):
        public = bytes.fromhex(self.trust["keys"][envelope["keyid"]]["public_hex"])
        self.assertTrue(ed25519_verify(public, canonical(envelope["statement"]),
                                       bytes.fromhex(envelope["signature_hex"])))

    def test_valid_signed_event(self):
        facts = self.facts(self.reply)
        self.assertEqual(facts["eventCount"], 1)
        self.assertTrue(facts["confirmationEvidence"])

    def test_tampered_event_does_not_count(self):
        reply = copy.deepcopy(self.reply)
        reply["statement"]["event_id"] = "invented-by-model"
        facts = self.facts(reply)
        self.assertEqual(facts["eventCount"], 0)
        self.assertTrue(facts["cancelSignatureBroken"])

    def test_another_booking_record_does_not_count(self):
        # An unchanged, correctly signed upstream negative: a bad signature
        # cannot mask failure to enforce the booking binding.
        self.assert_valid_signature(self.other_booking)
        case = {"statements": [self.other_booking]}
        actual = evaluate(self.occurrence, self.trust, case)
        self.assertEqual(actual["statements"][0]["standing"], "names_other_booking")
        self.assertEqual(actual["statements"][0]["reason"], "names_another_booking_or_client")
        self.assertEqual(project(case, actual)["recordStatus"], "unknown")

    def test_agent_signed_booking_record_does_not_count(self):
        # This signature really verifies under the agent's published test key;
        # only the missing booking-system role must keep its claim out.
        self.assert_valid_signature(self.agent_record)
        case = {"statements": [self.agent_record]}
        actual = evaluate(self.occurrence, self.trust, case)
        self.assertEqual(actual["statements"][0]["standing"], "not_counted")
        self.assertEqual(actual["statements"][0]["reason"], "key_not_trusted_for_role")
        self.assertEqual(project(case, actual)["recordStatus"], "unknown")

    def test_unknown_signer_does_not_count(self):
        reply = copy.deepcopy(self.reply)
        reply["keyid"] = "sha256:" + "0" * 64
        self.assertEqual(self.facts(reply)["eventCount"], 0)

    def test_expected_labels_and_case_id_cannot_change_projection(self):
        case = copy.deepcopy(self.corpus["cases"][0])
        before = project(case, evaluate(self.occurrence, self.trust, case))
        case["expected"] = {"cancel_confirmed": "invented-verdict"}
        case["id"] = "not-a-known-case"
        after = project(case, evaluate(self.occurrence, self.trust, case))
        self.assertEqual(before, after)

    def test_pinned_corpus_refuses_modified_bytes_even_if_manifest_is_rewritten(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in PINS:
                (root / name).write_bytes((PACKAGED_CORPUS / name).read_bytes())
            check_pins(root)
            (root / "cases.json").write_bytes((root / "cases.json").read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                check_pins(root)


if __name__ == "__main__":
    unittest.main()
