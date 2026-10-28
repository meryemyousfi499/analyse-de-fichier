# tests/test_decision_engine.py

import unittest

from agent.decision_engine import decide_analysis


class DecisionEngineTests(unittest.TestCase):

    def setUp(self):
        self.file_info = {
            "file_name": "sample.pdf",
            "file_path": "sample.pdf",
            "extension": ".pdf",
            "size_bytes": 1024,
            "sha256": "abc123",
            "detected_type": "PDF",
            "extension_mismatch": False,
        }

    def test_detected_clamav_result_requests_sandbox(self):
        result = decide_analysis(
            self.file_info,
            clamav_result={
                "status": "infected",
                "signature": "Test.Signature",
            },
        )

        self.assertTrue(result["clamav_detected"])
        self.assertEqual(result["sandbox_status"], "a_soumettre")
        self.assertIn("clamav_detection", result["alerts"])

    def test_rels_is_not_applicable_for_sandbox(self):
        info = {
            **self.file_info,
            "file_name": "document.xml.rels",
            "extension": ".rels",
        }

        result = decide_analysis(info)

        self.assertEqual(result["sandbox_status"], "non_applicable")

    def test_oversized_file_is_not_submitted(self):
        info = {
            **self.file_info,
            "size_bytes": 100 * 1024 * 1024,
        }

        result = decide_analysis(
            info,
            max_sandbox_size=10 * 1024 * 1024,
        )

        self.assertEqual(result["sandbox_status"], "non_applicable")

    def test_disabled_sandbox(self):
        result = decide_analysis(
            self.file_info,
            sandbox_enabled=False,
        )

        self.assertEqual(result["sandbox_status"], "desactive")

    def test_extension_mismatch_is_flagged(self):
        info = {
            **self.file_info,
            "extension": ".exe",
            "detected_type": "PDF",
            "extension_mismatch": True,
        }

        result = decide_analysis(info)

        self.assertIn("extension_mismatch", result["alerts"])
        self.assertEqual(result["sandbox_status"], "a_soumettre")


if __name__ == "__main__":
    unittest.main()