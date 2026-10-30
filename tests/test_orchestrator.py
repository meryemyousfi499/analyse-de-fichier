"""Tests d'integration de l'orchestrateur (ClamAV/YARA/sandbox isoles)."""
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import (archive_handler, clamav_scan, ioc_extraction, orchestrator, pipeline,
                   quarantine, report_store, sandbox, verdict, yara_scan)

EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode()

CLAM_OK = {"disponible": True, "infecte": False, "signature": None, "statut_brut": "OK"}
CLAM_DOWN = {"disponible": False, "raison": "ClamAV injoignable : connexion refusee"}
CLAM_FOUND = {"disponible": True, "infecte": True, "signature": "Win.Test.EICAR_HDB-1", "statut_brut": "FOUND"}


def make_docx(path):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        z.writestr("_rels/.rels", '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>')
        z.writestr("word/document.xml", '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>')
        z.writestr("word/_rels/document.xml.rels", "<Relationships/>")
        z.writestr("docProps/app.xml", "<Properties>http://purl.org/dc/elements/1.1/</Properties>")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cn_test_")
        self.work = os.path.join(self.tmp, "work")
        os.makedirs(self.work)
        reports = os.path.join(self.tmp, "reports"); os.makedirs(reports)
        patches = [
            mock.patch.object(orchestrator, "REPORTS_DIR", reports),
            mock.patch.object(pipeline, "REPORTS_DIR", reports),
            mock.patch.object(report_store, "REPORTS_DIR", reports),
            mock.patch.object(report_store, "DB_PATH", os.path.join(self.tmp, "t.db")),
            mock.patch.object(report_store, "_initialized", False),
            mock.patch.object(quarantine, "QUARANTINE_DIR", os.path.join(self.tmp, "q")),
            mock.patch.object(sandbox, "SANDBOX_DIR", os.path.join(self.tmp, "sb")),
            mock.patch.object(sandbox, "SANDBOX_REPORTS_DIR", os.path.join(self.tmp, "sbr")),
            mock.patch.object(sandbox, "REPORTS_DIR", reports),
            mock.patch.object(sandbox, "HYBRID_ANALYSIS_API_KEY", ""),
            mock.patch.object(orchestrator, "SANDBOX_ALLOW_EXTERNAL_SUBMISSION", False),
            mock.patch.object(clamav_scan, "scan_with_clamav", return_value=CLAM_OK),
        ]
        os.makedirs(os.path.join(self.tmp, "q")); os.makedirs(os.path.join(self.tmp, "sb")); os.makedirs(os.path.join(self.tmp, "sbr"))
        for p in patches:
            p.start(); self.addCleanup(p.stop)
        self.reports = reports
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def f(self, name, data=b"hello"):
        p = os.path.join(self.work, name)
        with open(p, "wb") as fh:
            fh.write(data)
        return p

    def run_it(self, path, **kw):
        kw.setdefault("enable_threat_intel", False)
        return pipeline.run_pipeline(path, **kw)

    def report_files(self):
        return [x for x in os.listdir(self.reports) if x.endswith(".json")]


@unittest.skipUnless(yara_scan._HAS_YARA, "yara-python requis")
class OfficeAndRels(Base):
    def test_docx_is_one_report_no_component_children_no_sandbox(self):
        p = os.path.join(self.work, "rapport.docx"); make_docx(p)
        r = self.run_it(p)
        self.assertEqual(r["conteneur"], "office_ooxml")
        self.assertFalse(r["archive"]["est_archive"])
        self.assertEqual(len(self.report_files()), 1)       # plus de rapport par .rels / .xml
        self.assertEqual(os.listdir(os.path.join(self.tmp, "sbr")), [])  # rien en sandbox
        self.assertFalse(r["sandbox"]["recommande"])

    def test_renamed_docx_is_still_a_container(self):
        p = os.path.join(self.work, "facture.zip"); make_docx(p)
        self.assertEqual(archive_handler.container_kind(p), "office_ooxml")
        self.assertIsNone(archive_handler._is_archive(p))

    def test_isolated_rels_never_goes_to_sandbox(self):
        p = self.f("item1.xml.rels", b"<Relationships>http://evil.ru/x.exe powershell certutil</Relationships>")
        with mock.patch.object(clamav_scan, "scan_with_clamav", return_value=CLAM_FOUND):
            r = self.run_it(p)
        self.assertFalse(r["sandbox"]["recommande"])
        self.assertTrue(r["sandbox"]["bloquants"])
        self.assertEqual(os.listdir(os.path.join(self.tmp, "sbr")), [])

    def test_schema_urls_are_not_iocs(self):
        p = self.f("a.xml", b'<x xmlns="http://schemas.openxmlformats.org/a" y="http://purl.org/dc/elements/1.1/ http://www.w3.org/1999/xhtml"/>')
        iocs = ioc_extraction.extract_iocs(p)
        self.assertEqual(iocs["urls"], []); self.assertEqual(iocs["domaines"], [])
        self.assertEqual(iocs["score_indicateurs"], 0)


@unittest.skipUnless(yara_scan._HAS_YARA, "yara-python requis")
class YaraDisguise(Base):
    def test_legit_exe_not_flagged_but_pdf_named_exe_is(self):
        mz = b"MZ" + b"\0" * 200
        self.assertEqual(yara_scan.scan_file(self.f("setup.exe", mz))["matches"], [])
        names = [m["regle"] for m in yara_scan.scan_file(self.f("facture.pdf", mz))["matches"]]
        self.assertIn("PE_Disguised_As_Document", names)

    def test_disguise_not_double_counted(self):
        r = self.run_it(self.f("facture.pdf", b"MZ" + b"\0" * 200))
        expl = " ".join(r["score_final"]["explications"])
        self.assertIn("comptes une seule fois", expl)
        self.assertLess(r["score_final"]["score"], 100)


class VerdictAndCoverage(Base):
    def test_clamav_down_is_inconclusive_not_clean(self):
        with mock.patch.object(clamav_scan, "scan_with_clamav", return_value=CLAM_DOWN):
            r = self.run_it(self.f("note.txt", b"bonjour"))
        self.assertEqual(r["verdict"]["verdict"], "inconclusive")
        self.assertEqual(r["action"]["action"], "human_review")
        self.assertIn("clamav", [m["outil"] for m in r["verdict"]["couverture"]["manquants"]])

    def test_clamav_detection_is_malicious(self):
        with mock.patch.object(clamav_scan, "scan_with_clamav", return_value=CLAM_FOUND), \
             mock.patch.object(sandbox, "HYBRID_ANALYSIS_API_KEY", "cle-de-test"):
            r = self.run_it(self.f("eicar.com", EICAR))
        self.assertEqual(r["verdict"]["verdict"], "malicious")
        self.assertIn(r["action"]["action"], ("quarantine", "block"))
        self.assertTrue(r["sandbox"]["recommande"])
        # soumission externe non autorisee -> en attente de validation
        entry = sandbox.list_entries()[0]
        self.assertEqual(entry["statut"], "en_attente_validation")

    def test_sandbox_enqueue_failure_is_not_a_fake_critical(self):
        with mock.patch.object(clamav_scan, "scan_with_clamav", return_value=CLAM_FOUND), \
             mock.patch.object(sandbox, "enqueue", side_effect=FileNotFoundError("boom")):
            r = self.run_it(self.f("eicar.com", EICAR))
        self.assertNotIn("erreur_pipeline", r)
        self.assertIsNone(r["sandbox"]["id_soumission"])
        self.assertIn("boom", r["sandbox"]["erreur"])
        self.assertEqual(r["orchestration"]["outils"]["sandbox"]["status"], "error")

    def test_vanished_file_gives_neutralized_report(self):
        r = self.run_it(os.path.join(self.work, "disparu.exe"))
        self.assertIn("erreur_pipeline", r)
        self.assertEqual(r["score_final"]["niveau"], "critique")

    def test_complete_clean_is_clean_and_cached_on_rewatch(self):
        r1 = self.run_it(self.f("note.txt", b"bonjour"), origine="auto_watch")
        if yara_scan._HAS_YARA:
            self.assertEqual(r1["verdict"]["verdict"], "clean")
            r2 = self.run_it(self.f("copie.txt", b"bonjour"), origine="auto_watch")
            self.assertTrue(r2["cache"]["reutilise"])
            self.assertEqual(r2["id_rapport"], r1["id_rapport"])
            # un depot manuel n'utilise jamais le cache
            r3 = self.run_it(self.f("copie2.txt", b"bonjour"), origine="manuel")
            self.assertNotIn("cache", r3)

    def test_tool_error_is_error_not_ok(self):
        with mock.patch.object(orchestrator.static_analysis, "run_static_analysis", side_effect=RuntimeError("x")):
            r = self.run_it(self.f("note.txt", b"bonjour"))
        self.assertEqual(r["orchestration"]["outils"]["analyse_statique"]["status"], "error")
        self.assertNotEqual(r["verdict"]["verdict"], "clean")


class Archives(Base):
    def zip_bytes(self, members):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z:
            for n, d in members:
                z.writestr(n, d)
        return b.getvalue()

    def test_children_are_linked_to_parent(self):
        p = self.f("lot.zip", self.zip_bytes([("a.txt", b"x"), ("b.txt", b"y")]))
        r = self.run_it(p)
        self.assertEqual(len(r["sous_rapports_archive"]), 2)
        kids = [json.load(open(os.path.join(self.reports, x))) for x in self.report_files()
                if x[:-5] != r["id_rapport"]]
        self.assertTrue(all(k["id_parent"] == r["id_rapport"] and k["profondeur"] == 1 for k in kids))
        # l'historique masque les enfants
        self.assertEqual([h["id_rapport"] for h in pipeline.list_reports()], [r["id_rapport"]])

    def test_zip_slip_refused(self):
        p = self.f("evil.zip", self.zip_bytes([("../../escaped.txt", b"pwn"), ("ok.txt", b"ok")]))
        r = self.run_it(p)
        self.assertFalse(r["archive"]["extraction_reussie"])
        self.assertIn("refusee", r["archive"]["erreur"])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "escaped.txt")))
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(self.tmp), "escaped.txt")))

    def test_too_many_files_refused(self):
        p = self.f("many.zip", self.zip_bytes([(f"{i}.txt", b"x") for i in range(6)]))
        with mock.patch.object(archive_handler, "ARCHIVE_MAX_FILES", 3):
            r = self.run_it(p)
        self.assertFalse(r["archive"]["extraction_reussie"])
        self.assertIn("trop de fichiers", r["archive"]["erreur"])

    def test_nested_depth_limited(self):
        data = b"fin"
        name = "core.txt"
        for i in range(6):
            data = self.zip_bytes([(f"level{i}.zip" if i else name, data)])
        p = self.f("nested.zip", data)
        with mock.patch.object(orchestrator, "ARCHIVE_MAX_DEPTH", 2):
            r = self.run_it(p)
        depths = []
        for x in self.report_files():
            depths.append(json.load(open(os.path.join(self.reports, x)))["profondeur"])
        self.assertEqual(max(depths), 2)
        blocked = [json.load(open(os.path.join(self.reports, x))) for x in self.report_files()]
        self.assertTrue(any(b["archive"] and b["archive"].get("extraction_refusee") for b in blocked))


class SandboxCorrelation(Base):
    def test_completed_sandbox_updates_report_verdict(self):
        with mock.patch.object(clamav_scan, "scan_with_clamav", return_value=CLAM_OK):
            r = self.run_it(self.f("prog.js", b"var a=1;" ))
        entry = {"id": "abc", "report_id": r["id_rapport"], "statut": "termine", "verdict": "malicious",
                 "menaces_detectees": ["T1059 Command"], "comportements_informatifs": [], "updated_at": "now"}
        sandbox._correlate_with_report(entry)
        again = pipeline.get_report(r["id_rapport"])
        self.assertEqual(again["verdict"]["verdict"], "malicious")
        self.assertEqual(again["sandbox"]["resultat"]["verdict"], "malicious")

    def test_threat_split_informative_vs_malicious(self):
        summary = {"mitre_attcks": [
            {"tactic": "Execution", "technique": "Shared Modules", "attck_id": "T1129",
             "malicious_identifiers_count": 0, "suspicious_identifiers_count": 0, "informative_identifiers_count": 3},
            {"tactic": "Persistence", "technique": "Registry Run Keys", "attck_id": "T1547",
             "malicious_identifiers_count": 2, "suspicious_identifiers_count": 0, "informative_identifiers_count": 0}]}
        menaces, info, mitre = sandbox._summarize_threats(summary)
        self.assertEqual(menaces, ["T1547 Registry Run Keys (Persistence)"])
        self.assertEqual(info, ["T1129 Shared Modules (Execution)"])
        self.assertTrue(all(isinstance(x, str) for x in menaces + info))

    def test_purge_only_old_finished_copies(self):
        old = os.path.join(self.tmp, "sb", "old.bin"); open(old, "wb").write(b"x")
        os.utime(old, (1, 1))
        sandbox._save_entry({"id": "e1", "statut": "termine", "chemin_sandbox": old, "created_at": "x"})
        outside = os.path.join(self.tmp, "outside.bin"); open(outside, "wb").write(b"x"); os.utime(outside, (1, 1))
        sandbox._save_entry({"id": "e2", "statut": "termine", "chemin_sandbox": outside, "created_at": "y"})
        self.assertEqual(sandbox.purge_old_samples(1), 1)
        self.assertFalse(os.path.exists(old)); self.assertTrue(os.path.exists(outside))


class VerdictUnit(unittest.TestCase):
    def test_adjust_action(self):
        self.assertEqual(verdict.adjust_action("allow", "inconclusive"), "human_review")
        self.assertEqual(verdict.adjust_action("allow", "malicious"), "quarantine")
        self.assertEqual(verdict.adjust_action("block", "inconclusive"), "block")


if __name__ == "__main__":
    unittest.main()