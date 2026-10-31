"""Failure paths of the generated terminal portal updater, using fake downloads."""
import hashlib
import json
import unittest

import test_terminal_portal_transaction as fixtures


class TerminalPortalRegressions(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.TerminalPortalTransactionTests(methodName='test_success_preserves_data_and_complete_backup')
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)

    def _run_failure(self):
        child = self.fx.launch()
        stdout, stderr = child.communicate(timeout=40)
        self.assertNotEqual(child.returncode, 0, (stdout + stderr).decode('utf-8', 'replace'))
        self.fx.assert_original()

    def test_unavailable_version_does_not_report_success(self):
        (self.fx.fixture / 'commit.json').unlink()
        self._run_failure()
        self.assertEqual(self.fx.events(), [])

    def test_missing_bundle_member_leaves_all_previous_files(self):
        (self.fx.fixture / 'usage-meter-runtime-20261007-v1.py').unlink()
        self._run_failure()
        self.assertEqual(self.fx.events(), [])

    def test_syntax_invalid_even_with_matching_blob_is_rejected(self):
        path = self.fx.fixture / 'portal.py'
        data = b'def page_html(): pass\ninvalid python (\n'
        path.write_bytes(data)
        mapping = json.loads((self.fx.fixture / 'map.json').read_text())
        for row in mapping:
            if row['name'] == 'portal.py':
                row['sha'] = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        (self.fx.fixture / 'map.json').write_text(json.dumps(mapping))
        self._run_failure()
        self.assertEqual(self.fx.events(), [])

    def test_valid_python_with_wrong_blob_is_rejected(self):
        mapping = json.loads((self.fx.fixture / 'map.json').read_text())
        for row in mapping:
            if row['name'] == 'portal.py':
                row['sha'] = '0' * 40
        (self.fx.fixture / 'map.json').write_text(json.dumps(mapping))
        self._run_failure()
        self.assertEqual(self.fx.events(), [])


if __name__ == '__main__':
    unittest.main()
