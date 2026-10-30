"""Regression tests for the latest Reality and capability changes."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal


class TestRealityClients(unittest.TestCase):
    def test_disabled_user_is_removed_but_registry_mapping_is_preserved(self):
        data = {
            'users': {
                'active-user': {'status': 'active'},
                'disabled-user': {'status': 'disabled'},
            },
            'reality_users': {
                'active-user': 'uuid-active',
                'disabled-user': 'uuid-disabled',
            },
        }

        clients = portal.reality_clients(data)

        self.assertEqual([c['email'] for c in clients], ['active-user'])
        self.assertEqual(data['reality_users']['disabled-user'], 'uuid-disabled')

    def test_missing_status_remains_active_for_legacy_users(self):
        data = {
            'users': {'legacy-user': {}},
            'reality_users': {'legacy-user': 'uuid-legacy'},
        }

        clients = portal.reality_clients(data)

        self.assertEqual([c['email'] for c in clients], ['legacy-user'])


class TestRealityPublicParameters(unittest.TestCase):
    def test_only_expected_client_parameters_are_returned(self):
        result = portal._reality_public_params({
            'public_key': 'client-public-key',
            'short_id': 'abcd1234',
            'dest_sni': 'node.example.test',
            'port': '2053',
            'private_key': 'server-secret',
            'unexpected': 'must-not-pass-through',
        })

        self.assertEqual(result, {
            'public_key': 'client-public-key',
            'short_id': 'abcd1234',
            'dest_sni': 'node.example.test',
            'port': 2053,
        })

    def test_invalid_port_and_empty_values_are_omitted(self):
        for bad in (70000, 0, -1, 'abc', True, 1.5, float('inf')):
            with self.subTest(bad=bad):
                self.assertEqual(
                    portal._reality_public_params({'public_key': ' ', 'port': bad}),
                    {},
                )


class TestRealityPortSelection(unittest.TestCase):
    def test_existing_port_is_kept_when_reality_already_listens_on_it(self):
        with patch.object(portal, '_listening_ports', return_value={443, 22}):
            port, _reason = portal._pick_reality_port(preferred=443)
        self.assertEqual(port, 443)

    def test_occupied_and_reserved_candidates_are_skipped(self):
        with patch.object(portal, '_listening_ports', return_value={443, 8443}):
            port, _reason = portal._pick_reality_port(extra_blocked={2053})
        self.assertEqual(port, 2083)

    def test_invalid_preference_does_not_abort_selection(self):
        with patch.object(portal, '_listening_ports', return_value=set()):
            port, _reason = portal._pick_reality_port(preferred='not-a-port')
        self.assertEqual(port, 443)


if __name__ == '__main__':
    unittest.main(verbosity=2)
