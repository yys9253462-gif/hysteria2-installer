"""机主手工加的、带自己 tag 的 Reality 入站不被门户认领（2026-11-06 修）。"""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402

OWNER = {'tag': 'my-reality', 'protocol': 'vless', 'port': 9443,
         'settings': {'clients': [{'id': 'owner-uuid'}]},
         'streamSettings': {'security': 'reality', 'realitySettings': {'privateKey': 'OWNER'}}}


class RealityForeignInboundTests(unittest.TestCase):
    def test_tagged_foreign_inbound_is_not_managed(self):
        cfg = {'inbounds': [copy.deepcopy(OWNER)]}
        self.assertFalse(portal.has_managed_inbound(cfg, portal.REALITY_INBOUND_TAG))
        work = copy.deepcopy(cfg)
        self.assertFalse(portal.remove_managed_inbound(work, portal.REALITY_INBOUND_TAG))
        self.assertEqual(work['inbounds'], [OWNER], '机主自己的入站被删掉了')

    def test_legacy_untagged_inbound_is_still_claimed(self):
        legacy = copy.deepcopy(OWNER)
        legacy.pop('tag')
        self.assertTrue(portal.has_managed_inbound({'inbounds': [legacy]}, portal.REALITY_INBOUND_TAG))


if __name__ == '__main__':
    unittest.main()
