"""回归测试：install_singbox 多层穿越/设备节点/armhf、generate_vless_encryption_pair、分流域名与 outbounds 空数组插入。"""
from __future__ import annotations

import hashlib
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import portal  # noqa: E402


class _FakeResponse:
    def __init__(self, data: bytes):
        self._buf = io.BytesIO(data)

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class SingboxVlessencRouteAndOutboundBlockGuardTests(unittest.TestCase):
    """验证第五十八批第 6 项的 5 组安全与稳定性防护。"""

    def test_install_singbox_blocks_nested_dot_slash_traversal_and_fifo_and_maps_armhf(self):
        """install_singbox 必须拦截 '././/etc/passwd' 与 FIFO/设备节点成员，且支持 armhf 映射。"""
        with tempfile.TemporaryDirectory(prefix="hy2-sb-tar-") as td:
            # 1) 构造含 '././/etc/passwd' 的 tar.gz
            buf_trav = io.BytesIO()
            with tarfile.open(fileobj=buf_trav, mode="w:gz") as tf:
                sb = tarfile.TarInfo("sing-box-1.12.0-linux-armv7/sing-box")
                sb.size = 4
                tf.addfile(sb, io.BytesIO(b"ELF!"))
                evil = tarfile.TarInfo("././/etc/passwd")
                evil.size = 3
                tf.addfile(evil, io.BytesIO(b"bad"))
            tar_bytes = buf_trav.getvalue()
            sha = hashlib.sha256(tar_bytes).hexdigest()
            meta = json.dumps({
                "tag_name": "v1.12.0",
                "assets": [{"name": "sing-box-1.12.0-linux-armv7.tar.gz", "digest": "sha256:" + sha}],
            }).encode("utf-8")

            def fake_urlopen(req, timeout=15):
                url = req.full_url if hasattr(req, "full_url") else str(req)
                if "api.github.com" in url:
                    return _FakeResponse(meta)
                return _FakeResponse(tar_bytes)

            with (
                mock.patch.object(portal, "_singbox_version", return_value=None),
                mock.patch.object(portal.platform, "machine", return_value="armhf"),
                mock.patch.object(portal.urllib.request, "urlopen", side_effect=fake_urlopen),
                mock.patch.object(portal, "ANYTLS_BINARY", str(Path(td) / "sing-box")),
            ):
                ok, msg = portal.install_singbox()
            self.assertFalse(ok, f"armhf 下含 '././/etc/passwd' 的包绝不可安装成功: {msg}")
            self.assertNotIn("不支持的 CPU 架构", msg, f"armhf 必须被映射到 armv7，实际: {msg}")
            self.assertIn("不安全路径成员", msg, f"应命中多层路径穿越拦截，实际: {msg}")

            # 2) 构造含 FIFO 特殊文件的 tar.gz
            buf_fifo = io.BytesIO()
            with tarfile.open(fileobj=buf_fifo, mode="w:gz") as tf:
                sb = tarfile.TarInfo("sing-box-1.12.0-linux-amd64/sing-box")
                sb.size = 4
                tf.addfile(sb, io.BytesIO(b"ELF!"))
                fifo = tarfile.TarInfo("sing-box-1.12.0-linux-amd64/evil_fifo")
                fifo.type = tarfile.FIFOTYPE
                tf.addfile(fifo)
            fifo_bytes = buf_fifo.getvalue()
            fifo_sha = hashlib.sha256(fifo_bytes).hexdigest()
            meta_amd = json.dumps({
                "tag_name": "v1.12.0",
                "assets": [{"name": "sing-box-1.12.0-linux-amd64.tar.gz", "digest": "sha256:" + fifo_sha}],
            }).encode("utf-8")

            def fake_urlopen2(req, timeout=15):
                url = req.full_url if hasattr(req, "full_url") else str(req)
                if "api.github.com" in url:
                    return _FakeResponse(meta_amd)
                return _FakeResponse(fifo_bytes)

            with (
                mock.patch.object(portal, "_singbox_version", return_value=None),
                mock.patch.object(portal.platform, "machine", return_value="x86_64"),
                mock.patch.object(portal.urllib.request, "urlopen", side_effect=fake_urlopen2),
                mock.patch.object(portal, "ANYTLS_BINARY", str(Path(td) / "sing-box")),
            ):
                ok2, msg2 = portal.install_singbox()
            self.assertFalse(ok2)
            self.assertIn("不允许", msg2, f"含 FIFO 特殊文件的包必须被拒，实际: {msg2}")

    def test_generate_vless_encryption_pair_validates_binary_and_encryption_format(self):
        """generate_vless_encryption_pair 必须拒非法 binary 与畸形 encryption，并将执行异常转为 RuntimeError。"""
        with self.assertRaises(RuntimeError):
            portal.generate_vless_encryption_pair("-bad-bin")

        bad_enc_out = SimpleNamespace(
            returncode=0,
            stdout='"decryption": "mlkem768x25519plus.native.600s.AAAA"\n"encryption": "bad enc\\nwith space"\n',
        )
        with mock.patch.object(portal.subprocess, "run", return_value=bad_enc_out):
            with self.assertRaises(RuntimeError):
                portal.generate_vless_encryption_pair("/usr/local/bin/xray")

        with mock.patch.object(portal.subprocess, "run", side_effect=OSError("no such binary")):
            with self.assertRaises(RuntimeError):
                portal.generate_vless_encryption_pair("/usr/local/bin/xray")

    def test_valid_route_domain_rejects_overlong_and_edge_hyphen(self):
        """_valid_route_domain 必须拒绝前导/尾随连字符与超 253 字符域名，并保留单标签合法名。"""
        self.assertFalse(portal._valid_route_domain("-bad.example.com"))
        self.assertFalse(portal._valid_route_domain("bad-.example.com"))
        self.assertFalse(portal._valid_route_domain("a" * 260 + ".com"))
        self.assertTrue(portal._valid_route_domain("openai.com"))
        self.assertTrue(portal._valid_route_domain("cn"))

    def test_upsert_outbound_block_handles_inline_empty_outbounds_list(self):
        """config.yaml 存在 `outbounds: []` 时，upsert_outbound_block 必须展开为块列表而非写出非法 YAML。"""
        cfg = "listen: :443\noutbounds: []\nmasquerade:\n  type: proxy\n"
        outbounds = [{"name": "my_socks", "type": "socks5", "addr": "127.0.0.1:1080"}]
        rendered = portal.upsert_outbound_block(cfg, outbounds)
        self.assertNotIn("outbounds: []", rendered, f"不得保留内联空数组导致非法 YAML:\n{rendered}")
        self.assertIn("outbounds:\n  - name: 'my_socks'\n", rendered)

    def test_build_acl_block_and_build_warp_acl_config_deduplicate_rules_and_filter_dirty_existing(self):
        """build_acl_block 与 build_warp_acl_config 须去重重复规则并过滤脏 existing_names。"""
        rules = [
            {"domain": "openai.com", "outbound": "warp_socks"},
            {"domain": "openai.com", "outbound": "warp_socks"},
        ]
        acl = portal.build_acl_block("rules", rules, [], tail_outbound="direct", existing_names=["warp_socks", "bad\nname", 123])
        self.assertEqual(acl.count("warp_socks(suffix:openai.com)"), 1, f"不应重复输出同一 ACL 规则:\n{acl}")

        warp_cfg = portal.build_warp_acl_config("listen: :443\n", True, rules)
        self.assertEqual(warp_cfg.count("warp_socks(suffix:openai.com)"), 1, f"build_warp_acl_config 不应重复输出同一规则:\n{warp_cfg}")


if __name__ == "__main__":
    unittest.main()
