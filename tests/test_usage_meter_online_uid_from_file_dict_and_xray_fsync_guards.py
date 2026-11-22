"""回归测试：计量模块在线/流量控制字符 uid 拦截、from_file 非对象拒收、xray 顶层字典校验与目录刷盘关闭异常隔离。"""

import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, REPO / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


READERS = _load('um_readers_b63', 'usage-meter-readers-20261007-v1.py')
RUNTIME = _load('um_runtime_b63', 'usage-meter-runtime-20261007-v1.py')
XRAY_CFG = _load('um_xray_cfg_b63', 'usage-meter-xray-config-20261007-v1.py')


class _FakeResp:
    def __init__(self, payload: bytes, status=200):
        self._buf = io.BytesIO(payload)
        self.status = status

    def read(self, n=-1):
        return self._buf.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class UsageMeterOnlineUidFromFileDictAndXrayFsyncGuardsTests(unittest.TestCase):
    def test_read_hysteria_and_online_reject_empty_and_control_char_uids(self):
        """read_hysteria 与 read_hysteria_online 须拦截空串与含控制字符的 uid 键。"""
        with patch.object(READERS, '_open_no_redirect',
                          return_value=_FakeResp(json.dumps({'bad\nuid': {'tx': 1, 'rx': 2}}).encode('utf-8'))):
            with self.assertRaises(ValueError):
                READERS.read_hysteria('http://127.0.0.1:19996', 'sec')

        for bad_map in ({'': 1}, {'u\x001': 2}, {'u\r\n': 1}):
            with patch.object(READERS, '_open_no_redirect',
                              return_value=_FakeResp(json.dumps(bad_map).encode('utf-8'))):
                with self.assertRaises(ValueError, msg=f'应拦截非法在线 uid 键: {bad_map!r}'):
                    READERS.read_hysteria_online('http://127.0.0.1:19996', 'sec')

    def test_from_file_rejects_non_dict_top_level_config(self):
        """usage-meter-runtime from_file 遇到非 JSON 对象顶层配置须抛 ValueError 而非后续 AttributeError。"""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'usage-meter-config.json'
            for raw in ('[]', 'null', '"str"', '123'):
                p.write_text(raw, encoding='utf-8')
                with self.assertRaisesRegex(ValueError, 'JSON object'):
                    RUNTIME.from_file({}, object(), lambda: None, str(p))

    def test_xray_config_enable_reality_online_validates_dict_and_fsync_isolates_close(self):
        """enable_reality_online 须拒绝非字典顶层 xray.json，且 _fsync_parent_dir 须隔离 os.close 异常。"""
        with tempfile.TemporaryDirectory() as td:
            xj = Path(td) / 'xray.json'
            xj.write_text('[]', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'invalid xray config'):
                XRAY_CFG.enable_reality_online(str(xj), '/usr/local/bin/xray', '127.0.0.1:10085')

            with patch.object(os, 'open', return_value=99), \
                    patch.object(os, 'fsync', return_value=None), \
                    patch.object(os, 'close', side_effect=OSError('EBADF')):
                # 隔离 os.close OSError，不得向外抛异常
                XRAY_CFG._fsync_parent_dir(xj)


if __name__ == '__main__':
    unittest.main()
