"""回归测试：awgctl.sh 事务回滚、二进制更新与客户端备份恢复均须使用同目录原子替换。"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AWG = (ROOT / 'awgctl.sh').read_text(encoding='utf-8')
BASH = shutil.which('bash')


class AwgAtomicRestoreTests(unittest.TestCase):
    def test_transaction_restore_and_peer_restore_do_not_overwrite_in_place(self):
        m_tx = re.search(r'awg_transaction_restore\(\) \{.*?\n\}', AWG, re.S)
        self.assertIsNotNone(m_tx)
        self.assertNotIn('cp -a "$AWG_TRANSACTION_DIR/bin.$index" "$path"', m_tx.group(0),
                         '回滚二进制直接 cp -a 覆盖运行中程序会触发 ETXTBSY')
        self.assertNotIn('cp -a "$AWG_TRANSACTION_DIR/$index" "$path"', m_tx.group(0),
                         '回滚配置直接 cp -a 存在非原子半写窗口')

        m_peer = re.search(r'restore_peer_files\(\) \{.*?\n\}', AWG, re.S)
        self.assertIsNotNone(m_peer)
        self.assertNotIn('cp -p "$peers_backup" "$AWG_PEERS_FILE"', m_peer.group(0))
        self.assertNotIn('cp -p "$config_backup" "$AWG_CONFIG"', m_peer.group(0))

    def test_download_binaries_smoke_tests_before_replacing_live_binaries_and_uses_atomic_mv(self):
        m_dl = re.search(r'download_binaries\(\) \{.*?\n\}', AWG, re.S)
        self.assertIsNotNone(m_dl)
        body = m_dl.group(0)
        self.assertNotIn('install -m 0755 "${tmpd}/amneziawg-go" "$AWG_GO_BIN"', body,
                         '直接 install 覆写目标二进制未走同目录暂存原子替换')
        smoke_pos = body.find('--version')
        replace_pos = body.find('AWG_GO_BIN')
        # 检查冒烟校验出现在替换现役二进制之前
        install_call_pos = body.find('awg_atomic_install_bin')
        self.assertGreater(install_call_pos, 0, 'download_binaries 应使用 awg_atomic_install_bin 原子替换')
        self.assertLess(smoke_pos, install_call_pos, '应先对解压出的新 awg 做冒烟校验再替换现役二进制')

    @unittest.skipUnless(BASH, 'requires bash')
    def test_atomic_copy_helper_replaces_target_and_cleans_temp(self):
        m_fn = re.search(r'(awg_atomic_copy_file\(\) \{.*?\n\})', AWG, re.S)
        self.assertIsNotNone(m_fn, '缺少 awg_atomic_copy_file 辅助函数')
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            src = td_path / 'bak.bin'
            dst = td_path / 'live.bin'
            src.write_bytes(b'NEW-CONTENT')
            dst.write_bytes(b'OLD-CONTENT')
            cmd = m_fn.group(1) + '\nawg_atomic_copy_file "$1" "$2"\n'
            res = subprocess.run([BASH, '-c', cmd, '_', str(src), str(dst)],
                                 capture_output=True, text=True, timeout=15)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(dst.read_bytes(), b'NEW-CONTENT')
            leftovers = [p.name for p in td_path.iterdir() if '.restore.' in p.name]
            self.assertEqual(leftovers, [])


if __name__ == '__main__':
    unittest.main()
