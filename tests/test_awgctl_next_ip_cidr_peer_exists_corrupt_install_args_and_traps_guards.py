"""回归测试：awgctl.sh 带掩码地址冲突、损坏 peers.json 容错、install 参数预检、混淆参数防溢出与清理陷阱。"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AWGCTL = ROOT / "awgctl.sh"


def _find_bash() -> str | None:
    cands = []
    if os.name == "nt":
        cands.extend([r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files\Git\usr\bin\bash.exe"])
    w = shutil.which("bash")
    if w:
        cands.append(w)
    for c in cands:
        if c and os.path.isfile(c) and not (os.name == "nt" and "system32" in c.lower()):
            return c
    return None


BASH = _find_bash()


def _to_bash_path(path: Path) -> str:
    s = str(path.resolve())
    if os.name == "nt" and len(s) >= 2 and s[1] == ":":
        return f"/{s[0].lower()}{s[2:].replace(chr(92), '/')}"
    return s.replace("\\", "/")


@unittest.skipUnless(BASH, "缺少可用 Bash")
class AwgctlBatch58Item3GuardTests(unittest.TestCase):
    """验证第五十八批第 3 项的 5 组边界防护。"""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="hy2-awg58-"))
        self.awgctl_posix = _to_bash_path(AWGCTL)
        self.src = AWGCTL.read_text(encoding="utf-8").replace("\r\n", "\n")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _preamble(self) -> str:
        return (
            "set -uo pipefail\n"
            f'eval "$(sed \'/^main "\\$@"$/d\' "{self.awgctl_posix}")"\n'
        )

    def _run_bash(self, script: str) -> subprocess.CompletedProcess[str]:
        assert BASH is not None
        return subprocess.run(
            [BASH, "-c", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )

    def test_next_peer_address_strips_cidr_suffix_to_avoid_ip_collision(self):
        """已有 peer 的 address 含 /32 后缀时，next_peer_address 必须识别已占用并分配下一个地址。"""
        np_start = self.src.index("next_peer_address() {")
        np_end = self.src.index("\n}\n", np_start)
        self.assertIn('split("/")[0]', self.src[np_start:np_end], "next_peer_address 必须先剥离 CIDR 掩码后缀再比对")
        if shutil.which("jq"):
            peers_file = self.tmp / "peers.json"
            peers_file.write_text('{"peers":[{"name":"c1","address":"10.66.66.2/32"}]}', encoding="utf-8")
            script = self._preamble() + f"""
AWG_SUBNET="10.66.66"
AWG_PEERS_FILE="{_to_bash_path(peers_file)}"
next_peer_address
"""
            res = self._run_bash(script)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout.strip(), "10.66.66.3", f"不应把已占用的 .2/32 重复分配，实际={res.stdout!r}")

    def test_peer_exists_handles_corrupt_peers_json_gracefully_under_set_e(self):
        """peers.json 损坏时 peer_exists 必须在 set -e 下安全返回 1 而非报错中断脚本。"""
        peers_file = self.tmp / "bad_peers.json"
        peers_file.write_text("{broken json", encoding="utf-8")
        script = "set -e\n" + self._preamble() + f"""
jq() {{ echo "parse error" >&2; return 4; }}
AWG_PEERS_FILE="{_to_bash_path(peers_file)}"
if peer_exists "alice"; then
    echo "FOUND"
else
    echo "NOT_FOUND"
fi
"""
        res = self._run_bash(script)
        self.assertEqual(res.returncode, 0, f"损坏 peers.json 不应中断 set -e，stderr={res.stderr!r}")
        self.assertEqual(res.stdout.strip(), "NOT_FOUND")
        self.assertEqual(res.stderr.strip(), "", f"不应泄漏 jq 错误到 stderr: {res.stderr!r}")

    def test_cmd_install_validates_client_and_server_name_upfront(self):
        """cmd_install 必须在下载二进制前就拒绝非法 --client（如 ../evil）和含控制字符的 --server-name。"""
        script_bad_client = self._preamble() + """
require_root() { return 0; }
require_jq() { return 0; }
command() { return 0; }
version_line() { echo "3"; }
download_binaries() { echo "SHOULD_NOT_DOWNLOAD" >&2; return 1; }
cmd_install --client "../evil"
"""
        r1 = self._run_bash(script_bad_client)
        self.assertNotEqual(r1.returncode, 0, "非法 --client 必须立即拒绝")
        self.assertIn("客户端名称非法", r1.stderr, f"应命中 --client 预检，stderr={r1.stderr!r}")
        self.assertNotIn("SHOULD_NOT_DOWNLOAD", r1.stderr)

        script_bad_sname = self._preamble() + """
require_root() { return 0; }
require_jq() { return 0; }
command() { return 0; }
version_line() { echo "3"; }
download_binaries() { echo "SHOULD_NOT_DOWNLOAD" >&2; return 1; }
cmd_install --server-name $'bad\\nname'
"""
        r2 = self._run_bash(script_bad_sname)
        self.assertNotEqual(r2.returncode, 0, "含换行的 --server-name 必须立即拒绝")
        self.assertIn("控制字符", r2.stderr, f"应命中 --server-name 预检，stderr={r2.stderr!r}")
        self.assertNotIn("SHOULD_NOT_DOWNLOAD", r2.stderr)

    def test_write_service_and_peers_init_have_return_traps_and_obfs_check_caps_digits(self):
        """write_service 与 peers_init 必须具备 RETURN 清理陷阱，且 3.x S1~S4 长度校验须限制数字位数防 64 位整数溢出。"""
        ws_start = self.src.index("write_service() {")
        ws_end = self.src.index("\n}\n", ws_start)
        self.assertIn("trap - RETURN;", self.src[ws_start:ws_end], "write_service 缺少 RETURN 清理陷阱")

        pi_start = self.src.index("peers_init() {")
        pi_end = self.src.index("\n}\n", pi_start)
        self.assertIn("trap - RETURN;", self.src[pi_start:pi_end], "peers_init 缺少 RETURN 清理陷阱")

        self.assertIn('[[ ! "$_s4" =~ ^[0-9]{1,5}$ ]]', self.src, "cmd_install S4 校验应限制数字位数防整数溢出")
        self.assertIn('[[ ! "$_sv" =~ ^[0-9]{1,5}$ ]]', self.src, "S1-S4 循环校验应限制数字位数防整数溢出")


if __name__ == "__main__":
    unittest.main()
