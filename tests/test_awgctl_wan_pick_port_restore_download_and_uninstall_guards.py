"""针对 awgctl.sh 网卡校验、选口边界、事务恢复、下载校验与卸载防误删的回归测试。"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AWGCTL = ROOT / "awgctl.sh"


def _find_bash() -> str | None:
    """优先寻找可用的 GNU Bash（在 Windows 上跳过仅指向 WSL 的 system32/bash.exe）。"""
    candidates = []
    if os.name == "nt":
        candidates.extend([
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files\Git\usr\bin\bash.exe",
        ])
    found = shutil.which("bash")
    if found:
        candidates.append(found)
    for path in candidates:
        if not path or not Path(path).is_file():
            continue
        if os.name == "nt" and "system32" in path.lower():
            continue
        return path
    return None


BASH_BIN = _find_bash()


def _to_bash_path(path: Path) -> str:
    s = str(path.resolve())
    if os.name == "nt" and len(s) >= 2 and s[1] == ":":
        drive = s[0].lower()
        rest = s[2:].replace("\\", "/")
        return f"/{drive}{rest}"
    return s.replace("\\", "/")


def _run_bash(script: str, env_extra: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    assert BASH_BIN is not None, "缺少可用 GNU Bash"
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [BASH_BIN, "-c", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=30,
    )


@unittest.skipUnless(BASH_BIN, "当前环境缺少可用 Bash")
class AwgctlHardeningTests(unittest.TestCase):
    """验证 awgctl.sh 的 5 组关键边界防护。"""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="hy2-awg-guard-"))
        self.awgctl_posix = _to_bash_path(AWGCTL)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _source_preamble(self) -> str:
        """载入 awgctl.sh 全部函数定义但不触发底部 main。"""
        return (
            "set -uo pipefail\n"
            f'eval "$(sed \'/^main "\\$@"$/d\' "{self.awgctl_posix}")"\n'
        )

    def test_detect_wan_iface_rejects_dotdot_and_malformed_names(self) -> None:
        """detect_wan_iface 必须拒绝 '..' 或含空白/特殊字符的伪造出口网卡名。"""
        # 在模拟环境中覆盖 ip 命令返回 'default via 1.1.1.1 dev ..'，
        # /sys/class/net/.. 在 Linux 上必然作为父目录真实存在，或者这里直接用符号检查。
        script = self._source_preamble() + """
ip() {
    echo "default via 192.0.2.1 dev .."
}
detect_wan_iface
"""
        res = _run_bash(script)
        self.assertNotEqual(res.returncode, 0, f"不应把 '..' 当合法网卡返回，stdout={res.stdout!r}")
        self.assertNotEqual(res.stdout.strip(), "..")
        self.assertIn("网卡名非法", res.stderr, f"应命中网卡名合法性校验，stderr={res.stderr!r}")

        script_bad = self._source_preamble() + """
ip() {
    echo "default via 192.0.2.1 dev eth0;id"
}
detect_wan_iface
"""
        res2 = _run_bash(script_bad)
        self.assertNotEqual(res2.returncode, 0, f"不应接受含分号的网卡名，stdout={res2.stdout!r}")
        self.assertIn("网卡名非法", res2.stderr, f"应命中网卡名合法性校验，stderr={res2.stderr!r}")

    def test_pick_port_skips_hy2_hop_range_and_handles_huge_hy2_port(self) -> None:
        """pick_port 必须跳过 20000-40000 跳跃区间，并对超长 hy2_port 与越界范围安全处理。"""
        script = self._source_preamble() + """
ss() { echo ""; }
AWG_PORT_MIN=19999
AWG_PORT_MAX=40000
pick_port "00001"
"""
        res = _run_bash(script)
        self.assertEqual(res.returncode, 0, f"应能选出 19999，stderr={res.stderr!r}")
        self.assertEqual(res.stdout.strip(), "19999")

        # 全部落在 20000-40000 内时应无可用端口返回非 0，而不是挑出跳跃区间内端口
        script_none = self._source_preamble() + """
ss() { echo ""; }
AWG_PORT_MIN=20000
AWG_PORT_MAX=20010
pick_port ""
"""
        res_none = _run_bash(script_none)
        self.assertNotEqual(res_none.returncode, 0, f"区间全在跳跃段内不应选出端口，stdout={res_none.stdout!r}")

        # 超长数字 hy2_port 不得触发 Python int 超长数字异常导致选口失败
        huge = "9" * 5000
        script_huge = self._source_preamble() + f"""
ss() {{ echo ""; }}
AWG_PORT_MIN=41000
AWG_PORT_MAX=41002
pick_port "{huge}"
"""
        res_huge = _run_bash(script_huge)
        self.assertEqual(res_huge.returncode, 0, f"超长 hy2_port 不应导致崩溃，stderr={res_huge.stderr!r}")
        picked = int(res_huge.stdout.strip())
        self.assertIn(picked, (41000, 41001, 41002))

    def test_awg_transaction_restore_guards_missing_state_and_bad_dir_mode(self) -> None:
        """awg_transaction_restore 缺少 service-state 必须失败，非法目录权限应回退 700。"""
        tx_missing = self.tmp / "tx_missing"
        tx_missing.mkdir()
        script_missing = self._source_preamble() + f"""
AWG_TRANSACTION_DIR="{_to_bash_path(tx_missing)}"
AWG_DIR="{_to_bash_path(self.tmp / 'cfg_missing')}"
AWG_META_FILE="$AWG_DIR/meta.json"
AWG_CONFIG="$AWG_DIR/awg0.conf"
AWG_PEERS_FILE="$AWG_DIR/peers.json"
AWG_SERVICE="{_to_bash_path(self.tmp / 'awg-quick@awg0.service')}"
AWG_VERSION_FILE="$AWG_DIR/version"
AWG_GO_BIN="{_to_bash_path(self.tmp / 'amneziawg-go')}"
AWG_BIN="{_to_bash_path(self.tmp / 'awg')}"
AWG_QUICK_BIN="{_to_bash_path(self.tmp / 'awg-quick')}"
systemctl() {{ echo "SHOULD_NOT_CALL:$*" >&2; return 0; }}
awg_transaction_restore
"""
        res_missing = _run_bash(script_missing)
        self.assertNotEqual(res_missing.returncode, 0, "缺失 service-state 时必须拒绝恢复")
        self.assertNotIn("SHOULD_NOT_CALL", res_missing.stderr)

        # 非法 AWG_TRANSACTION_DIR_MODE（如空串或 'abc'）时必须安全回退 700 而非中途失败
        tx_mode = self.tmp / "tx_mode"
        tx_mode.mkdir()
        (tx_mode / "service-state").write_text("inactive\nnot-found\n", encoding="utf-8")
        (tx_mode / "original-dir.present").write_text("", encoding="utf-8")
        cfg_dir = self.tmp / "cfg_mode"
        script_mode = self._source_preamble() + f"""
AWG_TRANSACTION_DIR="{_to_bash_path(tx_mode)}"
AWG_TRANSACTION_DIR_MODE="badmode"
AWG_DIR="{_to_bash_path(cfg_dir)}"
AWG_META_FILE="$AWG_DIR/meta.json"
AWG_CONFIG="$AWG_DIR/awg0.conf"
AWG_PEERS_FILE="$AWG_DIR/peers.json"
AWG_SERVICE="{_to_bash_path(self.tmp / 'awg-quick@awg0.service')}"
AWG_VERSION_FILE="$AWG_DIR/version"
AWG_GO_BIN="{_to_bash_path(self.tmp / 'amneziawg-go')}"
AWG_BIN="{_to_bash_path(self.tmp / 'awg')}"
AWG_QUICK_BIN="{_to_bash_path(self.tmp / 'awg-quick')}"
systemctl() {{ return 0; }}
awg_transaction_restore
"""
        res_mode = _run_bash(script_mode)
        self.assertEqual(res_mode.returncode, 0, f"非法目录权限应回退 700 完成恢复，stderr={res_mode.stderr!r}")
        self.assertTrue(cfg_dir.is_dir())

    def test_download_binaries_blocks_nested_dot_slash_abs_member_and_supports_nested_dot_slash_sums(self) -> None:
        """download_binaries 必须拦截 '././/etc/passwd' 压缩包穿越，并兼容 SHA256SUMS 多层 './'。"""
        # 构造带 '././/etc/passwd' 的恶意 tar.gz（Python tarfile 允许写原始名称）
        evil_tar = self.tmp / "evil.tar.gz"
        with tarfile.open(evil_tar, "w:gz") as tf:
            for name, payload in [
                ("amneziawg-go", b"bin1"),
                ("awg", b"#!/bin/sh\necho 1.0\n"),
                ("awg-quick", b"bin3"),
                ("././/etc/passwd", b"pwned"),
            ]:
                p = self.tmp / f"src_{name.replace('/', '_')}"
                p.write_bytes(payload)
                tf.add(p, arcname=name)

        import hashlib

        digest = hashlib.sha256(evil_tar.read_bytes()).hexdigest()
        sums_file = self.tmp / "SHA256SUMS"
        sums_file.write_text(
            f"# 注释行\n{digest}  *././amneziawg-linux-amd64-awg3.tar.gz\n",
            encoding="utf-8",
        )

        evil_tar_posix = _to_bash_path(evil_tar)
        sums_posix = _to_bash_path(sums_file)
        script = self._source_preamble() + f"""
curl() {{
    local out="" prev="" a
    for a in "$@"; do
        if [[ "$prev" == "-o" ]]; then out="$a"; fi
        prev="$a"
    done
    if [[ "$*" == *SHA256SUMS* ]]; then
        cp "{sums_posix}" "$out"
    else
        cp "{evil_tar_posix}" "$out"
    fi
}}
download_binaries 3 amd64
"""
        res = _run_bash(script)
        self.assertNotEqual(res.returncode, 0, "含 '././/etc/passwd' 的压缩包必须被拦截")
        # 确认是通过了 SHA256 校验后在路径安全检查阶段被拒（证明 *././ SHA256SUMS 也被正确解析）
        combined = res.stdout + "\n" + res.stderr
        self.assertIn("SHA256 校验通过", combined, f"应先通过 *././ SHA256SUMS 校验，输出:\n{combined}")
        self.assertIn("不安全路径成员", combined, f"应在路径安全校验处拦截，输出:\n{combined}")

    def test_cmd_uninstall_refuses_unsafe_awg_dir_and_bad_old_port(self) -> None:
        """cmd_uninstall 必须拒绝把 '/' 或 '/etc' 作为 AWG_DIR 删除，且不向 revoke_firewall 传非法端口。"""
        script = self._source_preamble() + f"""
require_root() {{ return 0; }}
systemctl() {{
    if [[ "$1" == "is-enabled" ]]; then echo "not-found"; return 0; fi
    return 1
}}
meta_get() {{
    if [[ "$1" == "port" ]]; then echo "not-a-port;rm"; fi
}}
revoke_firewall() {{ echo "REVOKE_CALLED:$1" >&2; }}
rm() {{
    local a
    for a in "$@"; do
        if [[ "$a" == "/etc" || "$a" == "/" ]]; then
            echo "DANGEROUS_RM_CALLED:$a" >&2
            return 0
        fi
    done
    command rm "$@"
}}
AWG_SERVICE="{_to_bash_path(self.tmp / 'missing.service')}"
AWG_DIR="/etc"
cmd_uninstall --keep-binaries
"""
        res = _run_bash(script)
        self.assertNotEqual(res.returncode, 0, "AWG_DIR=/etc 时必须拒绝卸载删除")
        self.assertNotIn("DANGEROUS_RM_CALLED", res.stderr, "绝不得对 /etc 执行 rm -rf")
        self.assertNotIn("REVOKE_CALLED", res.stderr, "非法端口不得传给 revoke_firewall")


if __name__ == "__main__":
    unittest.main()
