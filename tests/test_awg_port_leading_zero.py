"""AmneziaWG 端口校验拒绝前导零：防八进制算术绕过 20000-40000 跳跃区间及 08/09 崩溃。"""
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _find_working_bash():
    candidates = [
        Path(r'C:\Program Files\Git\bin\bash.exe'),
        Path(r'C:\Program Files\Git\usr\bin\bash.exe'),
    ]
    which_bash = shutil.which('bash')
    if which_bash:
        candidates.append(Path(which_bash))
    for cand in candidates:
        if not cand.exists():
            continue
        try:
            probe = subprocess.run([str(cand), '-c', 'echo ok'],
                                   capture_output=True, text=True, encoding='utf-8',
                                   errors='replace', timeout=5)
            if probe.returncode == 0 and probe.stdout.strip() == 'ok':
                return str(cand)
        except OSError:
            continue
    return None


BASH = _find_working_bash()


@unittest.skipUnless(BASH, '需要可用的 bash 环境')
class AwgPortLeadingZeroTest(unittest.TestCase):
    def test_awgctl_validate_port_rejects_leading_zeros_cleanly(self):
        script = r"""
set -euo pipefail
AWGCTL="$1"
MAIN_LINE="$(grep -n '^main "\$@"' "$AWGCTL" | tail -1 | cut -d: -f1)"
source <(head -n $(( MAIN_LINE - 1 )) "$AWGCTL")
for bad in 0 00 020000 030000 08080 09000 050000; do
    out="$(validate_port "$bad" 2>&1 || echo "__REJECTED__")"
    [[ "$out" == *"__REJECTED__"* ]] || { echo "未被拒绝: $bad -> $out"; exit 1; }
    [[ "$out" != *"value too great for base"* ]] || { echo "算术崩溃: $bad -> $out"; exit 1; }
done
validate_port 50000 2>/dev/null
"""
        r = subprocess.run([BASH, '-c', script, '_', str(ROOT / 'awgctl.sh')],
                           capture_output=True, text=True, encoding='utf-8',
                           errors='replace', timeout=20)
        self.assertEqual(r.returncode, 0, (r.stdout or '') + (r.stderr or ''))

    def test_install_sh_amneziawg_prompt_uses_strict_port_validation(self):
        src = (ROOT / 'install.sh').read_text(encoding='utf-8')
        start = src.index('install_amneziawg() {')
        body = src[start:src.index('\n}\n', start)]
        self.assertIn('is_valid_port "$port"', body,
                      'install_amneziawg 手写端口校验未调用 is_valid_port，会放过前导零端口')


if __name__ == '__main__':
    unittest.main()
