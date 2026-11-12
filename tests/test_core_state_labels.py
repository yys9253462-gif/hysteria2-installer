"""核心管理卡片的状态文字不夹英文原词（2026-11-13 修）。

后端 systemctl 没回话时给 unknown，正在停止 / 重载时是 deactivating / reloading；旧卡片显示
「已安装 · ● unknown」。在 node 里执行真实的 renderCore。
"""
import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402

NODE = shutil.which('node')


def core_card_renderer(src):
    start = src.index('const CORE_STATE_TEXT = {')
    return src[start:src.index('\n}\n', src.index('function renderCore(')) + 3]


@unittest.skipUnless(NODE, 'requires node')
class CoreStateLabelTest(unittest.TestCase):
    def pills(self, states):
        js = r"""
const mk = tag => ({tag, className: '', textContent: '', style: {}, children: [], type: '',
  appendChild(c) { this.children.push(c); return c; }, addEventListener() {}});
const document = {createElement: mk, createTextNode: t => ({textContent: String(t)})};
%s
console.log(JSON.stringify(%s.map(state => renderCore({name: 'Xray', installed: true, state,
  version: '26.3.27', service: 'xray', used_by: [], installable: false}).children[0].children[1].textContent)));
""" % (core_card_renderer(portal.SCRIPT), json.dumps(states))
        run = subprocess.run([NODE, '-e', js], capture_output=True, text=True, encoding='utf-8', timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout)

    def test_known_systemd_states_have_readable_labels(self):
        self.assertEqual(self.pills(['unknown', 'deactivating', 'reloading', 'active']),
                         ['已安装 · ? 状态未知', '已安装 · ● 停止中', '已安装 · ● 重载中', '已安装 · ● 运行中'])

    def test_unexpected_states_are_still_shown(self):
        self.assertEqual(self.pills(['maintenance']), ['已安装 · ● maintenance'])


if __name__ == '__main__':
    unittest.main()
