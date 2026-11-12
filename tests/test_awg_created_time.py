"""AWG 客户端「创建时间」按浏览器本地时间显示（2026-11-13 修）。

awgctl 存的是 UTC（2026-11-12T15:04:05Z），旧实现原样显示，国内看到的钟点差 8 小时。
在 node 里执行真实的 renderAwgPeers，时区固定为 Asia/Shanghai。
"""
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


def top_level_function(src, marker):
    start = src.index(marker)
    return src[start:src.index('\n}\n', start) + 3]


def peer_table_renderer(src):
    """renderAwgPeers 连同它前面的时间格式化函数（有的话）。"""
    render = src.index('function renderAwgPeers(')
    helper = src.find('function fmtAwgCreated(')
    start = helper if 0 <= helper < render else render
    return src[start:src.index('\n}\n', render) + 3]


@unittest.skipUnless(shutil.which('node'), 'requires node')
class AwgCreatedTimeTest(unittest.TestCase):
    def render(self, peers):
        s = portal.SCRIPT
        js = '\n'.join([
            top_level_function(s, 'function obEsc('),
            'const awgPeerTbody = { innerHTML: "", querySelectorAll: () => [] };',
            peer_table_renderer(s),
            'renderAwgPeers(%s);' % json.dumps(peers),
            # 第三列：创建时间（悬停提示, 显示文字）
            'const rows = awgPeerTbody.innerHTML.split("</tr>").filter(r => r.includes("<td"));',
            'console.log(JSON.stringify(rows.map(r => {',
            '  const cell = r.split("</td>")[2];',
            '  const title = /title="([^"]*)"/.exec(cell);',
            '  return [title ? title[1] : null, cell.slice(cell.lastIndexOf(">") + 1)];',
            '})));'])
        run = subprocess.run(['node', '-e', js], capture_output=True, text=True, encoding='utf-8',
                             timeout=20, env=dict(os.environ, TZ='Asia/Shanghai'))
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout)

    def test_created_time_is_local_with_the_original_in_the_tooltip(self):
        peers = [{'name': 'phone', 'address': '10.66.0.2', 'created_at': '2026-11-12T15:04:05Z'},
                 {'name': 'odd', 'address': '10.66.0.3', 'created_at': 'garbage'},
                 {'name': 'legacy', 'address': '10.66.0.4'}]
        self.assertEqual(self.render(peers), [['2026-11-12T15:04:05Z', '2026-11-12 23:04'],
                                              ['garbage', 'garbage'],
                                              ['', '-']])


if __name__ == '__main__':
    unittest.main()
