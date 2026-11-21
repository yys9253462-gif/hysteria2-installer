"""回归测试：AWG 启停动作续期死线与 reset-failed 隔离，以及 BBR 应用的 modprobe 容错与配置刷盘。"""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')


class AwgStartStopDeadlineAndBbrFsyncTests(unittest.TestCase):
    def test_awg_start_stop_restart_extends_deadline_and_isolates_reset_failed(self):
        start = SRC.index("                if action in ('start', 'stop', 'restart'):")
        end = SRC.index('            except subprocess.TimeoutExpired:', start)
        body = SRC[start:end]
        self.assertIn('self._extend_deadline(', body,
                      'AWG start/stop/restart 等待 awg_operation_lock 并调用 30s systemctl，必须延长连接死线')
        self.assertLess(body.index('self._extend_deadline('),
                        body.index('with awg_operation_lock:'),
                        '必须在等待 awg_operation_lock 之前续期连接死线')
        reset_idx = body.index("'reset-failed'")
        self.assertIn('except', body[reset_idx:body.index("proc = subprocess.run(['systemctl', action")],
                      'reset-failed 超时或异常不应阻断后续 systemctl start/restart')

    def test_set_bbr_handles_missing_modprobe_and_write_bbr_file_creates_dir_and_fsyncs(self):
        bbr_start = SRC.index('        def _set_bbr_locked(self):')
        bbr_end = SRC.index('        def _h_post_reboot_server(', bbr_start)
        bbr_body = SRC[bbr_start:bbr_end]

        modprobe_idx = bbr_body.index("subprocess.run(['modprobe'")
        avail_idx = bbr_body.index("net.ipv4.tcp_available_congestion_control")
        self.assertIn('except', bbr_body[modprobe_idx:avail_idx],
                      '精简系统未安装 modprobe 时不应阻断内核已内建的 tcp_bbr 切换')

        w_start = SRC.index('                def _write_bbr_file(target_path, raw_bytes):')
        w_end = SRC.index('                def _rollback_bbr_files_and_runtime():', w_start)
        w_body = SRC[w_start:w_end]
        self.assertIn('target_path.parent.mkdir(parents=True, exist_ok=True)', w_body,
                      '_write_bbr_file 应确保父目录存在，防止 /etc/modules-load.d 等目录缺失抛 FileNotFoundError')
        self.assertIn('os.fsync(', w_body,
                      '_write_bbr_file 替换 sysctl/modules 配置前必须 flush + os.fsync 刷盘')


if __name__ == '__main__':
    unittest.main()
