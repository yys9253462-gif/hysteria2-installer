import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
AWGCTL = ROOT / 'awgctl.sh'


@unittest.skipUnless(BASH, 'requires Bash')
class AwgTransactionTests(unittest.TestCase):
    def run_shell(self, body):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, AWG_TEST_ROOT=tmp)
            source = AWGCTL.read_text(encoding='utf-8')
            source = source[:source.rfind('\nmain "$@"')]
            lib = Path(tmp) / 'awgctl-lib.sh'
            lib.write_text(source, encoding='utf-8')
            script = '''
set -euo pipefail
source "$AWGCTL_LIB"
ROOT="$AWG_TEST_ROOT"
AWG_DIR="$ROOT/etc/amnezia/amneziawg"
AWG_LINK=awg0
AWG_CONFIG="$AWG_DIR/awg0.conf"
AWG_META_FILE="$AWG_DIR/awg_meta.json"
AWG_PEERS_FILE="$AWG_DIR/awg_peers.json"
AWG_SERVICE="$ROOT/etc/systemd/system/amneziawg-server.service"
AWG_VERSION_FILE="$AWG_DIR/binaries.VERSION"
AWG_GO_BIN="$ROOT/usr/local/bin/amneziawg-go"
AWG_BIN="$ROOT/usr/local/bin/awg"
AWG_QUICK_BIN="$ROOT/usr/local/bin/awg-quick"
AWG_SERVICE_NAME=amneziawg-server
AWG_TRANSACTION_DIR=""
mkdir -p "$AWG_DIR" "$(dirname "$AWG_SERVICE")" "$(dirname "$AWG_BIN")"
'''+body
            env['AWGCTL_LIB'] = str(lib)
            return subprocess.run([BASH, '-c', script], env=env, text=True,
                                  capture_output=True, timeout=20,
                                  encoding='utf-8', errors='replace')

    def test_restore_recovers_all_files_and_enabled_active_state(self):
        result = self.run_shell(r'''
for path in "$AWG_META_FILE" "$AWG_CONFIG" "$AWG_PEERS_FILE" "$AWG_SERVICE" \
             "$AWG_VERSION_FILE" "$AWG_GO_BIN" "$AWG_BIN" "$AWG_QUICK_BIN"; do
    printf 'original:%s\n' "$(basename "$path")" > "$path"
done
chmod 750 "$AWG_DIR"
STATE_ACTIVE=active
STATE_ENABLED=enabled
systemctl() {
    case "$*" in
        'is-active amneziawg-server') printf '%s' "$STATE_ACTIVE" ;;
        'is-enabled amneziawg-server') printf '%s' "$STATE_ENABLED" ;;
        'enable amneziawg-server') STATE_ENABLED=enabled ;;
        'disable amneziawg-server') STATE_ENABLED=disabled ;;
        'start amneziawg-server'|'restart amneziawg-server') STATE_ACTIVE=active ;;
        'stop amneziawg-server') STATE_ACTIVE=inactive ;;
        *) return 0 ;;
    esac
}
awg_transaction_snapshot
for path in "$AWG_META_FILE" "$AWG_CONFIG" "$AWG_PEERS_FILE" "$AWG_SERVICE" \
             "$AWG_VERSION_FILE" "$AWG_GO_BIN" "$AWG_BIN" "$AWG_QUICK_BIN"; do
    printf 'partial\n' > "$path"
done
chmod 700 "$AWG_DIR"
STATE_ACTIVE=inactive
STATE_ENABLED=disabled
awg_transaction_restore
[[ "$STATE_ACTIVE" == active && "$STATE_ENABLED" == enabled ]]
[[ "$(stat -c %a "$AWG_DIR")" == 755 ]]
for path in "$AWG_META_FILE" "$AWG_CONFIG" "$AWG_PEERS_FILE" "$AWG_SERVICE" \
             "$AWG_VERSION_FILE" "$AWG_GO_BIN" "$AWG_BIN" "$AWG_QUICK_BIN"; do
    [[ "$(cat "$path")" == "original:$(basename "$path")" ]]
done
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_fresh_install_rollback_removes_new_enablement_and_active_state(self):
        result = self.run_shell(r'''
STATE_ACTIVE=inactive
STATE_ENABLED=not-found
systemctl() {
    case "$*" in
        'is-active amneziawg-server') printf '%s' "$STATE_ACTIVE" ;;
        'is-enabled amneziawg-server') printf '%s' "$STATE_ENABLED" ;;
        'enable amneziawg-server') STATE_ENABLED=enabled ;;
        'disable amneziawg-server') STATE_ENABLED=disabled ;;
        'start amneziawg-server'|'restart amneziawg-server') STATE_ACTIVE=active ;;
        'stop amneziawg-server') STATE_ACTIVE=inactive ;;
        'daemon-reload') : ;;
        *) return 0 ;;
    esac
}
awg_transaction_snapshot
printf 'new unit\n' > "$AWG_SERVICE"
systemctl daemon-reload
systemctl enable "$AWG_SERVICE_NAME"
systemctl start "$AWG_SERVICE_NAME"
awg_transaction_restore
[[ "$STATE_ACTIVE" == inactive && "$STATE_ENABLED" == disabled ]]
[[ ! -e "$AWG_SERVICE" ]]
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_snapshot_copy_failure_cleans_private_snapshot_directory(self):
        result = self.run_shell(r'''
AWG_META_FILE="$AWG_DIR/awg_meta.json"
AWG_CONFIG="$AWG_DIR/awg0.conf"
AWG_META_FILE="$ROOT/meta.json"
AWG_CONFIG="$ROOT/config.json"
AWG_PEERS_FILE="$ROOT/peers.json"
AWG_SERVICE="$ROOT/unit.service"
AWG_VERSION_FILE="$ROOT/version"
AWG_GO_BIN="$ROOT/go"
AWG_BIN="$ROOT/awg"
AWG_QUICK_BIN="$ROOT/quick"
printf x > "$AWG_META_FILE"
printf x > "$AWG_CONFIG"
cp() {
    case "$*" in
        *"$AWG_CONFIG"*) return 1 ;;
        *) command cp "$@" ;;
    esac
}
if awg_transaction_snapshot; then exit 1; fi
[[ -z "$AWG_TRANSACTION_DIR" ]]
[[ ! -e "$ROOT"/hy2-awg-transaction.* ]]
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_transaction_exit_trap_restores_files_after_failure(self):
        result = self.run_shell(r'''
STATE_ACTIVE=active
STATE_ENABLED=enabled
systemctl() {
    case "$*" in
        'is-active amneziawg-server') printf '%s' "$STATE_ACTIVE" ;;
        'is-enabled amneziawg-server') printf '%s' "$STATE_ENABLED" ;;
        'enable amneziawg-server') STATE_ENABLED=enabled ;;
        'disable amneziawg-server') STATE_ENABLED=disabled ;;
        'start amneziawg-server'|'restart amneziawg-server') STATE_ACTIVE=active ;;
        'stop amneziawg-server') STATE_ACTIVE=inactive ;;
        *) return 0 ;;
    esac
}
printf old > "$AWG_CONFIG"
awg_transaction_snapshot
cat > "$ROOT/verify-after-exit.sh" <<'VERIFY'
[[ "$(cat "$AWG_CONFIG")" == old ]]
[[ "$STATE_ACTIVE" == active && "$STATE_ENABLED" == enabled ]]
[[ -z "$AWG_TRANSACTION_DIR" ]]
VERIFY
trap 'awg_transaction_on_exit; bash "$ROOT/verify-after-exit.sh"' EXIT
printf partial > "$AWG_CONFIG"
STATE_ACTIVE=inactive
STATE_ENABLED=disabled
exit 1
''')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
