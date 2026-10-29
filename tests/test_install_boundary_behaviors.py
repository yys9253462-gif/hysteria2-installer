"""Offline behavior regressions for installer IP, certificate and hopping boundaries.

Only extracted shell functions run. Network, service and firewall operations are
stubbed; filesystem fixtures live entirely inside TemporaryDirectory.
"""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


INSTALL = Path(__file__).resolve().parent.parent / "install.sh"


def find_bash():
    for candidate in (
        shutil.which("bash"),
        r"C:\Program Files\Git\bin\bash.exe",
        "/bin/bash",
    ):
        if candidate and Path(candidate).is_file():
            return candidate
    return None


BASH = find_bash()
LOG_STUBS = """
log_err(){ printf 'ERR: %s\\n' "$*" >&2; }
log_warn(){ printf 'WARN: %s\\n' "$*"; }
log_info(){ printf 'INFO: %s\\n' "$*"; }
log_step(){ :; }
"""


def extract_function(name):
    # These functions have indented bodies and a top-level closing brace.
    source = INSTALL.read_text(encoding="utf-8")
    match = re.search(r"^" + re.escape(name) + r"\(\) \{\n.*?^\}", source, re.M | re.S)
    if not match:
        raise AssertionError("Missing shell function: " + name)
    return match.group(0) + "\n"


def run_shell(script):
    with tempfile.TemporaryDirectory(prefix="hy2-boundary-") as directory:
        path = Path(directory) / "probe.sh"
        path.write_text("set -eo pipefail\n" + LOG_STUBS + script,
                        encoding="utf-8", newline="\n")
        env = os.environ.copy()
        # Git Bash can create real MSYS symlinks without Windows symlink privilege.
        if os.name == "nt":
            env["MSYS"] = env.get("MSYS", "") + " winsymlinks:lnk"
        return subprocess.run(
            [BASH, str(path)], cwd=directory, env=env, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=30,
        )


@unittest.skipUnless(BASH, "requires Bash")
class TestPublicIPv4Boundaries(unittest.TestCase):
    def check_addresses(self, cases):
        rows = "\n".join("|".join(row) for row in cases)
        result = run_shell(
            "curl(){ printf '%s' \"$MOCK_IP\"; }\n"
            + extract_function("get_public_ip")
            + """
while IFS='|' read -r MOCK_IP expected_status expected_ip; do
    status=0
    get_public_ip || status=$?
    if [[ "$status" != "$expected_status" || "$PUBLIC_IP" != "$expected_ip" ]]; then
        printf 'input=%s status=%s ip=%s expected_status=%s expected_ip=%s\n' \
            "$MOCK_IP" "$status" "$PUBLIC_IP" "$expected_status" "$expected_ip" >&2
        exit 1
    fi
done <<'CASES'
""" + rows + "\nCASES\n"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("value too great for base", result.stderr)

    def test_public_addresses_around_reserved_cidrs(self):
        addresses = (
            "100.63.255.255", "100.128.0.0", "100.128.1.1", "100.129.255.255",
            "198.17.255.255", "198.20.0.0", "198.20.1.1", "198.29.255.255",
            "198.30.0.1", "172.15.255.255", "172.32.0.1", "8.8.8.8",
        )
        self.check_addresses([(ip, "0", ip) for ip in addresses])

    def test_reserved_cidr_endpoints_remain_blocked(self):
        addresses = (
            "100.64.0.0", "100.127.255.255", "198.18.0.0", "198.19.255.255",
            "172.16.0.0", "172.31.255.255", "127.0.0.1", "10.0.0.1",
            "192.168.0.1", "169.254.1.1", "0.0.0.0",
        )
        self.check_addresses([(ip, "1", ip) for ip in addresses])

    def test_leading_zero_octets_are_decimal_and_normalized(self):
        self.check_addresses([
            ("008.008.008.008", "0", "8.8.8.8"),
            ("100.128.001.009", "0", "100.128.1.9"),
            ("010.000.000.001", "1", "10.0.0.1"),
            ("100.064.000.001", "1", "100.64.0.1"),
            ("198.019.000.001", "1", "198.19.0.1"),
        ])

    def test_out_of_range_octets_fail(self):
        self.check_addresses([
            ("299.1.1.1", "1", "299.1.1.1"),
            ("8.8.8.256", "1", "8.8.8.256"),
        ])


@unittest.skipUnless(BASH, "requires Bash")
class TestLocalCertificateDiscovery(unittest.TestCase):
    def probe_certificate(self, fixture, expected_status, expected_cert=""):
        result = run_shell(
            """
mkdir -p live/example archive/example acme home
SERVER_NAME=hy2.example.com
# Redirect only the production search roots, preserving find's actual predicates.
find(){
    local arg args=()
    for arg in "$@"; do
        case "$arg" in
            /etc/letsencrypt/live) arg="$PWD/live" ;;
            /root/.acme.sh) arg="$PWD/acme" ;;
            /home) arg="$PWD/home" ;;
        esac
        args+=("$arg")
    done
    command find "${args[@]}"
}
""" + fixture + "\n"
            + extract_function("select_local_certificate")
            + f"expected_status={expected_status}\n"
            + f"expected_cert='{expected_cert}'\n"
            + """
status=0
select_local_certificate || status=$?
[[ "$status" == "$expected_status" ]]
if [[ "$status" == 0 ]]; then
    [[ "$CERT_FILE" == "$PWD/$expected_cert" ]]
    [[ "$KEY_FILE" == "$PWD/live/example/privkey.pem" ]]
    [[ "$CERT_TYPE" == custom && "$IS_INSECURE" == false ]]
fi
"""
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_certbot_live_symlinks_are_selected_without_resolving_archive_paths(self):
        self.probe_certificate("""
printf chain > archive/example/fullchain1.pem
printf key > archive/example/privkey1.pem
ln -s ../../archive/example/fullchain1.pem live/example/fullchain.pem
ln -s ../../archive/example/privkey1.pem live/example/privkey.pem
[[ -L live/example/fullchain.pem && -L live/example/privkey.pem ]]
""", 0, "live/example/fullchain.pem")

    def test_regular_fullchain_and_key_remain_supported(self):
        self.probe_certificate("""
printf chain > live/example/fullchain.pem
printf key > live/example/privkey.pem
""", 0, "live/example/fullchain.pem")

    def test_broken_symlink_is_not_selected(self):
        self.probe_certificate("""
ln -s ../../archive/example/missing.pem live/example/fullchain.pem
printf key > live/example/privkey.pem
""", 1)

    def test_certificate_without_private_key_is_not_selected(self):
        self.probe_certificate("printf chain > live/example/fullchain.pem", 1)


@unittest.skipUnless(BASH, "requires Bash")
class TestExistingWebCertificate(unittest.TestCase):
    def test_existing_pair_is_used_without_requesting_another_certificate(self):
        result = run_shell(
            """
HY2_DOMAIN=hy2.example.com
HY2_EMAIL=ops@example.com
ACRE_PORT_BLOCKER='TCP 80/443'
CERT_TYPE=acme
CERT_FILE=stale-cert
KEY_FILE=stale-key
IS_INSECURE=true
detect_webserver_squatting(){ return 0; }
find_cert_in_webserver(){
    [[ "$1" == "$HY2_DOMAIN" ]] || return 1
    printf '/fixture/fullchain.pem|/fixture/privkey.pem\n'
}
setup_cert_via_dns_api(){ printf 'UNEXPECTED_DNS\n' >&2; return 2; }
setup_cert_via_existing_caddy(){ printf 'UNEXPECTED_CADDY\n' >&2; return 1; }
setup_cert_via_nginx(){ printf 'UNEXPECTED_NGINX\n' >&2; return 1; }
generate_self_signed_cert(){ printf 'UNEXPECTED_SELF_SIGNED\n' >&2; return 1; }
"""
            + extract_function("setup_acme_certificate")
            + """
setup_acme_certificate
[[ "$CERT_TYPE" == custom && "$IS_INSECURE" == false ]]
[[ "$CERT_FILE" == /fixture/fullchain.pem && "$KEY_FILE" == /fixture/privkey.pem ]]
[[ "$SERVER_NAME" == "$HY2_DOMAIN" ]]
"""
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("UNEXPECTED_", result.stderr)


@unittest.skipUnless(BASH, "requires Bash")
class TestPortHoppingPublication(unittest.TestCase):
    def probe_hopping(self, available):
        # Exercise the real no-iptables return path. All mutations are stubbed.
        # The available path uses a recorder stub instead of changing firewall rules.
        setup = extract_function("setup_iptables_port_hopping") if not available else """
setup_iptables_port_hopping(){ printf '%s|%s|%s' "$@" > hopping-call; }
"""
        result = run_shell(
            """
HY2_DIR="$PWD"
HY2_META_FILE="$PWD/missing-meta.json"
HY2_PORT=14617
HY2_PASSWORD=fixture-password
HY2_NODE_MODE=2
HOP_PORT_RANGE=stale-range
HOP_START=123
HOP_END=456
is_valid_port(){ [[ "$1" =~ ^[0-9]+$ ]] && (( $1 > 0 && $1 <= 65535 )); }
jq(){ return 0; }
openssl(){ printf fixture-secret; }
systemctl(){ return 0; }
rm(){ printf 'rm:%s\n' "$*"; }
clear_all_hopping_rules(){ :; }
iptables(){ printf 'UNEXPECTED_FIREWALL\n' >&2; return 99; }
"""
            + ("command(){ if [[ \"$1\" == -v && \"$2\" == iptables ]]; then return 1; fi; builtin command \"$@\"; }\n" if not available else "")
            + setup + extract_function("setup_ports_and_obfs")
            + "setup_ports_and_obfs\n"
            + ("""
[[ "$HOP_PORT_RANGE" == 20000-40000 && "$HOP_START" == 20000 && "$HOP_END" == 40000 ]]
[[ "$(<hopping-call)" == '14617|20000|40000' ]]
""" if available else """
[[ -z "$HOP_PORT_RANGE" && -z "$HOP_START" && -z "$HOP_END" ]]
[[ "$LISTEN_PORT" == 14617 && "$OBFS_PASSWORD" == fixture-secret ]]
""")
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("UNEXPECTED_FIREWALL", result.stderr)
        if not available:
            self.assertNotIn("端口跳跃已默认自动启用", result.stdout)

    def test_missing_iptables_clears_stale_range_and_keeps_direct_port(self):
        self.probe_hopping(False)

    def test_available_iptables_publishes_configured_range(self):
        self.probe_hopping(True)


@unittest.skipUnless(BASH, "requires Bash")
class TestHoppingSecurityGroupHint(unittest.TestCase):
    def probe_hint(self, hopping_range, saved_range=""):
        result = run_shell(
            """
HY2_DIR="$PWD"
HY2_META_FILE="$PWD/missing-meta.json"
HOP_START=''
HOP_END=''
LISTEN_PORT=14617
HY2_SUB_PORT=18080
printf '{}' > portal-access.json
jq(){
    case "$2" in
        .url) printf 'https://example.com:18080/fixture/' ;;
        .username) printf fixture-user ;;
        .password) printf fixture-password ;;
        '.hop_port_range // empty') printf '%s' "$SAVED_RANGE" ;;
        *) return 0 ;;
    esac
}
"""
            + f"SAVED_RANGE='{saved_range}'\n"
            + (f"HOP_PORT_RANGE='{hopping_range}'\n" if hopping_range is not None
               else "unset HOP_PORT_RANGE\n")
            + extract_function("show_client_configs")
            + "show_client_configs\n"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def test_disabled_hopping_has_no_security_group_range_hint(self):
        self.assertNotIn("UDP 20000-40000", self.probe_hint("", "20000-40000"))

    def test_enabled_hopping_displays_actual_range(self):
        self.assertIn("UDP 21000-22000", self.probe_hint("21000-22000"))

    def test_info_reads_actual_range_from_saved_metadata(self):
        self.assertIn("UDP 21000-22000", self.probe_hint(None, "21000-22000"))

    def test_info_with_no_saved_range_has_no_hopping_hint(self):
        self.assertNotIn("UDP 20000-40000", self.probe_hint(None))


if __name__ == "__main__":
    unittest.main()
