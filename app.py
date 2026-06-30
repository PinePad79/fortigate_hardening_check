#!/usr/bin/env python3
"""
FortiGate FortiOS Hardening Checker

Local Flask app that connects to a live FortiGate using read-only REST API GET calls,
then renders an HTML compliance report based on the selected Fortinet FortiOS
hardening baseline: 8.0, 7.6, or 7.4.

Tested design target: macOS/Linux with Python 3.10+.
"""
from __future__ import annotations

import datetime as dt
import html
import ipaddress
import json
import re
import traceback
from dataclasses import dataclass, asdict
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import requests
import urllib3
from flask import Flask, Response, render_template_string, request

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

APP_VERSION = "0.2.0"
DEFAULT_TIMEOUT = 10

FIRMWARE_BASELINES: Dict[str, Dict[str, Any]] = {
    "8.0": {
        "label": "FortiOS 8.0",
        "doc_url": "https://docs.fortinet.com/document/fortigate/8.0.0/best-practices/555436/hardening",
        "version_prefixes": ("v8.0", "8.0"),
    },
    "7.6": {
        "label": "FortiOS 7.6",
        "doc_url": "https://docs.fortinet.com/document/fortigate/7.6.0/best-practices/555436",
        "version_prefixes": ("v7.6", "7.6"),
    },
    "7.4": {
        "label": "FortiOS 7.4",
        "doc_url": "https://docs.fortinet.com/document/fortigate/7.4.0/best-practices/555436",
        "version_prefixes": ("v7.4", "7.4"),
    },
}
DEFAULT_BASELINE = "8.0"

app = Flask(__name__)


# FortiOS CMDB/Monitor endpoints used by the scanner.
# Each endpoint is best-effort: if the read-only API profile lacks permission or the exact endpoint
# varies by build/model, the related checks become REVIEW instead of breaking the scan.
ENDPOINTS: Dict[str, List[str]] = {
    "system_status": ["/api/v2/monitor/system/status"],
    "system_global": ["/api/v2/cmdb/system/global"],
    "system_interface": ["/api/v2/cmdb/system/interface"],
    "system_admin": ["/api/v2/cmdb/system/admin"],
    "system_api_user": ["/api/v2/cmdb/system/api-user"],
    "system_ntp": ["/api/v2/cmdb/system/ntp"],
    "system_autoinstall": ["/api/v2/cmdb/system/auto-install"],
    "system_snmp_sysinfo": ["/api/v2/cmdb/system.snmp/sysinfo", "/api/v2/cmdb/system/snmp/sysinfo"],
    "system_snmp_community": ["/api/v2/cmdb/system.snmp/community", "/api/v2/cmdb/system/snmp/community"],
    "system_snmp_user": ["/api/v2/cmdb/system.snmp/user", "/api/v2/cmdb/system/snmp/user"],
    "log_fortianalyzer": ["/api/v2/cmdb/log.fortianalyzer/setting", "/api/v2/cmdb/log/fortianalyzer/setting"],
    "log_syslogd": ["/api/v2/cmdb/log.syslogd/setting", "/api/v2/cmdb/log/syslogd/setting"],
    "log_syslogd2": ["/api/v2/cmdb/log.syslogd2/setting", "/api/v2/cmdb/log/syslogd2/setting"],
    "log_disk": ["/api/v2/cmdb/log.disk/setting", "/api/v2/cmdb/log/disk/setting"],
    "firewall_local_in_policy": ["/api/v2/cmdb/firewall/local-in-policy"],
    "firewall_dos_policy": ["/api/v2/cmdb/firewall/DoS-policy", "/api/v2/cmdb/firewall/dos-policy"],
    "firewall_policy": ["/api/v2/cmdb/firewall/policy"],
    "user_ldap": ["/api/v2/cmdb/user/ldap"],
    "user_radius": ["/api/v2/cmdb/user/radius"],
    "router_ospf": ["/api/v2/cmdb/router/ospf"],
    "vpn_ssl_settings": ["/api/v2/cmdb/vpn.ssl/settings", "/api/v2/cmdb/vpn/ssl/settings"],
    "vpn_ipsec_phase1_interface": ["/api/v2/cmdb/vpn.ipsec/phase1-interface", "/api/v2/cmdb/vpn/ipsec/phase1-interface"],
    "license_status": ["/api/v2/monitor/license/status", "/api/v2/monitor/system/license/status"],
}


@dataclass
class EndpointResult:
    key: str
    endpoint: Optional[str]
    ok: bool
    http_status: Optional[int]
    error: Optional[str]
    data: Any


@dataclass
class CheckResult:
    category: str
    control: str
    status: str  # PASS, FAIL, REVIEW, ERROR
    recommendation: str
    evidence: str
    severity: str = "Medium"
    control_id: str = ""

    @property
    def css_class(self) -> str:
        return self.status.lower()


class FortiGateClient:
    def __init__(self, host: str, api_token: str, port: int = 443, vdom: str = "root", verify_tls: bool = False, timeout: int = DEFAULT_TIMEOUT):
        host = host.strip()
        if not host:
            raise ValueError("FortiGate IP/FQDN is required")
        if not api_token.strip():
            raise ValueError("REST API token is required")
        if not host.startswith("http://") and not host.startswith("https://"):
            host = f"https://{host}"
        parsed = urlparse(host)
        scheme = parsed.scheme or "https"
        hostname = parsed.hostname or host.replace("https://", "").replace("http://", "")
        self.base_url = f"{scheme}://{hostname}:{int(port)}"
        self.vdom = vdom.strip() or "root"
        self.verify_tls = bool(verify_tls)
        self.timeout = int(timeout or DEFAULT_TIMEOUT)
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_token.strip()}",
            "Accept": "application/json",
            "User-Agent": f"fortigate-hardening-checker/{APP_VERSION}",
        })

    def get(self, endpoint: str) -> Tuple[bool, Optional[int], Any, Optional[str]]:
        url = f"{self.base_url}{endpoint}"
        params = {"vdom": self.vdom} if self.vdom else None
        try:
            response = self.session.get(url, params=params, timeout=self.timeout, verify=self.verify_tls)
            status = response.status_code
            try:
                data = response.json()
            except Exception:
                data = {"raw": response.text[:500]}
            if 200 <= status < 300:
                api_status = str(data.get("status", "success")).lower() if isinstance(data, dict) else "success"
                if api_status in {"error", "fail", "failed"}:
                    return False, status, data, data.get("message", "FortiGate API returned an error") if isinstance(data, dict) else "API returned an error"
                return True, status, data, None
            return False, status, data, f"HTTP {status}"
        except requests.exceptions.SSLError as exc:
            return False, None, None, f"TLS error: {exc}"
        except requests.exceptions.ConnectionError as exc:
            return False, None, None, f"Connection error: {exc}"
        except requests.exceptions.Timeout:
            return False, None, None, "Request timed out"
        except Exception as exc:
            return False, None, None, f"Unexpected error: {exc}"

    def fetch_all(self) -> Dict[str, EndpointResult]:
        results: Dict[str, EndpointResult] = {}
        for key, candidates in ENDPOINTS.items():
            last: Optional[EndpointResult] = None
            for endpoint in candidates:
                ok, http_status, data, error = self.get(endpoint)
                current = EndpointResult(key=key, endpoint=endpoint, ok=ok, http_status=http_status, error=error, data=data)
                last = current
                if ok:
                    results[key] = current
                    break
            if key not in results:
                results[key] = last or EndpointResult(key=key, endpoint=None, ok=False, http_status=None, error="No endpoint candidate", data=None)
        return results


# -------------------------
# Utility helpers
# -------------------------

def api_results(endpoint: EndpointResult) -> Any:
    if not endpoint or not endpoint.ok or endpoint.data is None:
        return None
    if isinstance(endpoint.data, dict) and "results" in endpoint.data:
        return endpoint.data.get("results")
    return endpoint.data


def as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        # Some singleton tables are returned as dicts.
        return [value]
    return [value]


def first_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return value[0]
    return {}


def get_any(d: Dict[str, Any], keys: Iterable[str], default: Any = None) -> Any:
    if not isinstance(d, dict):
        return default
    for key in keys:
        if key in d:
            return d[key]
    return default


def norm(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "enable" if value else "disable"
    return str(value).strip().lower()


def is_enabled(value: Any) -> bool:
    return norm(value) in {"enable", "enabled", "true", "yes", "1", "on"}


def is_disabled(value: Any) -> bool:
    return norm(value) in {"disable", "disabled", "false", "no", "0", "off", ""}


def to_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    try:
        return int(value)
    except Exception:
        return default


def mkey_name(obj: Dict[str, Any]) -> str:
    return str(get_any(obj, ["name", "q_origin_key", "mkey", "policyid", "id", "interface"], "unknown"))


def short_json(value: Any, max_len: int = 480) -> str:
    try:
        s = json.dumps(value, indent=2, sort_keys=True, default=str)
    except Exception:
        s = str(value)
    if len(s) > max_len:
        return s[:max_len] + "..."
    return s


def missing(key: str, endpoints: Dict[str, EndpointResult]) -> CheckResult:
    ep = endpoints.get(key)
    reason = ep.error if ep else "Endpoint not fetched"
    return CheckResult(
        category="Scanner",
        control=f"Endpoint available: {key}",
        status="REVIEW",
        recommendation="Grant read-only API access for this endpoint or verify whether this endpoint exists on the target FortiOS build/model.",
        evidence=f"{ep.endpoint if ep else key}: {reason}",
        severity="Info",
    )


def result(category: str, control: str, passed: Optional[bool], recommendation: str, evidence: str, severity: str = "Medium", control_id: str = "") -> CheckResult:
    if passed is None:
        status = "REVIEW"
    else:
        status = "PASS" if passed else "FAIL"
    return CheckResult(category, control, status, recommendation, evidence, severity, control_id)


def allowaccess_set(interface_obj: Dict[str, Any]) -> set:
    raw = get_any(interface_obj, ["allowaccess", "allow-access"], "")
    if isinstance(raw, list):
        return {str(x).lower() for x in raw}
    return {x.strip().lower() for x in str(raw).replace(",", " ").split() if x.strip()}


def has_admin_access(interface_obj: Dict[str, Any]) -> bool:
    return bool(allowaccess_set(interface_obj) & {"http", "https", "ssh", "telnet"})


def looks_wan(interface_obj: Dict[str, Any]) -> bool:
    name = norm(get_any(interface_obj, ["name", "q_origin_key", "alias"], ""))
    role = norm(get_any(interface_obj, ["role"], ""))
    return role == "wan" or "wan" in name or name in {"port1"} and role == "wan"


def trusthosts(obj: Dict[str, Any]) -> List[str]:
    hosts: List[str] = []
    for k, v in obj.items():
        lk = str(k).lower()
        if "trusthost" in lk or "trust-host" in lk:
            if isinstance(v, dict):
                # FortiOS sometimes returns nested objects.
                hosts.extend([str(x) for x in v.values()])
            elif isinstance(v, list):
                hosts.extend([short_json(x, 120) for x in v])
            else:
                hosts.append(str(v))
    nested = obj.get("trusthost") or obj.get("trusthosts") or obj.get("trust-host")
    if isinstance(nested, list):
        for entry in nested:
            if isinstance(entry, dict):
                hosts.extend([str(v) for k, v in entry.items() if "trusthost" in str(k).lower() or "ipv4" in str(k).lower() or "ipv6" in str(k).lower()])
            else:
                hosts.append(str(entry))
    return [h for h in hosts if h and h.lower() not in {"none", "null"}]


def is_any_trusthost(value: str) -> bool:
    v = value.strip().lower()
    if not v:
        return True
    any_patterns = [
        "0.0.0.0 0.0.0.0",
        "0.0.0.0/0",
        "::/0",
        "0::0/0",
    ]
    return any(p in v for p in any_patterns)


def has_restricted_trusthost(obj: Dict[str, Any]) -> bool:
    hosts = trusthosts(obj)
    if not hosts:
        return False
    return any(not is_any_trusthost(h) for h in hosts)


def policy_field_names(policies: List[Dict[str, Any]], field: str) -> List[str]:
    values: List[str] = []
    for policy in policies:
        raw = policy.get(field)
        if isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, dict):
                    values.append(str(entry.get("name") or entry.get("q_origin_key") or entry))
                else:
                    values.append(str(entry))
        elif isinstance(raw, dict):
            values.append(str(raw.get("name") or raw.get("q_origin_key") or raw))
        elif raw is not None:
            values.append(str(raw))
    return values


def endpoint_ok(key: str, endpoints: Dict[str, EndpointResult]) -> bool:
    return bool(endpoints.get(key) and endpoints[key].ok)


def get_baseline(firmware_family: str) -> Dict[str, Any]:
    selected = str(firmware_family or DEFAULT_BASELINE).strip()
    return FIRMWARE_BASELINES.get(selected, FIRMWARE_BASELINES[DEFAULT_BASELINE])


# -------------------------
# Check engine
# -------------------------

def run_checks(endpoints: Dict[str, EndpointResult], firmware_family: str = DEFAULT_BASELINE) -> List[CheckResult]:
    checks: List[CheckResult] = []
    baseline = get_baseline(firmware_family)

    # System status / version
    if endpoint_ok("system_status", endpoints):
        status = first_dict(api_results(endpoints["system_status"]))
        version = str(get_any(status, ["version", "Version"], ""))
        checks.append(result(
            "Platform",
            f"FortiGate is running {baseline['label']}.x",
            any(version.startswith(prefix) for prefix in baseline["version_prefixes"]),
            f"Run {baseline['label']}.x for this selected baseline, or select the matching control set for the installed train.",
            f"Selected baseline: {baseline['label']}; detected version: {version or 'unknown'}; build: {get_any(status, ['build', 'Build'], 'unknown')}; baseline source: {baseline['doc_url']}",
            "High",
            "FG-HARD-001",
        ))
    else:
        checks.append(missing("system_status", endpoints))

    # Global crypto and admin settings
    if endpoint_ok("system_global", endpoints):
        g = first_dict(api_results(endpoints["system_global"]))
        strong_crypto = get_any(g, ["strong-crypto", "strong_crypto"])
        static_key = get_any(g, ["ssl-static-key-ciphers", "ssl_static_key_ciphers"])
        dh_params = get_any(g, ["dh-params", "dh_params"])
        admin_sport = to_int(get_any(g, ["admin-sport", "admin_sport"]), None)
        admin_ssh_port = to_int(get_any(g, ["admin-ssh-port", "admin_ssh_port"]), None)
        admin_timeout = to_int(get_any(g, ["admintimeout", "admin-timeout", "admin_timeout"]), None)
        redirect = get_any(g, ["admin-https-redirect", "admin_https_redirect", "admin-http-redirect"])
        admin_host = get_any(g, ["admin-host", "admin_host"])
        private_data = get_any(g, ["private-data-encryption", "private_data_encryption"])
        cert = get_any(g, ["admin-server-cert", "admin-server-cert-name", "admin_cert", "admin-https-ssl-versions"])

        checks.extend([
            result("Cryptography", "Strong crypto is enabled", is_enabled(strong_crypto), "Enable strong crypto in system global settings.", f"strong-crypto={strong_crypto}", "High", "FG-CRYPTO-001"),
            result("Cryptography", "Static key SSL ciphers are disabled", is_disabled(static_key), "Disable ssl-static-key-ciphers.", f"ssl-static-key-ciphers={static_key}", "High", "FG-CRYPTO-002"),
            result("Cryptography", "Diffie-Hellman parameters are set to 8192", dh_params in [8192, "8192"], "Set dh-params to 8192 where supported.", f"dh-params={dh_params}", "Medium", "FG-CRYPTO-003"),
            result("Admin access", "HTTPS admin port is non-standard", (admin_sport is not None and admin_sport != 443), "Use a non-default HTTPS administrative port and restrict it with trusted hosts/local-in policy.", f"admin-sport={admin_sport}", "Medium", "FG-MGMT-012"),
            result("Admin access", "SSH admin port is non-standard", (admin_ssh_port is not None and admin_ssh_port != 22), "Use a non-default SSH administrative port and restrict it with trusted hosts/local-in policy.", f"admin-ssh-port={admin_ssh_port}", "Medium", "FG-MGMT-013"),
            result("Admin access", "Admin idle timeout is less than 10 minutes", (admin_timeout is not None and admin_timeout < 10), "Set the administrator idle timeout below 10 minutes.", f"admintimeout={admin_timeout}", "Medium", "FG-MGMT-016"),
            result("Admin access", "HTTP-to-HTTPS redirect is disabled or admin-host is configured", (is_disabled(redirect) or bool(admin_host)), "Disable HTTP-to-HTTPS redirection, or configure admin-host if redirection is required.", f"admin-https-redirect={redirect}; admin-host={admin_host}", "Medium", "FG-MGMT-020"),
            result("Admin TLS", "Custom/trusted HTTPS admin certificate is configured", bool(cert and norm(cert) not in {"self-sign", "self-signed", "fortinet_factory", "factory", ""}), "Replace the default/self-signed HTTPS admin certificate with a trusted certificate matching the management FQDN/IP.", f"admin certificate field={cert}", "Medium", "FG-MGMT-017"),
            result("Password storage", "Private data encryption is enabled", is_enabled(private_data), "Enable private data encryption where operationally acceptable and document backup/restore implications.", f"private-data-encryption={private_data}", "Medium", "FG-PWD-001"),
        ])
    else:
        checks.append(missing("system_global", endpoints))

    # Interfaces / management exposure
    if endpoint_ok("system_interface", endpoints):
        interfaces = [x for x in as_list(api_results(endpoints["system_interface"])) if isinstance(x, dict)]
        admin_ifaces = [i for i in interfaces if has_admin_access(i)]
        insecure_ifaces = [i for i in interfaces if allowaccess_set(i) & {"http", "telnet"}]
        wan_admin = [i for i in interfaces if looks_wan(i) and has_admin_access(i)]
        admin_names = [mkey_name(i) + ":" + "/".join(sorted(allowaccess_set(i))) for i in admin_ifaces]
        insecure_names = [mkey_name(i) + ":" + "/".join(sorted(allowaccess_set(i) & {"http", "telnet"})) for i in insecure_ifaces]
        wan_names = [mkey_name(i) + ":" + "/".join(sorted(allowaccess_set(i))) for i in wan_admin]
        checks.extend([
            result("Management plane", "Insecure admin protocols HTTP/Telnet are disabled on all interfaces", len(insecure_ifaces) == 0, "Remove HTTP and Telnet from interface allowaccess; use HTTPS/SSH only from trusted management networks.", f"Interfaces with HTTP/Telnet: {', '.join(insecure_names) or 'none'}", "High", "FG-MGMT-005"),
            result("Management plane", "WAN/public-looking interfaces do not expose admin access", len(wan_admin) == 0, "Disable admin access on WAN/public interfaces, or strictly restrict with trusted hosts and local-in policy if unavoidable.", f"WAN-like admin interfaces: {', '.join(wan_names) or 'none'}", "High", "FG-MGMT-003"),
            result("Management plane", "Administrative access is limited to few interfaces", len(admin_ifaces) <= 2, "Keep administrative access on a dedicated management interface/VLAN only.", f"Admin-enabled interfaces: {', '.join(admin_names) or 'none'}", "Medium", "FG-MGMT-001"),
        ])
    else:
        checks.append(missing("system_interface", endpoints))

    # Admin users
    if endpoint_ok("system_admin", endpoints):
        admins = [x for x in as_list(api_results(endpoints["system_admin"])) if isinstance(x, dict)]
        default_admins = [a for a in admins if norm(mkey_name(a)) in {"admin", "administrator", "root"}]
        admins_no_trust = [mkey_name(a) for a in admins if not has_restricted_trusthost(a)]
        local_admins = [a for a in admins if norm(get_any(a, ["remote-auth", "remote_auth"], "disable")) != "enable"]
        no_mfa = [mkey_name(a) for a in local_admins if is_disabled(get_any(a, ["two-factor", "two_factor"], "disable"))]
        super_admins = [mkey_name(a) for a in admins if norm(get_any(a, ["accprofile", "access-profile", "profile"], "")) == "super_admin"]
        disallowed_methods_missing = [mkey_name(a) for a in admins if not any(k in a for k in ["ssh-public-key1", "password", "trusthost1", "login-max", "gui-dashboard"])]

        checks.extend([
            result("Admin identity", "Default/well-known administrator username is not used", len(default_admins) == 0, "Rename/disable default administrator names such as admin and use unique named accounts.", f"Default-like admin users: {', '.join(mkey_name(a) for a in default_admins) or 'none'}", "Medium", "FG-MGMT-014"),
            result("Admin identity", "Administrator trusted hosts are configured", len(admins_no_trust) == 0, "Configure trusted hosts for every administrator account.", f"Admins without restricted trusted hosts: {', '.join(admins_no_trust) or 'none'}", "High", "FG-ADMIN-004"),
            result("Admin identity", "MFA is enabled for local administrator accounts", len(no_mfa) == 0, "Enable MFA/FortiToken/email token for local administrators, or use centralized authentication with MFA.", f"Local admins without detected MFA: {', '.join(no_mfa) or 'none'}", "High", "FG-ADMIN-006"),
            result("Admin identity", "Super admin profile use is minimized", len(super_admins) <= 1, "Use least-privilege admin profiles; keep only an emergency break-glass super_admin if required.", f"super_admin users: {', '.join(super_admins) or 'none'}", "Medium", "FG-ADMIN-007"),
        ])
    else:
        checks.append(missing("system_admin", endpoints))

    # REST API users
    if endpoint_ok("system_api_user", endpoints):
        api_users = [x for x in as_list(api_results(endpoints["system_api_user"])) if isinstance(x, dict)]
        api_no_trust = [mkey_name(u) for u in api_users if not has_restricted_trusthost(u)]
        api_super = [mkey_name(u) for u in api_users if norm(get_any(u, ["accprofile", "access-profile", "profile"], "")) == "super_admin"]
        checks.extend([
            result("REST API access", "REST API users have restricted trusted hosts", len(api_no_trust) == 0, "Restrict each REST API administrator to trusted source IPs/subnets.", f"API users without restricted trusted hosts: {', '.join(api_no_trust) or 'none'}", "High", "FG-API-001"),
            result("REST API access", "REST API users do not use generic super_admin", len(api_super) == 0, "Use read-only or custom least-privilege access profiles for API users.", f"API users with super_admin: {', '.join(api_super) or 'none'}", "High", "FG-API-002"),
        ])
    else:
        checks.append(missing("system_api_user", endpoints))

    # Time sync
    if endpoint_ok("system_ntp", endpoints):
        ntp = first_dict(api_results(endpoints["system_ntp"]))
        ntp_sync = get_any(ntp, ["ntpsync", "ntp-sync", "status"])
        auth = get_any(ntp, ["authentication", "auth", "ntp-auth"])
        checks.extend([
            result("System time", "NTP synchronization is enabled", is_enabled(ntp_sync), "Enable NTP time synchronization for accurate logs and certificate validation.", f"ntpsync/status={ntp_sync}", "High", "FG-TIME-001"),
            result("System time", "NTP authentication is enabled where configured", is_enabled(auth) if auth is not None else None, "Use NTP authentication where supported by the selected NTP server design.", f"authentication={auth}", "Low", "FG-TIME-005"),
        ])
    else:
        checks.append(missing("system_ntp", endpoints))

    # Logging
    logging_checks: List[str] = []
    encrypted_logging = False
    any_remote_logging = False
    if endpoint_ok("log_fortianalyzer", endpoints):
        faz = first_dict(api_results(endpoints["log_fortianalyzer"]))
        faz_status = get_any(faz, ["status"])
        if is_enabled(faz_status):
            any_remote_logging = True
            encrypted_logging = True  # FortiAnalyzer transport is expected to be encrypted by Fortinet design.
            logging_checks.append(f"FortiAnalyzer status={faz_status}")
    if endpoint_ok("log_syslogd", endpoints):
        syslog = first_dict(api_results(endpoints["log_syslogd"]))
        syslog_status = get_any(syslog, ["status"])
        if is_enabled(syslog_status):
            any_remote_logging = True
            mode = norm(get_any(syslog, ["mode", "reliable"])); enc = norm(get_any(syslog, ["enc-algorithm", "enc_algorithm", "ssl-min-proto-version"]))
            if mode in {"reliable", "tls"} or enc not in {"", "disable", "none"}:
                encrypted_logging = True
            logging_checks.append(f"syslogd status={syslog_status}, mode={mode or 'unknown'}, encryption={enc or 'unknown'}")
    checks.extend([
        result("Logging", "Remote or centralized logging is configured", any_remote_logging, "Send logs to FortiAnalyzer, FortiCloud, or a secured syslog destination.", "; ".join(logging_checks) or "No enabled remote logging target detected", "High", "FG-LOG-001"),
        result("Logging", "Remote log transport is encrypted", encrypted_logging if any_remote_logging else None, "Encrypt log transmission or send logs through a protected management/VPN path.", "; ".join(logging_checks) or "No remote logging target to evaluate", "High", "FG-LOG-006"),
    ])

    # Local-in policies
    if endpoint_ok("firewall_local_in_policy", endpoints):
        local_in = [x for x in as_list(api_results(endpoints["firewall_local_in_policy"])) if isinstance(x, dict)]
        enabled_pols = [p for p in local_in if not is_disabled(get_any(p, ["status"], "enable"))]
        logging_on = [p for p in enabled_pols if is_enabled(get_any(p, ["logtraffic", "log", "logtraffic-start"], "disable"))]
        checks.extend([
            result("Local-in policy", "Local-in policies are configured", len(enabled_pols) > 0, "Use local-in policies to restrict access to FortiGate interface services, especially management ports.", f"Enabled local-in policies: {len(enabled_pols)}", "High", "FG-LIN-001"),
            result("Local-in policy", "Local-in policy logging is enabled", len(enabled_pols) > 0 and len(logging_on) > 0, "Enable logging on local-in policies used to protect management access.", f"Enabled local-in policies={len(enabled_pols)}, with logging={len(logging_on)}", "Medium", "FG-LIN-005"),
        ])
    else:
        checks.append(missing("firewall_local_in_policy", endpoints))

    # Physical/USB auto-install
    if endpoint_ok("system_autoinstall", endpoints):
        ai = first_dict(api_results(endpoints["system_autoinstall"]))
        auto_cfg = get_any(ai, ["auto-install-config", "auto_install_config"])
        auto_img = get_any(ai, ["auto-install-image", "auto_install_image"])
        checks.extend([
            result("Physical security", "USB configuration auto-install is disabled", is_disabled(auto_cfg), "Disable USB configuration auto-install unless explicitly required for a controlled provisioning process.", f"auto-install-config={auto_cfg}", "High", "FG-PHYS-002"),
            result("Physical security", "USB firmware image auto-install is disabled", is_disabled(auto_img), "Disable USB firmware image auto-install to reduce risk from physical access.", f"auto-install-image={auto_img}", "High", "FG-PHYS-003"),
        ])
    else:
        checks.append(missing("system_autoinstall", endpoints))

    # SNMP
    snmp_enabled = False
    if endpoint_ok("system_snmp_sysinfo", endpoints):
        snmpinfo = first_dict(api_results(endpoints["system_snmp_sysinfo"]))
        snmp_enabled = is_enabled(get_any(snmpinfo, ["status"], "disable"))
    if endpoint_ok("system_snmp_community", endpoints):
        communities = [x for x in as_list(api_results(endpoints["system_snmp_community"])) if isinstance(x, dict)]
    else:
        communities = []
    if endpoint_ok("system_snmp_user", endpoints):
        snmp_users = [x for x in as_list(api_results(endpoints["system_snmp_user"])) if isinstance(x, dict)]
    else:
        snmp_users = []
    checks.append(result(
        "Encrypted protocols",
        "SNMP uses SNMPv3 or is disabled",
        True if not snmp_enabled else (len(communities) == 0 and len(snmp_users) > 0),
        "Use SNMPv3 users instead of SNMPv1/v2c communities, or disable SNMP if not needed.",
        f"SNMP enabled={snmp_enabled}; communities={len(communities)}; snmpv3 users={len(snmp_users)}",
        "High",
        "FG-ENC-004",
    ))

    # LDAP / RADIUS encrypted protocol checks
    if endpoint_ok("user_ldap", endpoints):
        ldaps = [x for x in as_list(api_results(endpoints["user_ldap"])) if isinstance(x, dict)]
        insecure_ldap = []
        for l in ldaps:
            secure = norm(get_any(l, ["secure", "ssl", "tls"], ""))
            port = to_int(get_any(l, ["port"], None), None)
            if secure in {"", "disable", "none"} and port != 636:
                insecure_ldap.append(mkey_name(l))
        checks.append(result("Encrypted protocols", "LDAP servers use LDAPS/secure transport", len(insecure_ldap) == 0, "Use LDAPS or secure LDAP transport for directory authentication.", f"LDAP objects without detected secure transport: {', '.join(insecure_ldap) or 'none'}", "High", "FG-ENC-001"))
    else:
        checks.append(missing("user_ldap", endpoints))

    if endpoint_ok("user_radius", endpoints):
        radii = [x for x in as_list(api_results(endpoints["user_radius"])) if isinstance(x, dict)]
        insecure_radius = []
        for r in radii:
            transport = norm(get_any(r, ["transport-protocol", "transport_protocol", "protocol"], ""))
            if transport not in {"tls", "radsec"}:
                insecure_radius.append(mkey_name(r))
        checks.append(result("Encrypted protocols", "RADIUS uses RADSEC/TLS where supported", len(insecure_radius) == 0 if radii else None, "Use RADSEC over TLS where supported by the identity infrastructure.", f"RADIUS objects without detected TLS/RADSEC: {', '.join(insecure_radius) or 'none'}", "Medium", "FG-ENC-003"))
    else:
        checks.append(missing("user_radius", endpoints))

    # DoS policy
    if endpoint_ok("firewall_dos_policy", endpoints):
        dos_policies = [x for x in as_list(api_results(endpoints["firewall_dos_policy"])) if isinstance(x, dict)]
        enabled_dos = [p for p in dos_policies if not is_disabled(get_any(p, ["status"], "enable"))]
        checks.append(result("DoS protection", "DoS policies are configured", len(enabled_dos) > 0, "Create DoS policies for internet-facing or high-risk interfaces and tune thresholds from observed traffic.", f"Enabled DoS policies: {len(enabled_dos)}", "Medium", "FG-DOS-001"))
        # Anomaly names are often nested; do a string scan to avoid brittle schema assumptions.
        dos_blob = short_json(enabled_dos, max_len=10000).lower()
        for anomaly in ["tcp_syn_flood", "tcp_port_scan", "tcp_src_session", "tcp_dst_session", "ip_src_session", "ip_dst_session"]:
            checks.append(result("DoS protection", f"DoS anomaly {anomaly} is present/enabled", anomaly.lower() in dos_blob and "disable" not in dos_blob[:dos_blob.find(anomaly.lower())+80], f"Enable and tune the {anomaly} anomaly where applicable.", f"Search result for {anomaly}: {'found' if anomaly.lower() in dos_blob else 'not found'}", "Low", f"FG-DOS-{anomaly}"))
    else:
        checks.append(missing("firewall_dos_policy", endpoints))

    # Firewall policy hygiene
    if endpoint_ok("firewall_policy", endpoints):
        policies = [x for x in as_list(api_results(endpoints["firewall_policy"])) if isinstance(x, dict)]
        enabled_policies = [p for p in policies if not is_disabled(get_any(p, ["status"], "enable"))]
        names = [str(get_any(p, ["name"], "")).strip() for p in enabled_policies]
        nonempty_names = [n for n in names if n]
        duplicate_names = sorted({n for n in nonempty_names if nonempty_names.count(n) > 1})
        blank_names = len(enabled_policies) - len(nonempty_names)
        broad_intf = []
        broad_service = []
        no_log = []
        for p in enabled_policies:
            pname = str(get_any(p, ["name", "policyid"], mkey_name(p)))
            fields = policy_field_names([p], "srcintf") + policy_field_names([p], "dstintf")
            if any(norm(v) in {"any", "all"} for v in fields):
                broad_intf.append(pname)
            services = policy_field_names([p], "service")
            if any(norm(v) in {"all", "any"} for v in services):
                broad_service.append(pname)
            if is_disabled(get_any(p, ["logtraffic"], "disable")):
                no_log.append(pname)
        checks.extend([
            result("Firewall policy hygiene", "Enabled firewall policies have unique, non-empty names", blank_names == 0 and len(duplicate_names) == 0, "Give every policy a unique descriptive name.", f"Enabled policies={len(enabled_policies)}; blank names={blank_names}; duplicates={', '.join(duplicate_names) or 'none'}", "Low", "FG-POL-001"),
            result("Firewall policy hygiene", "Enabled policies avoid any/all interfaces", len(broad_intf) == 0, "Use explicit source and destination interfaces instead of any/all, except documented exceptions.", f"Policies with broad interfaces: {', '.join(broad_intf[:20]) or 'none'}", "Medium", "FG-POL-003"),
            result("Firewall policy hygiene", "Enabled policies avoid broad ALL service", len(broad_service) == 0, "Restrict services to the minimum required set.", f"Policies with ALL/ANY service: {', '.join(broad_service[:20]) or 'none'}", "Medium", "FG-POL-006"),
            result("Firewall policy hygiene", "Traffic logging is enabled on firewall policies", len(no_log) == 0, "Enable traffic logging where visibility is required, at minimum for internet, server, and privileged-access policies.", f"Policies without traffic logging: {', '.join(no_log[:20]) or 'none'}", "Medium", "FG-LOG-004"),
        ])
    else:
        checks.append(missing("firewall_policy", endpoints))

    # SSL VPN and IPsec crypto checks
    if endpoint_ok("vpn_ssl_settings", endpoints):
        sslvpn = first_dict(api_results(endpoints["vpn_ssl_settings"]))
        ssl_status = get_any(sslvpn, ["status"])
        min_proto = get_any(sslvpn, ["ssl-min-proto-ver", "ssl-min-proto-version", "ssl_min_proto_version"])
        ciphers = short_json({k: v for k, v in sslvpn.items() if "cipher" in str(k).lower() or "proto" in str(k).lower()}, 500)
        if is_enabled(ssl_status):
            weak_min = norm(min_proto) in {"tls1-0", "tls1.0", "tlsv1-0", "tlsv1.0", "tls1-1", "tls1.1", "tlsv1-1", "tlsv1.1", ""}
            checks.append(result("Remote access", "SSL VPN minimum TLS version is strong", not weak_min, "Require TLS 1.2 or higher for SSL VPN where supported.", f"status={ssl_status}; min protocol={min_proto}; crypto fields={ciphers}", "High", "FG-VPN-005"))
        else:
            checks.append(result("Remote access", "SSL VPN is disabled or not exposed", True, "No action needed if SSL VPN is intentionally disabled.", f"SSL VPN status={ssl_status}", "Info", "FG-VPN-000"))
    else:
        checks.append(missing("vpn_ssl_settings", endpoints))

    if endpoint_ok("vpn_ipsec_phase1_interface", endpoints):
        phase1s = [x for x in as_list(api_results(endpoints["vpn_ipsec_phase1_interface"])) if isinstance(x, dict)]
        legacy = []
        ikev1 = []
        for p in phase1s:
            name = mkey_name(p)
            ikever = norm(get_any(p, ["ike-version", "ike_version"], ""))
            proposal = norm(get_any(p, ["proposal"], ""))
            dhgrp = norm(get_any(p, ["dhgrp"], ""))
            if ikever == "1":
                ikev1.append(name)
            if any(x in proposal for x in ["des", "3des", "md5"]) or re.search(r"(^|\s|,)(1|2|5)(\s|,|$)", dhgrp):
                legacy.append(f"{name} proposal={proposal} dhgrp={dhgrp}")
        checks.extend([
            result("Remote access", "IPsec phase1 interfaces prefer IKEv2", len(ikev1) == 0 if phase1s else None, "Prefer IKEv2 for IPsec VPNs where peer support allows it.", f"IKEv1 phase1 interfaces: {', '.join(ikev1) or 'none'}", "Medium", "FG-VPN-006"),
            result("Remote access", "IPsec phase1 avoids legacy DES/3DES/MD5/weak DH", len(legacy) == 0 if phase1s else None, "Disable DES/3DES/MD5 and weak DH groups; use modern AES/SHA-256+ and DH groups such as 14, 19, or 20 where appropriate.", f"Legacy crypto findings: {', '.join(legacy[:15]) or 'none'}", "High", "FG-VPN-007"),
        ])
    else:
        checks.append(missing("vpn_ipsec_phase1_interface", endpoints))

    # License / FortiGuard
    if endpoint_ok("license_status", endpoints):
        lic = api_results(endpoints["license_status"])
        lic_blob = short_json(lic, max_len=5000).lower()
        has_valid = any(word in lic_blob for word in ["valid", "registered", "connected", "licensed"])
        expired = "expired" in lic_blob or "invalid" in lic_blob
        checks.append(result("FortiGuard", "FortiGuard/license status appears healthy", has_valid and not expired, "Confirm FortiGuard connectivity, active contracts, and current AV/IPS/antispam databases.", short_json(lic, 800), "High", "FG-FGD-001"))
    else:
        checks.append(missing("license_status", endpoints))

    return checks


# -------------------------
# Rendering
# -------------------------

BASE_TEMPLATE = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FortiGate Hardening Checker</title>
  <style>
    :root {
      --bg: #0f172a;
      --panel: #111827;
      --panel2: #172033;
      --text: #e5e7eb;
      --muted: #9ca3af;
      --line: #334155;
      --pass: #16a34a;
      --fail: #dc2626;
      --review: #d97706;
      --error: #9333ea;
      --chip: #243045;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: radial-gradient(circle at top left, #1e293b, var(--bg) 42%); color: var(--text); }
    .wrap { max-width: 1240px; margin: 0 auto; padding: 32px 20px 56px; }
    h1 { margin: 0 0 8px; font-size: 34px; letter-spacing: -0.03em; }
    h2 { margin-top: 32px; }
    .subtitle { color: var(--muted); margin-bottom: 24px; }
    .card { background: linear-gradient(180deg, rgba(255,255,255,.04), rgba(255,255,255,.02)); border: 1px solid var(--line); border-radius: 18px; padding: 22px; box-shadow: 0 14px 60px rgba(0,0,0,.25); }
    label { display:block; margin: 16px 0 6px; color: #cbd5e1; font-weight: 600; }
    input[type=text], input[type=password], input[type=number], select { width: 100%; border: 1px solid #475569; border-radius: 12px; background: #0b1220; color: var(--text); padding: 12px 14px; font-size: 16px; }
    input[type=checkbox] { transform: scale(1.1); margin-right: 8px; }
    .grid { display: grid; grid-template-columns: repeat(12, 1fr); gap: 16px; }
    .col-6 { grid-column: span 6; }
    .col-4 { grid-column: span 4; }
    .col-12 { grid-column: span 12; }
    button, .button { display: inline-block; margin-top: 20px; border: 0; border-radius: 12px; background: #f97316; color: #111827; font-weight: 800; padding: 12px 18px; cursor: pointer; text-decoration: none; }
    button:hover, .button:hover { filter: brightness(1.08); }
    .note { color: var(--muted); font-size: 14px; line-height: 1.45; }
    .summary { display:grid; grid-template-columns: repeat(4, 1fr); gap:14px; margin: 22px 0; }
    .metric { border:1px solid var(--line); border-radius:16px; padding:16px; background: rgba(15,23,42,.68); }
    .metric b { font-size: 28px; display:block; }
    .metric span { color:var(--muted); }
    .pass b { color: var(--pass); } .fail b { color: var(--fail); } .review b { color: var(--review); } .error b { color: var(--error); }
    table { width:100%; border-collapse: collapse; overflow: hidden; border-radius: 16px; }
    th, td { padding: 12px 13px; border-bottom: 1px solid var(--line); vertical-align: top; }
    th { text-align:left; color:#cbd5e1; background:#121c2e; position: sticky; top: 0; }
    tr { background: rgba(15,23,42,.55); }
    tr:hover { background: rgba(30,41,59,.85); }
    .status { display:inline-flex; align-items:center; gap:6px; font-weight:800; border-radius:999px; padding:5px 9px; font-size:12px; }
    .status.pass { background: rgba(22,163,74,.14); color:#86efac; }
    .status.fail { background: rgba(220,38,38,.14); color:#fca5a5; }
    .status.review { background: rgba(217,119,6,.14); color:#fcd34d; }
    .status.error { background: rgba(147,51,234,.14); color:#d8b4fe; }
    .evidence { color:#cbd5e1; font-size: 13px; white-space: pre-wrap; }
    .toolbar { display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-bottom: 14px; }
    .filter { border:1px solid var(--line); background: var(--chip); color: var(--text); border-radius:999px; padding:8px 12px; cursor:pointer; }
    .filter.active { outline:2px solid #f97316; }
    details { margin-top: 20px; }
    summary { cursor: pointer; color: #fdba74; font-weight: 700; }
    pre { white-space: pre-wrap; background:#0b1220; padding:14px; border-radius:12px; border:1px solid var(--line); overflow:auto; }
    .footer { margin-top: 28px; color: var(--muted); font-size:13px; }
    @media (max-width: 800px) { .col-6, .col-4 { grid-column: span 12; } .summary { grid-template-columns: repeat(2,1fr); } th:nth-child(5), td:nth-child(5) { display:none; } }
  </style>
</head>
<body>
<div class="wrap">
  {{ body|safe }}
</div>
<script>
function setFilter(status) {
  document.querySelectorAll('[data-filter]').forEach(b => b.classList.toggle('active', b.dataset.filter === status));
  document.querySelectorAll('tr[data-status]').forEach(row => {
    row.style.display = (status === 'ALL' || row.dataset.status === status) ? '' : 'none';
  });
}
function downloadReport() {
  const blob = new Blob([document.documentElement.outerHTML], {type: 'text/html'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'fortigate-hardening-report.html';
  a.click();
  URL.revokeObjectURL(a.href);
}
</script>
</body>
</html>
"""

FORM_BODY = r"""
<h1>FortiGate Hardening Checker</h1>
<p class="subtitle">Local REST API scanner for FortiOS 8.0, 7.6, or 7.4 hardening controls. Read-only, no token storage, no wizardry behind the curtain.</p>
<div class="card">
  <form method="post" action="/scan">
    <div class="grid">
      <div class="col-6">
        <label for="host">FortiGate IP or FQDN</label>
        <input id="host" name="host" type="text" placeholder="192.0.2.10 or fgt.example.com" required>
      </div>
      <div class="col-4">
        <label for="port">HTTPS admin/API port</label>
        <input id="port" name="port" type="number" min="1" max="65535" value="443" required>
      </div>
      <div class="col-4">
        <label for="firmware_family">Hardening baseline</label>
        <select id="firmware_family" name="firmware_family" required>
          <option value="8.0" selected>FortiOS 8.0</option>
          <option value="7.6">FortiOS 7.6</option>
          <option value="7.4">FortiOS 7.4</option>
        </select>
      </div>
      <div class="col-4">
        <label for="vdom">VDOM</label>
        <input id="vdom" name="vdom" type="text" value="root">
      </div>
      <div class="col-12">
        <label for="token">REST API token</label>
        <input id="token" name="token" type="password" autocomplete="off" placeholder="Paste read-only REST API token" required>
      </div>
      <div class="col-12">
        <label><input type="checkbox" name="verify_tls" value="1"> Verify FortiGate TLS certificate</label>
        <p class="note">Leave unchecked for lab/self-signed certificates. For production, use a trusted certificate on the FortiGate and enable verification.</p>
      </div>
    </div>
    <button type="submit">Run hardening scan</button>
  </form>
</div>
<div class="footer">
  <p>Recommended API account: read-only profile with minimum permissions required, restricted trusted hosts, and token passed via Authorization header.</p>
</div>
"""


def render_page(body: str) -> str:
    return render_template_string(BASE_TEMPLATE, body=body)


@app.get("/")
def index() -> str:
    return render_page(FORM_BODY)


@app.post("/scan")
def scan() -> str:
    host = request.form.get("host", "").strip()
    port = int(request.form.get("port", "443") or 443)
    token = request.form.get("token", "")
    vdom = request.form.get("vdom", "root")
    firmware_family = request.form.get("firmware_family", DEFAULT_BASELINE)
    verify_tls = request.form.get("verify_tls") == "1"
    started = dt.datetime.now().astimezone()

    try:
        client = FortiGateClient(host=host, api_token=token, port=port, vdom=vdom, verify_tls=verify_tls)
        endpoints = client.fetch_all()
        checks = run_checks(endpoints, firmware_family)
        body = render_report(host, port, vdom, firmware_family, started, endpoints, checks, None)
    except Exception as exc:
        body = render_report(host, port, vdom, firmware_family, started, {}, [], f"{exc}\n\n{traceback.format_exc()}")
    return render_page(body)


def status_counts(checks: List[CheckResult]) -> Dict[str, int]:
    counts = {"PASS": 0, "FAIL": 0, "REVIEW": 0, "ERROR": 0}
    for c in checks:
        counts[c.status] = counts.get(c.status, 0) + 1
    return counts


def render_report(host: str, port: int, vdom: str, firmware_family: str, started: dt.datetime, endpoints: Dict[str, EndpointResult], checks: List[CheckResult], fatal_error: Optional[str]) -> str:
    baseline = get_baseline(firmware_family)
    if fatal_error:
        escaped = html.escape(fatal_error)
        return f"""
        <h1>FortiGate Hardening Checker</h1>
        <div class="card">
          <h2>Scan failed</h2>
          <p class="subtitle">Could not complete the scan against {html.escape(host)}:{port} / VDOM {html.escape(vdom)} / Baseline {html.escape(baseline['label'])}.</p>
          <pre>{escaped}</pre>
          <a class="button" href="/">Back</a>
        </div>
        """

    counts = status_counts(checks)
    total = len(checks)
    endpoint_rows = "".join(
        f"<tr><td>{html.escape(k)}</td><td>{html.escape(str(v.endpoint))}</td><td>{'OK' if v.ok else 'Failed'}</td><td>{html.escape(str(v.http_status or ''))}</td><td>{html.escape(str(v.error or ''))}</td></tr>"
        for k, v in endpoints.items()
    )
    check_rows = "".join(
        f"""
        <tr data-status="{c.status}">
          <td>{html.escape(c.category)}</td>
          <td>{html.escape(c.control_id)}</td>
          <td>{html.escape(c.control)}</td>
          <td><span class="status {c.css_class}">{html.escape(c.status)}</span></td>
          <td>{html.escape(c.severity)}</td>
          <td>{html.escape(c.recommendation)}</td>
          <td class="evidence">{html.escape(c.evidence)}</td>
        </tr>
        """ for c in checks
    )

    return f"""
    <h1>FortiGate Hardening Report</h1>
    <p class="subtitle">Target: {html.escape(host)}:{port} · VDOM: {html.escape(vdom)} · Baseline: {html.escape(baseline['label'])} · Scan time: {started.strftime('%Y-%m-%d %H:%M:%S %Z')} · App v{APP_VERSION}</p>
    <p class="subtitle">Baseline source: <a style="color:#fdba74" href="{html.escape(baseline['doc_url'])}" target="_blank" rel="noopener">{html.escape(baseline['doc_url'])}</a></p>

    <div class="summary">
      <div class="metric"><b>{total}</b><span>Total checks</span></div>
      <div class="metric pass"><b>{counts.get('PASS',0)}</b><span>Compliant</span></div>
      <div class="metric fail"><b>{counts.get('FAIL',0)}</b><span>Non-compliant</span></div>
      <div class="metric review"><b>{counts.get('REVIEW',0)}</b><span>Review / unavailable</span></div>
    </div>

    <div class="toolbar">
      <button class="filter active" data-filter="ALL" onclick="setFilter('ALL')">All</button>
      <button class="filter" data-filter="FAIL" onclick="setFilter('FAIL')">Failures</button>
      <button class="filter" data-filter="REVIEW" onclick="setFilter('REVIEW')">Review</button>
      <button class="filter" data-filter="PASS" onclick="setFilter('PASS')">Pass</button>
      <button class="filter" onclick="downloadReport()">Download HTML report</button>
      <a class="button" href="/">New scan</a>
    </div>

    <div class="card">
      <table>
        <thead><tr><th>Category</th><th>ID</th><th>Control</th><th>Status</th><th>Severity</th><th>Recommendation</th><th>Evidence</th></tr></thead>
        <tbody>{check_rows}</tbody>
      </table>
    </div>

    <details>
      <summary>Endpoint diagnostics</summary>
      <div class="card">
        <table>
          <thead><tr><th>Key</th><th>Endpoint</th><th>Status</th><th>HTTP</th><th>Error</th></tr></thead>
          <tbody>{endpoint_rows}</tbody>
        </table>
      </div>
    </details>

    <div class="footer">
      <p>Note: REVIEW means the app could not validate the control from the available GET data, usually because of endpoint permission, platform variance, or a control requiring manual evidence.</p>
    </div>
    """


@app.get("/health")
def health() -> Response:
    return Response(json.dumps({"status": "ok", "version": APP_VERSION, "baselines": list(FIRMWARE_BASELINES.keys())}), mimetype="application/json")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=False)
