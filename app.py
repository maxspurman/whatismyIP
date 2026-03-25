import os
import ipaddress
from typing import Optional, Dict, Any

import requests
from flask import Flask, jsonify, render_template, request
from ua_parser import parse
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)

TRUST_PROXY = os.getenv("TRUST_PROXY", "false").lower() == "true"
if TRUST_PROXY:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

IPWHOIS_TIMEOUT = 4
IPIFY_TIMEOUT = 4

session = requests.Session()
session.headers.update({
    "User-Agent": "ip-check-tool/1.0"
})


def safe_get_json(url: str, timeout: int = 4) -> Optional[Dict[str, Any]]:
    try:
        response = session.get(url, timeout=timeout)
        response.raise_for_status()
        if "application/json" not in response.headers.get("Content-Type", ""):
            return None
        return response.json()
    except (requests.RequestException, ValueError):
        return None


def normalize_ip(value: Optional[str]) -> Optional[str]:
    if not value:
        return None

    value = value.strip()

    if "," in value:
        value = value.split(",")[0].strip()

    if value.lower().startswith("::ffff:"):
        value = value[7:]

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def get_client_ip_from_request() -> Optional[str]:
    candidates = [
        request.headers.get("CF-Connecting-IP"),
        request.headers.get("True-Client-IP"),
        request.headers.get("X-Real-IP"),
        request.headers.get("X-Forwarded-For"),
        request.remote_addr,
    ]

    for candidate in candidates:
        ip = normalize_ip(candidate)
        if ip:
            return ip
    return None


def get_public_ip_via_ipify(version: str = "v4") -> Optional[str]:
    url = "https://api.ipify.org?format=json"
    if version == "v6":
        url = "https://api6.ipify.org?format=json"

    data = safe_get_json(url, timeout=IPIFY_TIMEOUT)
    if not data:
        return None

    return normalize_ip(data.get("ip"))


def classify_ip(ip: Optional[str]) -> Dict[str, Any]:
    result = {
        "value": ip,
        "version": None,
        "is_public": False,
        "is_private": False,
        "is_loopback": False,
        "is_reserved": False,
    }

    if not ip:
        return result

    try:
        parsed = ipaddress.ip_address(ip)
        result["version"] = parsed.version
        result["is_private"] = parsed.is_private
        result["is_loopback"] = parsed.is_loopback
        result["is_reserved"] = parsed.is_reserved
        result["is_public"] = not (
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_reserved
            or parsed.is_multicast
            or parsed.is_link_local
            or parsed.is_unspecified
        )
        return result
    except ValueError:
        return result


def get_geo_data(ip: Optional[str]) -> Dict[str, Any]:
    fallback = {
        "country": "Unbekannt",
        "country_code": None,
        "region": None,
        "city": None,
        "isp": None,
        "asn": None,
        "connection_type": None,
    }

    if not ip:
        return fallback

    data = safe_get_json(f"https://ipwho.is/{ip}", timeout=IPWHOIS_TIMEOUT)
    if not data or not data.get("success", False):
        return fallback

    country = data.get("country") or "Unbekannt"
    if country == "Germany":
        country = "Deutschland"

    connection = data.get("connection") or {}

    return {
        "country": country,
        "country_code": data.get("country_code"),
        "region": data.get("region"),
        "city": data.get("city"),
        "isp": connection.get("isp"),
        "asn": connection.get("asn"),
        "connection_type": connection.get("type"),
    }


def join_versioned_name(obj) -> str:
    if not obj:
        return "Unbekannt"

    family = getattr(obj, "family", None) or "Unbekannt"
    parts = [
        getattr(obj, "major", None),
        getattr(obj, "minor", None),
        getattr(obj, "patch", None),
        getattr(obj, "patch_minor", None),
    ]
    version = ".".join([p for p in parts if p])

    return f"{family} {version}".strip()


def parse_user_agent(user_agent: str) -> Dict[str, str]:
    if not user_agent:
        return {
            "os": "Unbekannt",
            "browser": "Unbekannt",
            "device": "Unbekannt",
        }

    parsed = parse(user_agent)

    os_name = join_versioned_name(parsed.os)
    browser_name = join_versioned_name(parsed.user_agent)

    device_family = "Unbekannt"
    if parsed.device and getattr(parsed.device, "family", None):
        device_family = parsed.device.family

    return {
        "os": os_name,
        "browser": browser_name,
        "device": device_family,
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/info")
def info():
    client_ip_v4 = normalize_ip(request.args.get("client_ip_v4"))
    client_ip_v6 = normalize_ip(request.args.get("client_ip_v6"))
    request_seen_ip = get_client_ip_from_request()

    if not client_ip_v4:
        candidate = request_seen_ip
        if candidate and classify_ip(candidate)["version"] == 4:
            client_ip_v4 = candidate
        if not client_ip_v4:
            client_ip_v4 = get_public_ip_via_ipify("v4")

    if not client_ip_v6:
        candidate = request_seen_ip
        if candidate and classify_ip(candidate)["version"] == 6 and not classify_ip(candidate)["is_loopback"]:
            client_ip_v6 = candidate
        if not client_ip_v6:
            client_ip_v6 = get_public_ip_via_ipify("v6")

    ua_data = parse_user_agent(request.headers.get("User-Agent", ""))
    preferred_geo_ip = client_ip_v4 or client_ip_v6
    geo = get_geo_data(preferred_geo_ip)

    ipv4_meta = classify_ip(client_ip_v4)
    ipv6_meta = classify_ip(client_ip_v6)

    return jsonify({
        "ip": client_ip_v4 or "Unbekannt",
        "ipv4": client_ip_v4 or "Unbekannt",
        "ipv6": client_ip_v6 or "nicht vorhanden",
        "os": ua_data["os"],
        "browser": ua_data["browser"],
        "device": ua_data["device"],
        "country": geo["country"],
        "country_code": geo["country_code"],
        "region": geo["region"],
        "city": geo["city"],
        "isp": geo["isp"],
        "asn": geo["asn"],
        "connection_type": geo["connection_type"],
        "meta": {
            "request_seen_ip": request_seen_ip,
            "ipv4_public": ipv4_meta["is_public"],
            "ipv6_public": ipv6_meta["is_public"],
            "trust_proxy_enabled": TRUST_PROXY,
        },
    })


if __name__ == "__main__":
    app.run(debug=True)