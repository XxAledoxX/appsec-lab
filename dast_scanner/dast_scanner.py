#!/usr/bin/env python3
"""
DAST Scanner — Escáner de vulnerabilidades web black-box.

Detecta: XSS Reflected (GET/POST), Header/CRLF Injection, Open Redirect,
Insecure Cookies, Information Disclosure, Missing Security Headers.

USO: python dast_scanner.py --url http://localhost:5000
ADVERTENCIA: Solo para uso en entornos autorizados y laboratorios controlados.
"""

import argparse
import json
import sys
import datetime
import requests
from urllib.parse import urljoin, urlencode

requests.packages.urllib3.disable_warnings()

TIMEOUT = 10
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "'><svg/onload=alert(1)>",
]
CRLF_PAYLOADS = [
    "test\r\nX-Injected: pwned",
    "test\r\nSet-Cookie: injected=1",
    "test%0d%0aX-Injected: pwned",
]
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com%2F@localhost",
]
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


class Finding:
    def __init__(self, module, severity, url, detail, evidence=""):
        self.module = module
        self.severity = severity
        self.url = url
        self.detail = detail
        self.evidence = evidence

    def to_dict(self):
        return {
            "module": self.module,
            "severity": self.severity,
            "url": self.url,
            "detail": self.detail,
            "evidence": self.evidence,
        }


class DASTScanner:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.verify = False
        self.findings = []

    def _get(self, path, params=None):
        try:
            return self.session.get(urljoin(self.base_url, path), params=params, timeout=TIMEOUT, allow_redirects=False)
        except requests.RequestException as e:
            print(f"  [!] Error GET {path}: {e}")
            return None

    def _post(self, path, data=None):
        try:
            return self.session.post(urljoin(self.base_url, path), data=data, timeout=TIMEOUT, allow_redirects=False)
        except requests.RequestException as e:
            print(f"  [!] Error POST {path}: {e}")
            return None

    def _add(self, module, severity, url, detail, evidence=""):
        f = Finding(module, severity, url, detail, evidence)
        self.findings.append(f)
        tag = {"HIGH": "[HIGH]", "MEDIUM": "[MED] ", "LOW": "[LOW] ", "INFO": "[INFO]"}[severity]
        print(f"  {tag} {detail}")

    # ── Módulo 1: XSS Reflected (GET) ────────────────────────────────────────
    def check_xss_get(self):
        print("\n[*] Módulo 1 — XSS Reflected (GET)")
        endpoints = [("/search", "q"), ("/redirect", "url")]
        for path, param in endpoints:
            for payload in XSS_PAYLOADS:
                resp = self._get(path, params={param: payload})
                if resp and payload in resp.text:
                    self._add(
                        "XSS Reflected (GET)", "HIGH",
                        f"{self.base_url}{path}?{param}={payload}",
                        f"XSS reflejado en {path} (param: {param})",
                        payload,
                    )
                    break

    # ── Módulo 2: XSS Reflected (POST) ───────────────────────────────────────
    def check_xss_post(self):
        print("\n[*] Módulo 2 — XSS Reflected (POST)")
        endpoints = [
            ("/comment", {"name": "", "message": ""}),
        ]
        for path, fields in endpoints:
            for field in fields:
                for payload in XSS_PAYLOADS:
                    data = {k: "test" for k in fields}
                    data[field] = payload
                    resp = self._post(path, data=data)
                    if resp and payload in resp.text:
                        self._add(
                            "XSS Reflected (POST)", "HIGH",
                            f"{self.base_url}{path}",
                            f"XSS reflejado en {path} (campo: {field})",
                            payload,
                        )
                        break

    # ── Módulo 3: Header / CRLF Injection ────────────────────────────────────
    def check_crlf_injection(self):
        print("\n[*] Módulo 3 — Header / CRLF Injection")
        endpoints = [
            ("/login", "POST", {"username": "", "password": "test"}),
            ("/newsletter", "POST", {"email": "a@b.com", "lang": ""}),
        ]
        injected_field = {"username": True, "lang": True}

        for path, method, base_data in endpoints:
            for field, _ in injected_field.items():
                if field not in base_data:
                    continue
                for payload in CRLF_PAYLOADS:
                    data = dict(base_data)
                    data[field] = payload
                    resp = self._post(path, data=data)
                    if resp is None:
                        continue
                    # Werkzeug/Flask moderno rechaza headers con CRLF — detectamos el intento
                    injected_header = "x-injected"
                    if injected_header in (k.lower() for k in resp.headers):
                        self._add(
                            "CRLF Injection", "HIGH",
                            f"{self.base_url}{path}",
                            f"CRLF injection exitosa en {path} (campo: {field})",
                            payload,
                        )
                        break
                    else:
                        # Si el payload llega al header sin sanitizar (versiones antiguas)
                        # o si el servidor lo acepta parcialmente
                        raw_header_val = resp.headers.get("X-Logged-User", "") or resp.headers.get("Content-Language", "")
                        if "\r\n" in raw_header_val or "\n" in raw_header_val or "pwned" in raw_header_val:
                            self._add(
                                "CRLF Injection", "HIGH",
                                f"{self.base_url}{path}",
                                f"CRLF injection — valor sin sanitizar en header de respuesta ({path}, campo: {field})",
                                payload,
                            )
                            break
                        elif payload.split("\r\n")[0] in raw_header_val:
                            self._add(
                                "Header Injection (punto de inyección)", "MEDIUM",
                                f"{self.base_url}{path}",
                                f"Input del usuario reflejado sin sanitizar en header de respuesta ({path}, campo: {field})",
                                f"Header value: {raw_header_val!r}",
                            )
                            break

    # ── Módulo 4: Open Redirect ───────────────────────────────────────────────
    def check_open_redirect(self):
        print("\n[*] Módulo 4 — Open Redirect")
        for payload in REDIRECT_PAYLOADS:
            resp = self._get("/redirect", params={"url": payload})
            if resp is None:
                continue
            location = resp.headers.get("Location", "")
            if "evil.com" in location or location.startswith("//"):
                self._add(
                    "Open Redirect", "HIGH",
                    f"{self.base_url}/redirect?url={payload}",
                    "Open Redirect — redirección a dominio externo sin validación",
                    f"Location: {location}",
                )
                break

    # ── Módulo 5: Insecure Cookies ────────────────────────────────────────────
    def check_insecure_cookies(self):
        print("\n[*] Módulo 5 — Insecure Cookies")
        resp = self._get("/profile")
        if resp is None:
            return
        for cookie in resp.cookies:
            issues = []
            if not cookie.has_nonstandard_attr("HttpOnly") and not getattr(cookie, "_rest", {}).get("HttpOnly"):
                issues.append("sin HttpOnly")
            if not cookie.secure:
                issues.append("sin Secure")
            if not cookie.has_nonstandard_attr("SameSite") and "samesite" not in str(cookie).lower():
                issues.append("sin SameSite")
            if issues:
                self._add(
                    "Insecure Cookie", "MEDIUM",
                    f"{self.base_url}/profile",
                    f"Cookie '{cookie.name}': {', '.join(issues)}",
                    str(cookie),
                )

        # Inspeccionar Set-Cookie en headers raw
        set_cookie = resp.headers.get("Set-Cookie", "")
        if set_cookie:
            issues = []
            if "httponly" not in set_cookie.lower():
                issues.append("sin HttpOnly")
            if "secure" not in set_cookie.lower():
                issues.append("sin Secure")
            if "samesite" not in set_cookie.lower():
                issues.append("sin SameSite")
            if issues:
                self._add(
                    "Insecure Cookie", "MEDIUM",
                    f"{self.base_url}/profile",
                    f"Set-Cookie header inseguro: {', '.join(issues)}",
                    set_cookie,
                )

    # ── Módulo 6: Information Disclosure ─────────────────────────────────────
    def check_info_disclosure(self):
        print("\n[*] Módulo 6 — Information Disclosure")
        resp = self._get("/")
        if resp is None:
            return
        for header in ["Server", "X-Powered-By"]:
            value = resp.headers.get(header, "")
            if value:
                self._add(
                    "Information Disclosure", "LOW",
                    self.base_url,
                    f"Header '{header}' revela tecnología: {value}",
                    f"{header}: {value}",
                )

    # ── Módulo 7: Missing Security Headers ───────────────────────────────────
    def check_missing_security_headers(self):
        print("\n[*] Módulo 7 — Missing Security Headers")
        resp = self._get("/")
        if resp is None:
            return
        for header in SECURITY_HEADERS:
            if header not in resp.headers:
                self._add(
                    "Missing Security Headers", "LOW",
                    self.base_url,
                    f"Header de seguridad ausente: {header}",
                )

    # ── Ejecución y reporte ───────────────────────────────────────────────────
    def run(self):
        print(f"[*] DAST Scanner iniciado — target: {self.base_url}")
        print(f"[*] {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        self.check_xss_get()
        self.check_xss_post()
        self.check_crlf_injection()
        self.check_open_redirect()
        self.check_insecure_cookies()
        self.check_info_disclosure()
        self.check_missing_security_headers()

        print(f"\n[*] Escaneo completado. Hallazgos: {len(self.findings)}")
        return self.findings

    def save_json(self, path="reports/dast_report.json"):
        data = {
            "target": self.base_url,
            "timestamp": datetime.datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }
        with open(path, "w") as fp:
            json.dump(data, fp, indent=2, ensure_ascii=False)
        print(f"[*] Reporte JSON guardado: {path}")

    def save_html(self, path="reports/dast_report.html"):
        severity_color = {"HIGH": "#e74c3c", "MEDIUM": "#e67e22", "LOW": "#f1c40f", "INFO": "#3498db"}
        rows = ""
        for f in self.findings:
            color = severity_color.get(f.severity, "#999")
            rows += f"""
            <tr>
                <td style="color:{color};font-weight:bold">{f.severity}</td>
                <td>{f.module}</td>
                <td style="word-break:break-all">{f.url}</td>
                <td>{f.detail}</td>
                <td><code>{f.evidence}</code></td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>DAST Report — {self.base_url}</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 40px; background: #f9f9f9; }}
  h1 {{ color: #2c3e50; }}
  table {{ border-collapse: collapse; width: 100%; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  th {{ background: #2c3e50; color: white; padding: 10px; text-align: left; }}
  td {{ padding: 9px 10px; border-bottom: 1px solid #eee; vertical-align: top; }}
  tr:hover {{ background: #f0f0f0; }}
  .meta {{ color: #666; margin-bottom: 20px; }}
</style>
</head>
<body>
<h1>Reporte DAST</h1>
<p class="meta">Target: <strong>{self.base_url}</strong> &nbsp;|&nbsp; Fecha: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; Hallazgos: <strong>{len(self.findings)}</strong></p>
<table>
  <tr><th>Severidad</th><th>Módulo</th><th>URL</th><th>Detalle</th><th>Evidencia</th></tr>
  {rows}
</table>
</body>
</html>"""
        with open(path, "w") as fp:
            fp.write(html)
        print(f"[*] Reporte HTML guardado: {path}")


def main():
    parser = argparse.ArgumentParser(description="DAST Scanner para VulnShop (uso en laboratorio autorizado)")
    parser.add_argument("--url", required=True, help="URL base del target (ej: http://localhost:5000)")
    parser.add_argument("--json", default="reports/dast_report.json", help="Ruta de salida JSON")
    parser.add_argument("--html", default="reports/dast_report.html", help="Ruta de salida HTML")
    args = parser.parse_args()

    scanner = DASTScanner(args.url)
    scanner.run()
    scanner.save_json(args.json)
    scanner.save_html(args.html)


if __name__ == "__main__":
    main()
