"""Tests del DAST scanner — lógica de reporte y regresión de seguridad.

Estos tests no requieren un servidor: ejercitan directamente el objeto
`DASTScanner`, incluyendo la regresión del XSS en el reporte HTML.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dast_scanner"))

from dast_scanner import DASTScanner  # noqa: E402


@pytest.fixture
def scanner():
    s = DASTScanner("http://localhost:5000")
    s._add("XSS Reflected (GET)", "HIGH", "http://x/s?q=<script>alert(1)</script>",
           "XSS reflejado", "<script>alert('XSS')</script>")
    s._add("Insecure Cookie", "MEDIUM", "http://x/profile", "Cookie insegura", "session=1")
    s._add("Missing Security Headers", "LOW", "http://x/", "Falta CSP")
    return s


def test_severity_counts(scanner):
    counts = scanner.severity_counts()
    assert counts == {"HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 0}


def test_html_report_escapes_payloads(scanner, tmp_path):
    """Regresión: el reporte HTML no debe incrustar payloads sin escapar,
    o el propio reporte sería vulnerable a XSS al abrirse en el navegador."""
    out = tmp_path / "report.html"
    scanner.save_html(str(out))
    content = out.read_text()

    # El payload crudo NO debe aparecer como HTML ejecutable...
    assert "<script>alert('XSS')</script>" not in content
    # ...sino escapado.
    assert "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;" in content


def test_json_report_has_summary(scanner, tmp_path):
    out = tmp_path / "report.json"
    scanner.save_json(str(out))
    data = json.loads(out.read_text())

    assert data["total_findings"] == 3
    assert data["severity_summary"]["HIGH"] == 1
    assert len(data["findings"]) == 3
