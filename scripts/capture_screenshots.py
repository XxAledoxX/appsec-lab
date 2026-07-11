#!/usr/bin/env python3
"""Genera capturas de pantalla para el README: VulnShop + reporte DAST.

Requiere VulnShop corriendo en localhost:5000 y un reporte HTML generado
en reports/dast_report.html. Usa Playwright (Chromium headless).

USO:
    python scripts/capture_screenshots.py
"""

import pathlib
import sys

from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "docs" / "screenshots"
BASE_URL = "http://localhost:5000"

SHOTS = [
    ("vulnshop-home.png", f"{BASE_URL}/", False),
    ("vulnshop-search-xss.png", f"{BASE_URL}/search?q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E", False),
    ("dast-report.png", (ROOT / "reports" / "dast_report.html").as_uri(), True),
]


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 500})
        for filename, url, full_page in SHOTS:
            try:
                page.goto(url, wait_until="networkidle", timeout=10_000)
                if not full_page:
                    height = page.evaluate("document.body.scrollHeight")
                    page.set_viewport_size({"width": 1280, "height": min(height, 700)})
                page.screenshot(path=str(OUT_DIR / filename), full_page=full_page)
                print(f"[*] Guardado {OUT_DIR / filename}")
            except Exception as e:
                print(f"[!] Error capturando {url}: {e}", file=sys.stderr)
        browser.close()


if __name__ == "__main__":
    main()
