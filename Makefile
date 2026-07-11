.PHONY: install run scan sast test lint clean

VENV ?= .venv
PY   := $(VENV)/bin/python
PIP  := $(VENV)/bin/pip
URL  ?= http://localhost:5000

install:  ## Crea el venv e instala dependencias
	python3 -m venv $(VENV)
	$(PIP) install -q -r requirements.txt

run:  ## Levanta VulnShop en localhost:5000
	$(PY) vulnshop/app.py

scan:  ## Ejecuta el DAST scanner contra $(URL)
	$(PY) dast_scanner/dast_scanner.py --url $(URL)

sast:  ## Análisis estático con Bandit sobre el código del repo
	$(VENV)/bin/bandit -r vulnshop dast_scanner -f json -o sast/bandit_selfscan.json || true

test:  ## Ejecuta la suite de tests
	$(PY) -m pytest tests/ -q

clean:  ## Elimina artefactos generados
	rm -rf $(VENV) reports/dast_report.html reports/dast_report.json
	find . -type d -name __pycache__ -exec rm -rf {} +
