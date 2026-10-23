.PHONY: install test evaluate build serve decoy clean

install:
	cd backend && pip install -r requirements-dev.txt
	cd frontend && npm install --no-audit --no-fund

test:
	cd backend && python -m pytest -q

evaluate:
	cd backend && python scripts/evaluate.py

build:
	cd frontend && npm run build

serve:
	cd backend && uvicorn app.main:app --host 127.0.0.1 --port 8000

decoy:
	cd backend && python -m app.cli decoy --host 127.0.0.1 --port 8022

clean:
	rm -rf backend/.pytest_cache backend/__pycache__ backend/app/__pycache__ frontend/dist
