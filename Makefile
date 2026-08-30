.PHONY: install run-dashboard run-api test docker-build docker-up clean generate-data

install:
	pip install -r requirements.txt

run-dashboard:
	streamlit run app.py

run-api:
	uvicorn src.api.routes:app --reload --host 0.0.0.0 --port 8000

test:
	pytest

generate-data:
	python data/generate_sample_data.py

docker-build:
	docker compose build

docker-up:
	docker compose up -d

clean:
	rm -rf __pycache__ .pytest_cache *.db logs/
