# LogSentinel AI — Installation & Setup Guide

## System Requirements

- Python 3.11+ (Python 3.11 or 3.12 recommended)
- Git
- Docker & Docker Compose (Optional for containerized deployment)

---

## 1. Local Setup

### Clone Repository
```bash
git clone https://github.com/your-username/LogSentinel-AI.git
cd LogSentinel-AI
```

### Create Virtual Environment

**Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 2. Generate Demo Dataset
```bash
python data/generate_sample_data.py
```

---

## 3. Run Application

### Launch Streamlit SOC Dashboard
```bash
streamlit run app.py
```
Open browser at: `http://localhost:8501`

### Launch FastAPI REST API Server
```bash
uvicorn src.api.routes:app --reload --host 0.0.0.0 --port 8000
```
API Documentation (Swagger UI) at: `http://localhost:8000/docs`

---

## 4. Run Test Suite
```bash
pytest
```

---

## 5. Docker Deployment

```bash
docker compose up --build -d
```
- Dashboard: `http://localhost:8501`
- API Docs: `http://localhost:8000/docs`
