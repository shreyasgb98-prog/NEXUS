# NEXUS AI

**Passive Defensive RF Telemetry & Anomaly Detection Workstation**

NEXUS AI is a local-first wireless telemetry and anomaly detection dashboard designed to ingest real-time RF metrics from an ESP32-S3 hardware sensor over serial (`115200` baud) or run deterministic replay/simulation sessions.

## Architecture Stack

- **Backend:** FastAPI (`uvicorn`) with EWMA + Z-score statistical anomaly detection, cross-signal correlation, and incident management
- **Storage:** SQLite3 in WAL mode (`PRAGMA journal_mode = WAL;`) with sequential SQL migrations
- **Frontend:** Vanilla HTML5, CSS3, Canvas telemetry plots, and Web Serial API (classic Win32 engineering workstation UI)
- **Local RAG & Assistant:** Local Ollama (`llama3.2`) / `llama.cpp` integration backed by `defensive_corpus.json`

## Quickstart

1. **Create and activate a Python virtual environment:**
   ```bash
   python -m venv .venv
   # Windows PowerShell:
   .venv\Scripts\Activate.ps1
   # Linux/macOS:
   source .venv/bin/activate
   ```

2. **Install backend dependencies:**
   ```bash
   pip install -r NEXUS/backend/requirements.txt
   ```

3. **Start the dashboard server:**
   ```bash
   cd NEXUS/backend
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```

4. **Open the workstation UI:**
   Navigate to `http://127.0.0.1:8000` in a Chromium-based browser (required for Web Serial API hardware connectivity).

## Local Llama AI Assistant (Ollama / llama.cpp)

The incident assistant uses a local LLM backed by the defensive RAG corpus (`NEXUS/backend/knowledge_base/defensive_corpus.json`).

### Option A: Ollama (Default)

1. Install [Ollama](https://ollama.com/) and pull the default model:
   ```bash
   ollama pull llama3.2
   ```
2. Start the Ollama server (if not already running as a background service):
   ```bash
   ollama serve
   ```
   By default, NEXUS AI connects to `http://localhost:11434` using model `llama3.2`. You can override these with `NEXUS_OLLAMA_URL` and `NEXUS_OLLAMA_MODEL`.

### Option B: llama.cpp Server

Start `llama-server` with an OpenAI-compatible endpoint on port `8080`:
```bash
llama-server -m /path/to/model.gguf --port 8080
```
NEXUS AI checks `http://localhost:8080/v1/chat/completions` by default (configurable via `NEXUS_LLAMA_CPP_URL`).

## Database Initialization

Runtime SQLite databases (`NEXUS/database/nexus.db` and `NEXUS/database/nexus_sim.db`) are excluded from version control and auto-initialize from `NEXUS/backend/migrations/` (`001_` through `009_`) on first startup.

## Running Tests

From `NEXUS/backend/`:
```bash
pytest tests/
```
