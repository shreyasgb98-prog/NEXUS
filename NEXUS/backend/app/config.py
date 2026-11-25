import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
DB_PATH = os.getenv("NEXUS_DB_PATH", str(BASE_DIR / "database" / "nexus.db"))
SIM_DB_PATH = os.getenv("NEXUS_SIM_DB_PATH", str(BASE_DIR / "database" / "nexus_sim.db"))
MIGRATIONS_DIR = BASE_DIR / "backend" / "migrations"
FRONTEND_DIR = BASE_DIR / "frontend"

# Mathematical parameters for statistical detection
EWMA_ALPHA = 0.9
Z_SCORE_THRESHOLD = 3.5
STD_DEV_FLOOR = 0.7
MIN_DEAUTH_COUNT = 3
FIXED_DEAUTH_THRESHOLD = 5
WARMUP_WINDOWS = 30
CORRELATION_SPAN = 3
EVENT_COOLDOWN_WINDOWS = 8

# Confidence scoring constants
CONF_BASE = 0.45
CONF_MULTI_SIGNAL_WEIGHT = 0.20
CONF_ZMAX_WEIGHT = 0.04
CONF_ROGUE_WEIGHT = 0.15
CONF_MAX = 0.99

# Hardware serial interface defaults
DEFAULT_BAUD_RATE = 115200
DEFAULT_SERIAL_TIMEOUT_SEC = 1.0

# RAG and Local LLM configuration
KNOWLEDGE_BASE_DIR = BASE_DIR / "backend" / "knowledge_base"
KNOWLEDGE_CORPUS_PATH = KNOWLEDGE_BASE_DIR / "defensive_corpus.json"
CORPUS_PATH = KNOWLEDGE_CORPUS_PATH
RAG_INDEX_DIR = BASE_DIR / "database" / "rag_index"
OLLAMA_DEFAULT_URL = os.getenv("NEXUS_OLLAMA_URL", "http://localhost:11434")
OLLAMA_DEFAULT_MODEL = os.getenv("NEXUS_OLLAMA_MODEL", "llama3.2")
LLAMA_CPP_DEFAULT_URL = os.getenv("NEXUS_LLAMA_CPP_URL", "http://localhost:8080/v1/chat/completions")
LLAMA_CPP_MODEL_PATH = os.getenv("NEXUS_LLAMA_CPP_MODEL_PATH", None)
DEFAULT_LLM_TIMEOUT_SEC = float(os.getenv("NEXUS_LLM_TIMEOUT_SEC", "60.0"))
