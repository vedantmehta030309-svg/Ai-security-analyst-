# AI Security Analyst

College prototype: parse Linux journal/auth-style logs, detect suspicious SSH activity, correlate attack sequences, score risk, optionally flag anomalies, then explain incidents in human language.

## Pipeline

Logs → parser → SSH enrichment → detectors → correlation → **risk_score.py** → ML prototype (optional) → AI analyst → report / dashboard

`risk_score.py` is the only numerical risk engine. AI/ML do not replace detection, correlation, or scoring.

## How to run

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

python main.py
python -m unittest discover -s tests
streamlit run dashboard.py
```

`config.json` points at `data/test_log_1.txt` by default.

Disable extras without touching the core pipeline:

- `"ai_analyst": { "enabled": false }`
- `"ml_anomaly": { "enabled": false }`

Optional LLM explanations (otherwise offline templates are used):

- set `AI_ANALYST_API_KEY` (or `OPENAI_API_KEY`)
- set `"mode": "llm"` under `ai_analyst` in `config.json`
- optional: `AI_ANALYST_BASE_URL`, `AI_ANALYST_MODEL`

Do not put API keys in source files.

## Outputs

- `alerts.json` — detector alerts + correlated incidents + risk (+ ML/AI fields when enabled)
- `correlation_incidents.json` — correlation engine output
- `ai_analysis.json` — human-readable incident explanations

## ML note

The Isolation Forest module is a **prototype** trained on synthetic “typical auth” baselines because the sample logs are small and attack-heavy. It is for demonstration and viva explanation, not a production accuracy claim.
