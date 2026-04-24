# Smart Fuzzer

LLM-powered fuzzer for finding vulnerabilities in Python functions.

## Description

Smart Fuzzer analyzes Python functions using LLM (DeepSeek) to generate intelligent test cases, runs them automatically, and produces a security report with found vulnerabilities and recommendations.

## Live Demo
API is available at http://89.125.91.14:8003/docs

## Architecture
Python function code
⬇️
LLM generates test cases    — DeepSeek analyzes the function and creates edge cases
⬇️
Runner executes tests       — runs each test case and catches exceptions
⬇️
Reporter generates report   — LLM summarizes findings and recommendations

## Stack

- Python 3.12
- DeepSeek — LLM provider
- FastAPI — REST API
- Pydantic — data validation
- pytest — testing

## Quick Start

1. Clone the repository:
```bash
   git clone https://github.com/Atsaev/smart-fuzzer.git
   cd smart-fuzzer
```

2. Install dependencies:
```bash
   uv sync
```

3. Create `.env` file:
DEEPSEEK_API_KEY=your_key_here

4. Run via script:
```bash
   uv run main.py
```

5. Or run API:
```bash
   uv run uvicorn api.main:app --reload
```

6. Open docs:
http://localhost:8000/docs

## API

### POST /fuzzer_test

Send a Python function as plain text — the fuzzer will analyze it and return a report.

Example:
```python
def divide(a, b):
    return a / b
```

Response:
```json
{
  "function_name": "divide",
  "total_tests": 5,
  "passed": 2,
  "failed": 1,
  "errors": 2,
  "vulnerabilities": [...],
  "summary": "Found 2 vulnerabilities: ZeroDivisionError..."
}
```

## Security

The API blocks dangerous constructs: `import os`, `import sys`, `import subprocess`, `exec`, `eval`, `__import__`.

## Project Structure
```
smart-fuzzer/
├── fuzzer/
│   ├── generator.py    — LLM test case generation
│   └── runner.py       — test execution engine
├── models/
│   └── schemas.py      — Pydantic models
├── reports/
│   └── reporter.py     — report generation
├── api/
│   └── main.py         — FastAPI application
└── main.py             — entry point
```