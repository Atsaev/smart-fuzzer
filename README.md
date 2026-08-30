# Smart Fuzzer

LLM-powered fuzzer for finding vulnerabilities in Python functions.

## Description

Smart Fuzzer analyzes Python functions using LLM (DeepSeek) to generate intelligent test cases, runs them automatically, and produces a security report with found vulnerabilities and recommendations.

## Live Demo

- **UI (лаборатория):** https://atsaev-dev.ru/fuzzer/
- **API docs:** https://atsaev-dev.ru/fuzzer/docs

## Architecture

```
function
   ↓
LLM test generation    — DeepSeek: input_data + structured expected + postconditions
   ↓
Validator              — drops invalid tests (JSON types, signature mismatch, unjustified exceptions)
   ↓
Blind oracle           — recomputes expected from the contract WITHOUT the function body
   ↓
Sandbox executor       — RestrictedPython, separate process, resource limits, timeout
   ↓
Deterministic comparator — PASS / VULNERABILITY / ERROR (code, not LLM)
   ↓
LLM summary            — explains the verdicts, does not decide them
```

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
  "function_name": "safe_divide",
  "total_tests": 10,
  "passed": 9,
  "failed": 0,
  "errors": 0,
  "vulnerabilities": [...],
  "results": [
    {
      "test_case": {
        "input_data": {"a": 10, "b": 0},
        "expected": {"type": "exception", "name": "ValueError"}
      },
      "status": "passed",
      "actual_output": null
    },
    {
      "test_case": {
        "input_data": {"a": 1e308, "b": 1e-308},
        "expected": {"type": "return", "value": "inf"}
      },
      "status": "passed",
      "actual_output": "inf"
    }
  ],
  "summary": "..."
}
```

Verdicts are decided by a deterministic comparator, not the LLM:
`PASS`, `VULNERABILITY` (actual result deviates from the contract), `ERROR` (sandbox/environment issue).

## Security

The API executes user code only inside a sandbox: RestrictedPython blocks import statements and private attribute access at compile time, execution runs in a separate process with resource limits (CPU, memory, processes, fds), privileges are dropped to nobody, and a hard timeout kills the process. Whitelisted stdlib modules without I/O can be imported inside the analyzed function via import_module, e.g. json = import_module('json').

## Project Structure
```
smart-fuzzer/
├── fuzzer/
│   ├── generator.py    — LLM test case generation
│   ├── runner.py       — test execution engine
│   └── sandbox.py      — isolated execution of user code
├── models/
│   └── schemas.py      — Pydantic models
├── reports/
│   └── reporter.py     — report generation
├── api/
│   └── main.py         — FastAPI application
└── main.py             — entry point
```