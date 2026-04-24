import textwrap

from dotenv import load_dotenv
from fastapi import Body, FastAPI, HTTPException

from fuzzer.generator import generate_test_cases
from fuzzer.runner import run_all_tests
from models.schemas import FuzzReport
from reports.reporter import generate_report

load_dotenv()

app = FastAPI(
    title="Smart fuzzer inspector",
    description="Инспектор функций для поиска уязвимостей",
    version="1.0",
)

FORBIDDEN = ["import os", "import sys", "import subprocess", "exec", "eval", "__import__"]

@app.post("/fuzzer_test", response_model=FuzzReport)
async def fuzzer_test(function_code: str = Body(..., media_type="text/plain")):
    for pattern in FORBIDDEN:
        if pattern in function_code:
            raise HTTPException(
                status_code=400,
                detail=f"Запрещённая конструкция: {pattern}"
            )
    try:
        namespace = {}
        exec(function_code, namespace)

        func = None
        for name, obj in namespace.items():
            if callable(obj) and not name.startswith("_"):
                func = obj
                func_name = name
                break

        if func is None:
            raise HTTPException(
                status_code=400, detail="Не удалось найти тестируемую функцию"
            )

        code = textwrap.dedent(function_code)
        test_cases = generate_test_cases(code, func_name)
        results = run_all_tests(func, test_cases)
        report = generate_report(func_name, results)
        return report

    except SyntaxError as e:
        raise HTTPException(status_code=400, detail=f"Синтаксическая ошибка: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка фаззинга: {e}")
