import ast
import textwrap

from dotenv import load_dotenv
from fastapi import Body, FastAPI, HTTPException

from fuzzer.generator import generate_test_cases
from fuzzer.sandbox import SandboxError, run_all_tests_sandboxed, validate_code
from models.schemas import FuzzReport
from reports.reporter import generate_report

load_dotenv()

app = FastAPI(
    title="Smart fuzzer inspector",
    description="Инспектор функций для поиска уязвимостей",
    version="1.1",
)


def _detect_function_name(code: str) -> str:
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        raise HTTPException(status_code=400, detail=f"Синтаксическая ошибка: {e}")
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node.name
    raise HTTPException(status_code=400, detail="Не удалось найти тестируемую функцию")


@app.post("/fuzzer_test", response_model=FuzzReport)
def fuzzer_test(function_code: str = Body(..., media_type="text/plain")):
    try:
        code = textwrap.dedent(function_code)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Ошибка отступов: {e}")

    # ранняя проверка без исполнения: import и опасные конструкции отсекаются
    try:
        validate_code(code)
    except SyntaxError as e:
        raise HTTPException(status_code=400, detail=f"Запрещённая конструкция: {e}")

    try:
        func_name = _detect_function_name(code)
        test_cases = generate_test_cases(code, func_name)
        results = run_all_tests_sandboxed(code, func_name, test_cases)
        return generate_report(func_name, results)
    except SandboxError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка фаззинга: {e}")
