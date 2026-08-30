from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel


class TestStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    VULNERABILITY = "vulnerability"


class Expected(BaseModel):
    """Структурированное ожидание — классификатор работает только с ним."""
    type: Literal["return", "exception"]
    value: Any = None        # для type="return" (null означает ожидание None)
    name: str | None = None  # для type="exception"; None = любое исключение


class Postconditions(BaseModel):
    """Пост-условия на входные данные после вызова."""
    inputs_unchanged: bool | None = None  # функция НЕ должна менять входы
    input_data: dict | None = None        # ожидаемое состояние входов по именам параметров


class TestCase(BaseModel):
    input_data: dict | list = {}   # dict — один вызов; list[dict] — последовательность
    expected: Expected | list[Expected]
    category: str = ""
    reason: str = ""
    postconditions: Postconditions | None = None

    @property
    def is_sequence(self) -> bool:
        return isinstance(self.expected, list)

    @property
    def expected_behavior(self) -> str:
        if isinstance(self.expected, list):
            return " | ".join(
                f"{e.type}:{e.name if e.type == 'exception' else e.value!r}"
                for e in self.expected
            )
        e = self.expected
        if e.type == "exception":
            return f"raises {e.name}" if e.name else "raises exception"
        return f"returns {e.value!r}"


class TestResult(BaseModel):
    test_case: TestCase
    status: TestStatus
    actual_output: str | None = None
    error_message: str | None = None
    is_vulnerability: bool = False


class FuzzReport(BaseModel):
    function_name: str
    total_tests: int
    passed: int
    failed: int
    errors: int
    vulnerabilities: list[TestResult]
    summary: str


class FuzzerRequest(BaseModel):
    function_code: str
