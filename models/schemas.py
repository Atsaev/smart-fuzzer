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


class TestCase(BaseModel):
    input_data: dict
    expected: Expected
    category: str = ""
    reason: str = ""

    @property
    def expected_behavior(self) -> str:
        if self.expected.type == "exception":
            return f"raises {self.expected.name}" if self.expected.name else "raises exception"
        return f"returns {self.expected.value!r}"


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
