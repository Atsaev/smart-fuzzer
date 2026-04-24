from enum import Enum

from pydantic import BaseModel


class TestStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"


class TestCase(BaseModel):
    input_data: dict
    expected_behavior: str
    category: str


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
