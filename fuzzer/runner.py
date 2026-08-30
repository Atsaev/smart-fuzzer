import inspect
import math
import re

from models.schemas import TestCase, TestResult, TestStatus

_EXCEPTION_RE = re.compile(
    r"\b(TypeError|ValueError|KeyError|IndexError|ZeroDivisionError|"
    r"AttributeError|OverflowError|RuntimeError|StopIteration|AssertionError|"
    r"ImportError|NameError|OSError|PermissionError|TimeoutError|"
    r"FileNotFoundError|UnicodeDecodeError|UnicodeEncodeError|UnicodeError|"
    r"RecursionError|MemoryError|ArithmeticError|LookupError|EOFError|"
    r"NotImplementedError|SyntaxError|IndentationError|TabError)\b",
    re.IGNORECASE,
)
_EXCEPTION_HINT = re.compile(
    r"\braise\b|\bexception\b|\bбросает\b|\bошибк\b", re.IGNORECASE
)

_QUOTED_VALUE_RE = re.compile(r"['\"]([^'\"]*)['\"]")
_BOOL_VALUE_RE = re.compile(r"\b(True|False|true|false)\b")
_NUMBER_VALUE_RE = re.compile(r"[-+]?\d+\.?\d*")

_RETURN_MARKER = "RETURN"


def _parse_expectation(expected_behavior: str):
    """Что ждёт тест: исключение (какого типа) или возврат значения."""
    m = _EXCEPTION_RE.search(expected_behavior)
    if m or _EXCEPTION_HINT.search(expected_behavior):
        return m.group(0) if m else None
    return _RETURN_MARKER


def _parse_expected_value(expected_behavior: str):
    """Конкретное ожидаемое значение из текста ожидания или None.

    "returns 'a@b.c'" -> 'a@b.c'; "returns 90" -> 90; "возвращает True" -> True.
    """
    m = _QUOTED_VALUE_RE.search(expected_behavior)
    if m:
        return m.group(1)
    m = _BOOL_VALUE_RE.search(expected_behavior)
    if m:
        return m.group(0).lower() == "true"
    m = _NUMBER_VALUE_RE.search(expected_behavior)
    if m:
        token = m.group(0)
        return float(token) if "." in token else int(token)
    return None


def _values_match(expected, actual):
    """Сравнение ожидаемого и фактического значения.

    True — совпало; False — не совпало; None — значения несопоставимы.
    """
    if isinstance(expected, bool) or isinstance(actual, bool):
        if isinstance(expected, bool) and isinstance(actual, bool):
            return expected == actual
        return None
    if isinstance(expected, (int, float)) and isinstance(actual, (int, float)):
        return math.isclose(
            float(expected), float(actual), rel_tol=1e-6, abs_tol=1e-9
        )
    if isinstance(expected, str) and isinstance(actual, str):
        return expected.strip() == actual.strip()
    return None


def _classify(test_case: TestCase, exc: BaseException | None, actual_value=None):
    """Строгая классификация результата теста.

    Исключения:
      expected: TypeError, actual: TypeError   -> PASS
      expected: ValueError, actual: TypeError  -> FAIL
      expected: return,      actual: exception -> VULNERABILITY
      expected: exception,   actual: return    -> FAIL

    Возвращаемые значения:
      expected: 90, actual: 90   -> PASS
      expected: 90, actual: -900 -> VULNERABILITY (сломана семантика)
    """
    expected = _parse_expectation(test_case.expected_behavior)

    if exc is None:
        if expected != _RETURN_MARKER:
            return TestStatus.FAILED, False
        expected_value = _parse_expected_value(test_case.expected_behavior)
        if expected_value is not None:
            match = _values_match(expected_value, actual_value)
            if match is False:
                return TestStatus.VULNERABILITY, True
        return TestStatus.PASSED, False

    actual_name = type(exc).__name__
    if expected == _RETURN_MARKER:
        return TestStatus.VULNERABILITY, True
    if expected is None or expected.lower() == actual_name.lower():
        return TestStatus.PASSED, False
    return TestStatus.FAILED, False


def _build_call(func, input_data):
    """Собирает аргументы вызова по сигнатуре функции.

    {"value": "8080"} для функции с одним параметром превращается в
    позиционный аргумент "8080"; dict с несколькими ключами передаётся
    целиком (типично для функций, принимающих dict).
    """
    try:
        params = list(inspect.signature(func).parameters.values())
    except (ValueError, TypeError):
        params = []

    positional = [
        p for p in params
        if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
    ]
    has_var_kw = any(p.kind == p.VAR_KEYWORD for p in params)
    has_var_args = any(p.kind == p.VAR_POSITIONAL for p in params)

    if not positional and not has_var_args:
        return (), (dict(input_data) if isinstance(input_data, dict) else {})

    if len(positional) == 1 and not has_var_kw:
        if isinstance(input_data, dict) and len(input_data) == 1:
            value = next(iter(input_data.values()))
        else:
            value = input_data
        return (value,), {}

    if has_var_args and not positional:
        return (input_data,), {}

    if isinstance(input_data, dict):
        return (), dict(input_data)

    return (input_data,), {}


def run_test(func, test_case: TestCase) -> TestResult:
    args, kwargs = _build_call(func, test_case.input_data)
    try:
        result = func(*args, **kwargs)
        status, is_vuln = _classify(test_case, None, result)
        return TestResult(
            test_case=test_case,
            status=status,
            actual_output=str(result),
            is_vulnerability=is_vuln,
        )
    except Exception as e:
        status, is_vuln = _classify(test_case, e)
        return TestResult(
            test_case=test_case,
            status=status,
            error_message=f"{type(e).__name__}: {e}",
            is_vulnerability=is_vuln,
        )


def run_all_tests(func, test_cases: list[TestCase]) -> list[TestResult]:
    results = []
    for i, test_case in enumerate(test_cases, 1):
        print(f"-> Тест {i}/{len(test_cases)}: {test_case.category}")
        result = run_test(func, test_case)
        results.append(result)
    return results
