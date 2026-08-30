"""Детерминированный классификатор: вердикт вычисляется кодом из
структурированного ожидания (TestCase.expected) и фактического результата.
LLM не участвует в принятии решения."""

import copy
import inspect
import math
import re
from dataclasses import dataclass

from models.schemas import Expected, TestCase, TestResult, TestStatus

# Исключения, которые функция бросает на некорректных входных данных:
# их появление там, где ожидался нормальный возврат, — VULNERABILITY.
# Остальное (NameError, AttributeError, ImportError, OSError и т.п.) —
# ошибка окружения или самого кода -> ERROR.
_VULN_EXCEPTIONS = (
    TypeError, ValueError, KeyError, IndexError, ZeroDivisionError,
    OverflowError, ArithmeticError, LookupError, UnicodeError,
    UnicodeDecodeError, UnicodeEncodeError, StopIteration,
)

_ANNOTATION_TYPES = {
    "int": int, "float": (int, float), "str": str, "list": list,
    "dict": dict, "bool": bool, "bytes": bytes, "tuple": tuple, "set": set,
}


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
    if isinstance(expected, dict) and isinstance(actual, dict):
        return expected == actual
    if isinstance(expected, (list, tuple)) and isinstance(actual, (list, tuple)):
        return list(expected) == list(actual)
    return None


def _classify(expected: Expected, exc: BaseException | None, actual_value):
    """Чисто детерминированный вердикт по (контракт, фактический результат)."""
    if exc is None:
        # функция вернула значение
        if expected.type == "exception":
            return TestStatus.VULNERABILITY, True  # ждали исключение — вернулась
        if expected.value is None:
            if actual_value is None:
                return TestStatus.PASSED, False
            return TestStatus.VULNERABILITY, True  # ждали None — вернулось значение
        if actual_value is None:
            return TestStatus.VULNERABILITY, True  # ждали значение — вернулся None
        if _values_match(expected.value, actual_value) is False:
            return TestStatus.VULNERABILITY, True  # неверное значение
        return TestStatus.PASSED, False

    # функция бросила исключение
    if expected.type == "return":
        if isinstance(exc, _VULN_EXCEPTIONS):
            return TestStatus.VULNERABILITY, True
        return TestStatus.ERROR, False

    if expected.name is None:
        return TestStatus.PASSED, False  # ждали любое исключение
    if expected.name.lower() == type(exc).__name__.lower():
        return TestStatus.PASSED, False
    return TestStatus.VULNERABILITY, True  # другой тип исключения


def _check_return_annotation(func_source: str, actual_value) -> str | None:
    """Детерминированная проверка: фактический тип результата против
    аннотации возврата (-> int / -> float / ...). Не зависит от LLM."""
    try:
        tree = ast_parse(func_source)
    except SyntaxError:
        return None
    for node in tree.body:
        if isinstance(node, ast_FunctionDef):
            returns = node.returns
            if returns is None:
                return None
            name = returns.id if isinstance(returns, ast_Name) else None
            if name in _ANNOTATION_TYPES and actual_value is not None:
                if not isinstance(actual_value, _ANNOTATION_TYPES[name]):
                    return (
                        f"возвращаемое значение ({type(actual_value).__name__}) "
                        f"не соответствует аннотации -> {name}"
                    )
            return None
    return None


# алиасы, чтобы не плодить импорты выше
import ast as _ast
ast_parse = _ast.parse
ast_FunctionDef = _ast.FunctionDef
ast_Name = _ast.Name


@dataclass
class _Outcome:
    value: object = None
    exc: BaseException | None = None

    @property
    def error_message(self) -> str | None:
        if self.exc is None:
            return None
        return f"{type(self.exc).__name__}: {self.exc}"


def _invoke(func, args, kwargs) -> _Outcome:
    try:
        return _Outcome(value=func(*args, **kwargs))
    except Exception as e:
        return _Outcome(exc=e)


def _values_equal(a, b) -> bool:
    try:
        if isinstance(a, float) and isinstance(b, float):
            if math.isnan(a) and math.isnan(b):
                return True
            return a == b or math.isclose(a, b, rel_tol=1e-9, abs_tol=1e-12)
        return a == b
    except Exception:
        return True


def _outcomes_equal(o1: _Outcome, o2: _Outcome) -> bool:
    if (o1.exc is None) != (o2.exc is None):
        return False
    if o1.exc is not None:
        return type(o1.exc) is type(o2.exc)
    return _values_equal(o1.value, o2.value)


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


def run_test(func, test_case: TestCase, func_source: str | None = None) -> TestResult:
    """Выполняет тест дважды: проверяет мутацию входных данных и
    стабильность результата при одинаковом входе.

    Детерминированные проверки (не зависят от LLM):
    - вердикт по структурированному ожиданию;
    - соответствие аннотации возврата;
    - мутация входных данных;
    - стабильность результата.
    """
    args, kwargs = _build_call(func, copy.deepcopy(test_case.input_data))
    inputs_snapshot = copy.deepcopy((args, kwargs))

    first = _invoke(func, args, kwargs)
    second = _invoke(func, args, kwargs)

    mutated = (args, kwargs) != inputs_snapshot
    unstable = not _outcomes_equal(first, second)

    status, is_vuln = _classify(test_case.expected, first.exc, first.value)

    if status == TestStatus.PASSED:
        if func_source:
            ann_error = _check_return_annotation(func_source, first.value)
            if ann_error:
                return TestResult(
                    test_case=test_case,
                    status=TestStatus.VULNERABILITY,
                    actual_output=str(first.value) if first.exc is None else None,
                    error_message=ann_error,
                    is_vulnerability=True,
                )
        if unstable:
            return TestResult(
                test_case=test_case,
                status=TestStatus.VULNERABILITY,
                actual_output=str(first.value) if first.exc is None else None,
                error_message="нестабильное поведение: разные результаты при одинаковом входе",
                is_vulnerability=True,
            )
        if mutated:
            return TestResult(
                test_case=test_case,
                status=TestStatus.VULNERABILITY,
                actual_output=str(first.value) if first.exc is None else None,
                error_message="входные данные были изменены функцией",
                is_vulnerability=True,
            )

    return TestResult(
        test_case=test_case,
        status=status,
        actual_output=str(first.value) if first.exc is None else None,
        error_message=first.error_message,
        is_vulnerability=is_vuln,
    )


def run_all_tests(func, test_cases: list[TestCase]) -> list[TestResult]:
    results = []
    for i, test_case in enumerate(test_cases, 1):
        print(f"-> Тест {i}/{len(test_cases)}: {test_case.category}")
        result = run_test(func, test_case)
        results.append(result)
    return results
