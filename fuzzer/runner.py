"""Детерминированный классификатор: вердикт вычисляется кодом из
структурированного ожидания (TestCase.expected) и фактического результата.
LLM не участвует в принятии решения."""

import ast
import copy
import inspect
import math
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
        if expected.type == "exception":
            return TestStatus.VULNERABILITY, True
        if expected.value is None:
            if actual_value is None:
                return TestStatus.PASSED, False
            return TestStatus.VULNERABILITY, True
        if actual_value is None:
            return TestStatus.VULNERABILITY, True
        if _values_match(expected.value, actual_value) is False:
            return TestStatus.VULNERABILITY, True
        return TestStatus.PASSED, False

    if expected.type == "return":
        if isinstance(exc, _VULN_EXCEPTIONS):
            return TestStatus.VULNERABILITY, True
        return TestStatus.ERROR, False

    if expected.name is None:
        # ожидание исключения без типа — классифицировать нечего
        return TestStatus.ERROR, False
    if expected.name.lower() == type(exc).__name__.lower():
        return TestStatus.PASSED, False
    return TestStatus.VULNERABILITY, True


def _check_return_annotation(func_source: str, actual_value) -> str | None:
    """Детерминированная проверка: фактический тип результата против
    аннотации возврата (-> int / -> float / ...). Не зависит от LLM."""
    try:
        tree = ast.parse(func_source)
    except SyntaxError:
        return None
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            returns = node.returns
            if returns is None:
                return None
            name = returns.id if isinstance(returns, ast.Name) else None
            if name in _ANNOTATION_TYPES and actual_value is not None:
                if not isinstance(actual_value, _ANNOTATION_TYPES[name]):
                    return (
                        f"возвращаемое значение ({type(actual_value).__name__}) "
                        f"не соответствует аннотации -> {name}"
                    )
            return None
    return None


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


def _log_verdict(test_case: TestCase, outcome: "_Outcome", status: TestStatus) -> None:
    """Лог для аудита: ожидание, факт, вердикт."""
    if outcome.exc is not None:
        actual = {"type": "exception", "name": type(outcome.exc).__name__}
    else:
        actual = {"type": "return", "value": outcome.value}
    print(
        f"  [test] input={test_case.input_data} "
        f"expected={test_case.expected.model_dump()} "
        f"actual={actual} verdict={status.value}"
    )


def _run_single(func, test_case: TestCase, func_source: str | None) -> TestResult:
    """Одиночный вызов: вердикт + аннотация + пост-условия + стабильность."""
    call_input = copy.deepcopy(test_case.input_data)
    args, kwargs = _build_call(func, call_input)
    first = _invoke(func, args, kwargs)

    # свежий вход для второго вызова: мутация не должна влиять на проверку
    # стабильности, а результат копируем, чтобы общий объект не портил сравнение
    args2, kwargs2 = _build_call(func, copy.deepcopy(test_case.input_data))
    second = _invoke(func, args2, kwargs2)
    first = _Outcome(value=copy.deepcopy(first.value), exc=first.exc)
    second = _Outcome(value=copy.deepcopy(second.value), exc=second.exc)

    mutated = call_input != test_case.input_data
    unstable = not _outcomes_equal(first, second)

    status, is_vuln = _classify(test_case.expected, first.exc, first.value)
    _log_verdict(test_case, first, status)

    if status == TestStatus.PASSED:
        if func_source:
            ann_error = _check_return_annotation(func_source, first.value)
            if ann_error:
                return TestResult(
                    test_case=test_case, status=TestStatus.VULNERABILITY,
                    actual_output=str(first.value) if first.exc is None else None,
                    error_message=ann_error, is_vulnerability=True,
                )

        pc = test_case.postconditions
        if pc is not None:
            if pc.inputs_unchanged is True and mutated:
                return TestResult(
                    test_case=test_case, status=TestStatus.VULNERABILITY,
                    actual_output=str(first.value) if first.exc is None else None,
                    error_message="нарушение inputs_unchanged: входные данные были изменены функцией",
                    is_vulnerability=True,
                )
            if pc.input_data:
                for key, expected_val in pc.input_data.items():
                    actual_val = call_input.get(key)
                    if _values_match(expected_val, actual_val) is False:
                        return TestResult(
                            test_case=test_case, status=TestStatus.VULNERABILITY,
                            actual_output=str(first.value) if first.exc is None else None,
                            error_message=(
                                f"пост-условие не выполнено: {key} должен быть "
                                f"{expected_val!r}, фактически {actual_val!r}"
                            ),
                            is_vulnerability=True,
                        )
        else:
            if mutated:
                return TestResult(
                    test_case=test_case, status=TestStatus.VULNERABILITY,
                    actual_output=str(first.value) if first.exc is None else None,
                    error_message="входные данные были изменены функцией",
                    is_vulnerability=True,
                )

        if unstable:
            return TestResult(
                test_case=test_case, status=TestStatus.VULNERABILITY,
                actual_output=str(first.value) if first.exc is None else None,
                error_message="нестабильное поведение: разные результаты при одинаковом входе",
                is_vulnerability=True,
            )

    return TestResult(
        test_case=test_case, status=status,
        actual_output=str(first.value) if first.exc is None else None,
        error_message=first.error_message, is_vulnerability=is_vuln,
    )


def _run_sequence(func, test_case: TestCase) -> TestResult:
    """Последовательность вызовов в одном процессе: ловит утечки состояния.

    Состояние между вызовами сохраняется; каждый вызов сверяется со своим
    ожиданием. Отклонение на любом шаге — VULNERABILITY.
    """
    inputs = test_case.input_data
    expected = test_case.expected

    if len(inputs) != len(expected):
        return TestResult(
            test_case=test_case, status=TestStatus.ERROR,
            error_message="число вызовов и ожиданий не совпадает",
            is_vulnerability=False,
        )

    outcomes = []
    for inp in inputs:
        args, kwargs = _build_call(func, copy.deepcopy(inp))
        outcomes.append(_invoke(func, args, kwargs))

    for i, (outcome, exp) in enumerate(zip(outcomes, expected)):
        status, is_vuln = _classify(exp, outcome.exc, outcome.value)
        if status != TestStatus.PASSED:
            detail = outcome.error_message or "неверное значение"
            return TestResult(
                test_case=test_case, status=status,
                actual_output=str(outcome.value) if outcome.exc is None else None,
                error_message=f"вызов {i + 1}: {detail}",
                is_vulnerability=is_vuln,
            )

    return TestResult(
        test_case=test_case, status=TestStatus.PASSED,
        actual_output=str(outcomes[-1].value) if outcomes else None,
        is_vulnerability=False,
    )


def run_test(func, test_case: TestCase, func_source: str | None = None) -> TestResult:
    if test_case.is_sequence:
        return _run_sequence(func, test_case)
    return _run_single(func, test_case, func_source)


def run_all_tests(func, test_cases: list[TestCase]) -> list[TestResult]:
    results = []
    for i, test_case in enumerate(test_cases, 1):
        print(f"-> Тест {i}/{len(test_cases)}: {test_case.category}")
        result = run_test(func, test_case)
        results.append(result)
    return results
