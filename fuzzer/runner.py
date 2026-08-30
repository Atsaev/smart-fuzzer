import inspect

from models.schemas import TestCase, TestResult, TestStatus


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

    # функция без явных параметров или только **kwargs
    if not positional and not has_var_args:
        return (), (dict(input_data) if isinstance(input_data, dict) else {})

    # один позиционный параметр: {"param": value} -> value
    if len(positional) == 1 and not has_var_kw:
        if isinstance(input_data, dict) and len(input_data) == 1:
            value = next(iter(input_data.values()))
        else:
            value = input_data
        return (value,), {}

    # *args без именованных параметров
    if has_var_args and not positional:
        return (input_data,), {}

    # несколько параметров: передаём по именам
    if isinstance(input_data, dict):
        return (), dict(input_data)

    return (input_data,), {}


def run_test(func, test_case: TestCase) -> TestResult:
    try:
        args, kwargs = _build_call(func, test_case.input_data)
        result = func(*args, **kwargs)

        is_vulnerability = (
            result is None and "None" not in test_case.expected_behavior
        )

        return TestResult(
            test_case=test_case,
            status=TestStatus.PASSED,
            actual_output=str(result),
            is_vulnerability=is_vulnerability,
        )

    except (ValueError, KeyError) as e:
        is_vulnerability = isinstance(e, KeyError)
        return TestResult(
            test_case=test_case,
            status=TestStatus.FAILED,
            error_message=f"{type(e).__name__}: {str(e)}",
            is_vulnerability=is_vulnerability,
        )

    except Exception as e:
        return TestResult(
            test_case=test_case,
            status=TestStatus.ERROR,
            error_message=f"{type(e).__name__}: {str(e)}",
            is_vulnerability=True,
        )


def run_all_tests(func, test_cases: list[TestCase]) -> list[TestResult]:
    results = []
    for i, test_case in enumerate(test_cases, 1):
        print(f"-> Тест {i}/{len(test_cases)}: {test_case.category}")
        result = run_test(func, test_case)
        results.append(result)
    return results
