from models.schemas import TestCase, TestResult, TestStatus


def run_test(func, test_case: TestCase) -> TestResult:
    try:
        try:
            result = func(**test_case.input_data)
        except TypeError:
            import inspect
            first_param = list(inspect.signature(func).parameters.keys())[0]
            result = func(**{first_param: test_case.input_data})

        is_vulnerability = (result is None and "None" not in
                            test_case.expected_behavior)

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