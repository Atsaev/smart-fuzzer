import os

from openai import OpenAI

from models.schemas import FuzzReport, TestResult, TestStatus


def get_client():
    return OpenAI(
        api_key=os.getenv("DEEPSEEK_API_KEY"),
        base_url="https://api.deepseek.com/v1/",
    )


def generate_report(function_name: str, results: list[TestResult]) -> FuzzReport:
    print("-> Генерирую отчёт ...")
    client = get_client()

    passed = sum(1 for r in results if r.status == TestStatus.PASSED)
    failed = sum(1 for r in results if r.status == TestStatus.FAILED)
    errors = sum(1 for r in results if r.status == TestStatus.ERROR)
    vulnerabilities = [r for r in results if r.is_vulnerability]

    lines = []
    for i, r in enumerate(results, 1):
        actual = r.error_message or str(r.actual_output)
        lines.append(
            f"{i}. [{r.status.value}] input={r.test_case.input_data} "
            f"expected={r.test_case.expected_behavior!r} actual={actual!r} "
            f"reason={r.test_case.reason!r}"
        )
    details = "\n".join(lines)

    prompt = f"""Ты эксперт по безопасности. Ниже — результаты фаззинга функции {function_name}.

Движок уже классифицировал каждый тест:
- PASS — поведение совпало с ожидаемым
- FAIL — поведение отличается от ожидаемого
- ERROR — не удалось классифицировать
- VULNERABILITY — функция вернула неверное значение, упала там, где ожидался возврат, вернула значение там, где ожидалось исключение, или бросила исключение другого типа, чем ожидалось

Результаты тестов:
{details}

Итого: всего {len(results)}, PASS: {passed}, FAIL: {failed}, ERROR: {errors}, VULNERABILITY: {len(vulnerabilities)}.

Напиши краткое резюме на русском языке (3-5 предложений): что показал фаззинг,
опиши только реальные VULNERABILITY (если они есть), какими входными данными они
вызываются и что стоит исправить. Не выдумывай проблем, которых нет в результатах.
Строго опирайся на список тестов выше: не утверждай, что какой-то сценарий проверен,
если его нет в списке, и не делай выводов о корректности функции сверх показанного."""

    response = client.chat.completions.create(
        model="deepseek-chat",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,
    )
    summary = response.choices[0].message.content.strip()

    return FuzzReport(
        function_name=function_name,
        total_tests=len(results),
        passed=passed,
        failed=failed,
        errors=errors,
        vulnerabilities=vulnerabilities,
        results=results,
        summary=summary,
    )
