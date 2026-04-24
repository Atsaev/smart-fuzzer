import os

from openai import OpenAI

from models.schemas import FuzzReport, TestResult, TestStatus


def get_client():
    return OpenAI(
        api_key=os.getenv("DEEPSEEK_API_KEY"),
        base_url="https://api.deepseek.com/v1/",
    )


def generate_report(function_name: str, results: list[TestResult]) -> FuzzReport:
    print(f"-> Генерирую отчет ...")
    client = get_client()
    passed = sum(1 for r in results if r.status == TestStatus.PASSED)
    failed = sum(1 for r in results if r.status == TestStatus.FAILED)
    errors = sum(1 for r in results if r.status == TestStatus.ERROR)
    vulnerabilities = [r for r in results if r.is_vulnerability]
    vuln_details = "\n".join(
        [
            f"- Input: {r.test_case.input_data}, Error: {r.error_message}"
            for r in vulnerabilities
        ]
    )

    prompt = f"""Ты эксперт по безопасности. Проанализируй результаты фаззинга функции {function_name}:

    Всего тестов: {len(results)}
    Прошло: {passed}
    Упало: {failed}
    Ошибок: {errors}
    Уязвимостей найдено: {len(vulnerabilities)}

    Детали уязвимостей:
    {vuln_details if vuln_details else "Уязвимостей не найдено"}

    Напиши краткое резюме на русском языке — что нашли и что рекомендуешь исправить. 3-5 предложений."""
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
        summary=summary,
    )
