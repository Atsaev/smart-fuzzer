import inspect

from dotenv import load_dotenv

from fuzzer.generator import generate_test_cases
from fuzzer.runner import run_all_tests
from reports.reporter import generate_report

load_dotenv()

def fuzz_function(func):
    function_code = inspect.getsource(func)
    print(f"\n -> Фаззинг функции: {func.__name__}\n")

    test_cases = generate_test_cases(function_code, func.__name__)
    print(f"  Сгенерировано тест-кейсов: {len(test_cases)}\n")

    print("  Запускаем тесты...")
    results = run_all_tests(func, test_cases)

    report = generate_report(func.__name__, results)

    print(f"""
    ======
    -> ОТЧЁТ: {report.function_name}
    
    Всего тестов:      {report.total_tests}
    Прошло:            {report.passed}
    Упало:             {report.failed}
    Ошибок:            {report.errors}
    Уязвимостей:       {len(report.vulnerabilities)}
    
    -> Резюме:
    {report.summary}
    =======
    """)
    return report

# Здесь пишем тестовую функцию для чека
def parse_config(config: dict) -> dict:
    result = {}
    host = config["host"]
    port = int(config["port"])

    if port < 0 or port > 65535:
        raise ValueError("Invalid port")
    timeout = config.get("timeout", 30)
    result["timeout"] = int(timeout)
    allowed_ips = config.get("allowed_ips", [])
    result["allowed_ips"] = [str(ip) for ip in allowed_ips]
    result["connection_string"] = f"http://{host}:{port}"
    result["port"] = port
    result["host"] = host

    return result
if __name__ == "__main__":
    fuzz_function(parse_config)