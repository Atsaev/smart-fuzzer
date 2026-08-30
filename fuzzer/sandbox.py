"""Изолированное исполнение кода, присланного на фаззинг.

Код пользователя никогда не выполняется в процессе сервера:
- компилируется RestrictedPython (import-выражения и доступ к приватным
  атрибутам запрещены ещё на этапе компиляции);
- исполняется в отдельном процессе с лимитами ресурсов (CPU, память,
  процессы, файловые дескрипторы);
- с пониженными привилегиями (nobody), когда процесс запущен от root;
- с таймаутом - по истечении процесс принудительно завершается.
"""

import ast
import multiprocessing as mp
import os
import resource

from RestrictedPython import compile_restricted, safe_builtins, safe_globals

from fuzzer.runner import run_test
from models.schemas import TestCase, TestResult

TIMEOUT_SECONDS = 10
MAX_CPU_SECONDS = 5
MAX_MEMORY_BYTES = 512 * 1024 * 1024
MAX_PROCESSES = 32
MAX_FDS = 64
NOBODY_UID = 65534
NOBODY_GID = 65534

# stdlib-модули без ввода-вывода: их можно импортировать внутри фаззируемой функции
ALLOWED_IMPORTS = frozenset({
    "json", "math", "re", "random", "string", "itertools", "functools",
    "collections", "statistics", "decimal", "fractions", "datetime",
    "uuid", "hashlib", "base64", "typing", "enum", "dataclasses",
    "textwrap", "unicodedata", "bisect", "heapq",
})


class SandboxError(Exception):
    """Ошибка песочницы: запрещённая конструкция, таймаут, отказ."""


def _guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name.split(".")[0] not in ALLOWED_IMPORTS:
        raise ImportError(f"Импорт модуля '{name}' запрещён")
    return __import__(name, globals, locals, fromlist, level)


def validate_code(code: str) -> None:
    """Проверяет код без исполнения, до обращения к LLM.

    Кидает SyntaxError на import-выражениях; синтаксис и опасные
    конструкции дополнительно отсекает RestrictedPython-компиляция.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        raise
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            raise SyntaxError(
                f"Import is not allowed: {ast.unparse(node)}"
            )
    compile_restricted(code, "<validation>", "exec")


def _run_worker(func_source, test_cases, result_queue):
    # лимиты ресурсов - до любого пользовательского кода
    resource.setrlimit(resource.RLIMIT_CPU, (MAX_CPU_SECONDS, MAX_CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_AS, (MAX_MEMORY_BYTES, MAX_MEMORY_BYTES))
    resource.setrlimit(resource.RLIMIT_NPROC, (MAX_PROCESSES, MAX_PROCESSES))
    resource.setrlimit(resource.RLIMIT_NOFILE, (MAX_FDS, MAX_FDS))

    # понижаем привилегии до nobody (когда запущены от root)
    try:
        os.setgid(NOBODY_GID)
        os.setuid(NOBODY_UID)
    except OSError:
        pass

    try:
        bytecode = compile_restricted(func_source, "<sandbox>", "exec")
        namespace = dict(safe_globals)
        namespace["__builtins__"] = {**safe_builtins, "__import__": _guarded_import}
        # доступный пользователю способ импортировать whitelist-модули
        # (имя __import__ запрещено RestrictedPython как начинающееся с _)
        namespace["import_module"] = _guarded_import
        exec(bytecode, namespace)

        func = next(
            (
                obj
                for name, obj in namespace.items()
                if callable(obj) and not name.startswith("_")
            ),
            None,
        )
        if func is None:
            result_queue.put({"error": "Не удалось найти тестируемую функцию"})
            return

        results = [run_test(func, TestCase(**tc)) for tc in test_cases]
        result_queue.put({"results": results})
    except SyntaxError as e:
        result_queue.put({"error": f"Запрещённая конструкция: {e}"})
    except BaseException as e:
        result_queue.put({"error": f"{type(e).__name__}: {e}"})


def run_all_tests_sandboxed(code: str, test_cases: list[TestCase]) -> list[TestResult]:
    """Запускает тест-кейсы в песочнице.

    Возвращает результаты или кидает SandboxError.
    """
    ctx = mp.get_context("spawn")
    queue = ctx.Queue()
    process = ctx.Process(
        target=_run_worker,
        args=(code, [tc.model_dump() for tc in test_cases], queue),
    )
    process.start()

    process.join(TIMEOUT_SECONDS)
    if process.is_alive():
        process.terminate()
        process.join(2)
        if process.is_alive():
            process.kill()
        raise SandboxError(f"Таймаут: исполнение заняло больше {TIMEOUT_SECONDS} с")

    if process.exitcode not in (0, None):
        raise SandboxError(f"Песочница завершилась с кодом {process.exitcode}")

    try:
        payload = queue.get(timeout=2)
    except Exception:
        raise SandboxError("Песочница не вернула результат")

    if "error" in payload:
        raise SandboxError(payload["error"])
    return payload["results"]
