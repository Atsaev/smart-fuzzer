"""Изолированное исполнение кода, присланного на фаззинг.

Код пользователя никогда не выполняется в процессе сервера:
- компилируется RestrictedPython (guard-ы на атрибуты/индексы/распаковку,
  import через whitelist-функцию __import__);
- каждый тест исполняется в отдельном процессе с лимитами ресурсов
  (CPU, память, процессы, файловые дескрипторы) и таймаутом;
- с пониженными привилегиями (nobody), когда процесс запущен от root.
"""

import ast
import copy
import multiprocessing as mp
import os
import resource

from RestrictedPython import compile_restricted, safe_builtins, safe_globals
from RestrictedPython.Eval import (
    default_guarded_getattr,
    default_guarded_getitem,
    default_guarded_getiter,
)
from RestrictedPython.Guards import full_write_guard, guarded_unpack_sequence

from fuzzer.runner import run_test
from models.schemas import TestCase, TestResult, TestStatus

TEST_TIMEOUT_SECONDS = 5
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

# builtins, которых нет в RestrictedPython 8.5, но нужны для обычного кода
_SAFE_EXTRA_BUILTINS = {
    "list": list, "dict": dict, "set": set, "frozenset": frozenset,
    "min": min, "max": max, "sum": sum, "all": all, "any": any,
    "enumerate": enumerate, "filter": filter, "map": map,
    "iter": iter, "next": next, "reversed": reversed,
    "print": print, "format": format,
}


class SandboxError(Exception):
    """Ошибка песочницы: запрещённая конструкция, таймаут, отказ."""


def _guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name.split(".")[0] not in ALLOWED_IMPORTS:
        raise ImportError(f"Импорт модуля '{name}' запрещён")
    return __import__(name, globals, locals, fromlist, level)


def validate_code(code: str) -> None:
    """Проверяет код без исполнения, до обращения к LLM.

    Кидает SyntaxError на import-выражениях; синтаксис дополнительно
    проверяет RestrictedPython-компиляция.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        raise
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            raise SyntaxError(f"Import is not allowed: {ast.unparse(node)}")
    compile_restricted(code, "<validation>", "exec")


def _sandbox_namespace() -> dict:
    namespace = dict(safe_globals)
    # официальные guard-ы RestrictedPython (в 8.x их нужно задавать явно)
    namespace.update({
        "_getattr_": default_guarded_getattr,
        "_getitem_": default_guarded_getitem,
        "_getiter_": default_guarded_getiter,
        "_unpack_sequence_": guarded_unpack_sequence,
        "_unpack_tuple_": guarded_unpack_sequence,
        "_write_": full_write_guard,
    })
    namespace["__builtins__"] = {
        **safe_builtins,
        **namespace["__builtins__"],
        **_SAFE_EXTRA_BUILTINS,
        "__import__": _guarded_import,
    }
    return namespace


def _apply_limits():
    resource.setrlimit(resource.RLIMIT_CPU, (MAX_CPU_SECONDS, MAX_CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_AS, (MAX_MEMORY_BYTES, MAX_MEMORY_BYTES))
    resource.setrlimit(resource.RLIMIT_NPROC, (MAX_PROCESSES, MAX_PROCESSES))
    resource.setrlimit(resource.RLIMIT_NOFILE, (MAX_FDS, MAX_FDS))
    try:
        os.setgid(NOBODY_GID)
        os.setuid(NOBODY_UID)
    except OSError:
        pass


def _run_single_test(func_source, func_name, test_case_dict, result_queue):
    """Выполняется в дочернем процессе: один тест-кейс."""
    _apply_limits()
    try:
        bytecode = compile_restricted(func_source, "<sandbox>", "exec")
        namespace = _sandbox_namespace()
        exec(bytecode, namespace)

        func = namespace.get(func_name)
        if not callable(func):
            result_queue.put({"error": f"Функция {func_name} не найдена"})
            return

        result = run_test(func, TestCase(**copy.deepcopy(test_case_dict)), func_source=func_source)
        result_queue.put({"result": result})
    except SyntaxError as e:
        result_queue.put({"error": f"Запрещённая конструкция: {e}"})
    except BaseException as e:
        result_queue.put({"error": f"{type(e).__name__}: {e}"})


def run_all_tests_sandboxed(code: str, func_name: str, test_cases):
    """Запускает каждый тест в отдельном процессе с таймаутом.

    Зависший тест (возможный бесконечный цикл) превращается в
    TestResult со статусом ERROR, остальные тесты продолжают работать.
    """
    ctx = mp.get_context("spawn")
    results = []

    for tc in test_cases:
        queue = ctx.Queue()
        process = ctx.Process(
            target=_run_single_test,
            args=(code, func_name, tc.model_dump(), queue),
        )
        process.start()
        process.join(TEST_TIMEOUT_SECONDS)

        if process.is_alive():
            process.terminate()
            process.join(2)
            if process.is_alive():
                process.kill()
            results.append(TestResult(
                test_case=tc,
                status=TestStatus.ERROR,
                error_message=f"таймаут {TEST_TIMEOUT_SECONDS} с: возможно, бесконечный цикл",
                is_vulnerability=False,
            ))
            continue

        try:
            payload = queue.get(timeout=2)
        except Exception:
            results.append(TestResult(
                test_case=tc,
                status=TestStatus.ERROR,
                error_message=f"процесс завершён аварийно (код {process.exitcode})",
                is_vulnerability=False,
            ))
            continue

        if "error" in payload:
            results.append(TestResult(
                test_case=tc,
                status=TestStatus.ERROR,
                error_message=payload["error"],
                is_vulnerability=False,
            ))
            continue

        results.append(payload["result"])

    return results
