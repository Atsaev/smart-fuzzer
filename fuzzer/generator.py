import ast
import json
import os
import re

import json5
from openai import OpenAI

from models.schemas import Expected, TestCase


def get_client():
    return OpenAI(
        api_key=os.getenv("DEEPSEEK_API_KEY"),
        base_url="https://api.deepseek.com/v1/",
    )


def extract_json(text: str) -> str:
    matches = re.findall(r"\[.*\]", text, re.DOTALL)
    if not matches:
        raise ValueError(f"JSON массив не найден:\n{text[:200]}")
    return max(matches, key=len)


def normalize_json(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    text = re.sub(r"\bNone\b", "null", text)
    text = re.sub(r"\bTrue\b", "true", text)
    text = re.sub(r"\bFalse\b", "false", text)
    return text.strip()


# литерал в выражении: строка в двойных/одинарных кавычках или список
_LITERAL = r"(?:\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|\[[^\[\]]*\])"

# выражение вида "a" * 250 + "@b.c" или [0] * 4 (повтор + опциональные конкатенации)
_EXPR_RE = re.compile(
    _LITERAL
    + r"\s*\*\s*\d+"
    + r"(?:\s*\+\s*" + _LITERAL + r")*"
)

# JS-стиль "a".repeat(255) [+ "@b.c"] — LLM его тоже использует
_METHOD_REPEAT_RE = re.compile(
    r'"((?:[^"\\]|\\.)*)"\s*\.\s*repeat\s*\(\s*(\d+)\s*\)'
    + r'(?:\s*\+\s*"((?:[^"\\]|\\.)*)")?'
)


def _safe_literal_eval(expr: str):
    """Вычисляет выражение только из литералов.

    Разрешает константы, списки и операции +/* над ними. Имён, вызовов
    и атрибутов в AST нет, поэтому eval безопасен.
    """
    tree = ast.parse(expr, mode="eval")

    def check(node):
        if isinstance(node, ast.Constant):
            return
        if isinstance(node, ast.List):
            for el in node.elts:
                check(el)
            return
        if isinstance(node, ast.BinOp) and isinstance(
            node.op, (ast.Add, ast.Mult)
        ):
            check(node.left)
            check(node.right)
            return
        raise ValueError(f"Недопустимое выражение: {type(node).__name__}")

    check(tree.body)
    return eval(compile(tree, "<expr>", "eval"), {"__builtins__": {}})


def expand_python_exprs(text: str) -> str:
    """Разворачивает Python-выражения LLM в JSON-значениях безопасно.

    LLM часто игнорирует требование валидного JSON и генерирует в
    значениях "a" * 250 + "@b.c", "a".repeat(255) или [0] * 4.
    Такие фрагменты вычисляются и заменяются на валидный JSON.
    """

    def repl(match):
        expr = match.group(0)
        try:
            value = _safe_literal_eval(expr)
        except (ValueError, SyntaxError, TypeError, MemoryError):
            return expr
        if isinstance(value, (str, list)) and len(value) <= 5000:
            return json.dumps(value, ensure_ascii=False)
        return expr

    text = _EXPR_RE.sub(repl, text)

    def repl_method(match):
        base = match.group(1)
        count = min(int(match.group(2)), 1000)
        suffix = match.group(3) or ""
        return json.dumps(base * count + suffix)

    return _METHOD_REPEAT_RE.sub(repl_method, text)


def parse_json(content: str) -> list:
    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        print(f"json.loads не смог: {e}")
        try:
            return json5.loads(content)
        except Exception as e2:
            print(f"json5 также не смог: {e2}")
            raise


def repair_json(client, broken_json: str) -> str:
    prompt = (
        "Исправь JSON ниже. Верни ТОЛЬКО валидный JSON массив без пояснений, "
        "без markdown, без комментариев.\n\n" + broken_json
    )
    response = client.chat.completions.create(
        model="deepseek-chat",
        messages=[{"role": "user", "content": prompt}],
        temperature=0,
        max_tokens=8000,
    )
    return response.choices[0].message.content.strip()


def _build_prompt(function_code: str) -> str:
    return f"""Ты генератор fuzz-тестов для поиска ошибок и уязвимостей в Python-функции. Проанализируй переданную функцию и сгенерируй 10 тест-кейсов. НЕ изменяй исходную функцию — только генерируй тесты и их ожидаемое поведение.

Функция:
```python
{function_code}
```

Входные данные ("input_data"):
- Для обычного теста input_data — объект, ключи которого ДОЛЖНЫ в точности соответствовать именам параметров функции.
- Для последовательности input_data — массив таких объектов, по одному на каждый вызов; каждый объект должен соответствовать параметрам функции.
- Каждый параметр функции ДОЛЖЕН присутствовать в input_data, если у него нет значения по умолчанию.
- НЕ передавай параметры, которых нет в сигнатуре.
- Для параметров со значением по умолчанию можешь передать явное значение или опустить параметр.
- НЕ добавляй дополнительные параметры.

Ожидаемое поведение ("expected"):
- expected — это КОНТРАКТ функции: что она ДОЛЖНА делать по смыслу (название, сигнатура, параметры, очевидная семантика), а НЕ то, что делает текущая реализация. Если код подозрительный (например, "clamp" возвращает maximum при value < minimum, или "normalize_name" удаляет внутренние пробелы) — ожидание всё равно по смыслу: clamp(5, 10, 20) -> value: 10; normalize_name("John  Doe") -> value: "john doe".
- Рассчитывай expected НЕ через выполнение или мысленное повторение текущей реализации. Сначала определи семантический контракт функции, затем НЕЗАВИСИМО вычисли ожидаемый результат. НИКОГДА не используй фактический результат текущей реализации как expected.
- expected ВСЕГДА должен содержать конкретное проверяемое значение или конкретный тип исключения. ЗАПРЕЩЕНО: "примерно", "возможно", "ожидается ошибка", "корректное значение" и любые другие неопределённые ожидания.
- Если контракт невозможно однозначно определить из кода, имени, сигнатуры и очевидной семантики — НЕ придумывай поведение. Используй тест только там, где ожидаемое поведение однозначно.
- Ожидай исключение ТОЛЬКО если оно следует из контракта или явной валидации функции. Если функция по контракту должна бросить TypeError и бросает TypeError — expected: {{"type": "exception", "name": "TypeError"}}. Сам факт возникновения исключения — НЕ уязвимость.
- Для функций со строками обязательно включай тесты с внутренними пробелами ("John Doe"), краевыми пробелами, регистром.
- Для функций с диапазонами (clamp и т.п.) обязательно включай value ниже минимума и выше максимума с конкретными ожиданиями.

Числовые результаты и переполнение:
- Для ожидаемых числовых результатов учитывай промежуточные операции и ограничения типа данных. НЕ считай математически конечный результат корректным expected, если сама корректная реализация неизбежно получает переполнение на промежуточном вычислении (например, (x * x) / y при больших x: промежуточное x * x может дать inf, и корректный результат будет inf, а не математический).
- Для overflow-тестов ожидаемое поведение должно соответствовать контракту функции. Если контракт не определяет обработку переполнения — не объявляй получение inf/NaN автоматически уязвимостью.
- НЕ считай ограничение диапазона float уязвимостью само по себе.
- Перед тем как использовать экстремальное значение как тест на переполнение, убедись, что существует реальный сценарий переполнения: функция действительно выполняет промежуточные арифметические операции, которые могут переполниться на этом входе. Не добавляй overflow-тест ради категории.

Пост-условия ("postconditions"):
- Если функция НЕ должна менять входные данные — укажи {{"inputs_unchanged": true}}.
- Указывай inputs_unchanged ТОЛЬКО если неизменяемость входных данных следует из контракта или очевидной семантики функции. НЕ предполагай неизменяемость автоматически.
- Если функция по контракту изменяет вход (in-place, как append в список) — опиши ожидаемое состояние через {{"input_data": {{"items": [1, 2, 3]}}}}.
- Если не уверен — не указывай.

Последовательности (для утечек состояния и повторных вызовов):
- Чтобы проверить state leakage / повторные вызовы, используй формат последовательности: "input_data" — массив объектов (по одному на каждый вызов), "expected" — массив ожиданий (по одному на вызов).

Выбор тестов:
- Выбери 10 НАИБОЛЕЕ ИНФОРМАТИВНЫХ тестов. Приоритет:
  1) потенциальные логические ошибки;
  2) граничные условия;
  3) нарушение контракта;
  4) неправильные типы;
  5) edge cases;
  6) остальные категории (NaN, переполнение, деление на ноль и т.п.), если применимы.
- Для арифметических функций ОБЯЗАТЕЛЬНО включи минимум 3 теста с простыми круглыми значениями, где ожидаемый результат можно вычислить вручную (например, percentage(25, 100) -> value: 25.0). Рассчитывай ожидание независимо от тела функции — по смыслу операции.
- Каждый из 10 тестов должен проверять ОТДЕЛЬНОЕ поведение. НЕ создавай несколько тестов, отличающихся только значением, если они проверяют одно и то же свойство. Предпочитай тесты, которые могут обнаружить разные классы ошибок.
- НЕ добавляй тест только ради покрытия категории (например, NaN на функции, где он неинтересен).
- Полезные категории: граничные значения; за пределами допустимых; нулевые/отрицательные; min/max; очень большие; пустые; None; неверные типы; пустые/большие коллекции; дубликаты; пробелы; Unicode; некорректные форматы; неполные/лишние данные; min/max длина; off-by-one; ошибки нормализации/преобразования типов; неверные вычисления; нарушение инвариантов; NaN/Infinity; переполнение; деление на ноль; комбинации условий; изменение входных данных; повторные вызовы; утечки состояния.

Только константные значения — никаких Python-выражений: без "a" * 100, без "a".repeat(255), без list comprehension, без вызовов функций.
Отвечай ТОЛЬКО валидным JSON массивом, без markdown, без пояснений.

Формат (одиночный вызов):
[
  {{
    "input_data": {{"price": 100, "percent": 10}},
    "expected": {{"type": "return", "value": 90.0}},
    "postconditions": {{"inputs_unchanged": true}},
    "category": "boundary",
    "reason": "стандартная скидка"
  }},
  {{
    "input_data": {{"price": "100"}},
    "expected": {{"type": "exception", "name": "TypeError"}},
    "category": "invalid",
    "reason": "неверный тип"
  }}
]

Формат (последовательность вызовов):
[
  {{
    "input_data": [{{"value": 10}}, {{"value": 10}}],
    "expected": [
      {{"type": "return", "value": 11}},
      {{"type": "return", "value": 11}}
    ],
    "category": "state",
    "reason": "повторный вызов с тем же входом: утечка состояния"
  }}
]"""


def _extract_signature(code: str) -> str:
    """Сигнатура функции без тела — oracle не должен видеть реализацию.

    Собираем срезом исходника от `def` до начала тела: ast.unparse на
    Python 3.14 падает на искусственных узлах без lineno/col_offset.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return ""
    lines = code.splitlines()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.body:
            start_pos = (node.lineno - 1, node.col_offset)
            first_stmt = node.body[0]
            end_pos = (first_stmt.lineno - 1, first_stmt.col_offset)
            if start_pos[0] == end_pos[0]:
                header = lines[start_pos[0]][start_pos[1]:end_pos[1]].rstrip()
            else:
                parts = [lines[start_pos[0]][start_pos[1]:]]
                parts.extend(lines[start_pos[0] + 1:end_pos[0]])
                header = "\n".join(parts).rstrip()
            if header.endswith(":"):
                header = header[:-1].rstrip()
            return header
    return ""


def _extract_raises(code: str) -> list[str]:
    """Имена исключений из явных raise в теле функции."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Raise) and node.exc is not None:
            exc = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
            if isinstance(exc, ast.Name):
                names.add(exc.id)
    return sorted(names)


def _refine_expectations(client, code: str, cases: list[TestCase]) -> list[TestCase]:
    """Независимый oracle: пересчитывает expected по сигнатуре и контракту,
    НЕ видя тело функции (исключения из валидаций передаются как подсказка)."""
    signature = _extract_signature(code)
    if not signature:
        return cases
    raises = _extract_raises(code)
    inputs = json.dumps([c.input_data for c in cases], ensure_ascii=False)

    prompt = f"""Ты независимый oracle для fuzz-тестов. Вычисли ОЖИДАЕМОЕ поведение функции по её КОНТРАКТУ, НЕ видя тело функции.

Сигнатура функции:
{signature}

Функция может бросать исключения (из явных проверок): {raises if raises else "нет явных проверок"}

Входы тест-кейсов (в том же порядке):
{inputs}

Для КАЖДОГО входа вычисли expected по смыслу контракта:
- возвращается значение: {{"type": "return", "value": <точное значение>}}
- вход некорректен по контракту: {{"type": "exception", "name": "<тип исключения>"}}
- контракт для входа неоднозначен: {{"type": "return", "value": null}}

Пример: percentage(25, 100) -> {{"type": "return", "value": 25.0}}

Верни ТОЛЬКО JSON массив с ожиданиями в том же порядке, без пояснений:
[
  {{"type": "return", "value": 25.0}},
  {{"type": "exception", "name": "TypeError"}}
]"""

    try:
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            max_tokens=8000,
        )
        raw = response.choices[0].message.content
        print("-> ORACLE RAW:", raw[:400])
        content = extract_json(raw)
        content = normalize_json(content)
        content = expand_python_exprs(content)
        parsed = parse_json(content)
    except Exception as e:
        print(f"-> Oracle не смог распарсить: {e}")
        return cases

    if len(parsed) != len(cases):
        print(f"-> Oracle: ожиданий {len(parsed)} != тестов {len(cases)}, оставляем draft")
        return cases

    refined = []
    for case, exp_item in zip(cases, parsed):
        if not isinstance(exp_item, dict):
            refined.append(case)
            continue
        try:
            refined.append(case.model_copy(update={"expected": Expected(**exp_item)}))
        except Exception as e:
            print(f"-> Oracle: невалидное ожидание {exp_item}: {e}")
            refined.append(case)
    return refined


def generate_test_cases(function_code: str, function_name: str) -> list[TestCase]:
    print(f"-> Генерация тест-кейсов для: {function_name}")
    client = get_client()
    prompt = _build_prompt(function_code)

    def call_llm() -> str:
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=8000,
        )
        return response.choices[0].message.content

    def try_parse(text: str) -> list[TestCase] | None:
        try:
            content = extract_json(text)
            content = normalize_json(content)
            content = expand_python_exprs(content)
            raw = parse_json(content)
        except Exception as e:
            print(f"-> Парсинг не удался: {e}")
            return None
        cases = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            # LLM иногда пишет input_data голым значением — оборачиваем
            # (list не трогаем — это формат последовательности вызовов)
            if not isinstance(item.get("input_data"), (dict, list)):
                item["input_data"] = {"value": item.get("input_data")}
            try:
                cases.append(TestCase(**item))
            except Exception as e:
                print(f"-> Невалидный тест-кейс: {e}")
        return cases or None

    raw_content = call_llm()
    print("-> RAW ответ (первые 300 символов):")
    print(raw_content[:300])

    # Попытка 1: прямой парсинг
    result = try_parse(raw_content)

    # Попытка 2: repair через LLM
    if result is None:
        print("-> Запускаем repair через LLM...")
        try:
            repaired = repair_json(client, raw_content)
            result = try_parse(repaired)
        except Exception as e:
            print(f"-> Repair также не помог: {e}")

    # Попытка 3: повторная генерация (вывод LLM нестабилен)
    if result is None:
        print("-> Вторая попытка генерации...")
        try:
            result = try_parse(call_llm())
        except Exception as e:
            print(f"-> Вторая попытка не удалась: {e}")

    if result is None:
        raise RuntimeError(
            f"Не удалось распарсить ответ LLM после всех попыток.\n"
            f"Сырой ответ:\n{raw_content}"
        )

    # независимый oracle: пересчитывает ожидания без тела функции
    return _refine_expectations(client, function_code, result)
