import ast
import json
import os
import re

import json5
from openai import OpenAI

from models.schemas import TestCase


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

# выражение вида "a" * 250 + "@b.c" или [0] * 4 (повтор + конкатенации)
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
    значениях "a" * 250 + "@b.c" или [0] * 4. Такие фрагменты
    вычисляются и заменяются на валидный JSON.
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
        max_tokens=4000,
    )
    return response.choices[0].message.content.strip()


def generate_test_cases(function_code: str, function_name: str) -> list[TestCase]:
    print(f"-> Генерация тест-кейсов для: {function_name}")
    client = get_client()

    prompt = f"""Ты генератор тест-кейсов для фаззинга. Проанализируй функцию и сгенерируй 10 тест-кейсов.

Функция:
```python
{function_code}
```

Правила (СТРОГО):
- Отвечай ТОЛЬКО валидным JSON массивом, без markdown, без пояснений
- Только JSON типы: string, number, boolean, null, array, object
- Списки пиши литерально: [1, 2, 3] — НЕ [0] * 100, максимум 5 элементов
- Никаких Python-выражений внутри JSON: умножение строк ("a" * 100), list comprehension и вызовы функций запрещены — только константные значения

Категории тест-кейсов:
- boundary: граничные значения (0, -1, пустая строка, пустой список)
- invalid: неверные типы (null вместо списка, число вместо строки)
- special: специфичные для данной функции случаи

Формат ответа:
[
  {{
    "input_data": {{"param_name": value}},
    "expected_behavior": "что должно произойти",
    "category": "boundary"
  }}
]"""

    response = client.chat.completions.create(
        model="deepseek-chat",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,
        max_tokens=4000,
    )
    raw_content = response.choices[0].message.content
    print("-> RAW ответ (первые 300 символов):")
    print(raw_content[:300])

    def try_parse(text: str) -> list | None:
        try:
            content = extract_json(text)
            content = normalize_json(content)
            content = expand_python_exprs(content)
            return parse_json(content)
        except Exception as e:
            print(f"-> Парсинг не удался: {e}")
            return None

    # Попытка 1: прямой парсинг
    result = try_parse(raw_content)

    # Попытка 2: repair через LLM
    if result is None:
        print("-> Запускаем repair через LLM...")
        try:
            repaired = repair_json(client, raw_content)
            print("-> Репейр-ответ (первые 200 символов):")
            print(repaired[:200])
            result = try_parse(repaired)
        except Exception as e:
            print(f"-> Repair также не помог: {e}")

    # Попытка 3: повторная генерация (вывод LLM нестабилен)
    if result is None:
        print("-> Вторая попытка генерации...")
        try:
            response = client.chat.completions.create(
                model="deepseek-chat",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=4000,
            )
            result = try_parse(response.choices[0].message.content)
        except Exception as e:
            print(f"-> Вторая попытка не удалась: {e}")

    if result is None:
        raise RuntimeError(
            f"Не удалось распарсить ответ LLM после всех попыток.\n"
            f"Сырой ответ:\n{raw_content}"
        )

    return [TestCase(**tc) for tc in result]
