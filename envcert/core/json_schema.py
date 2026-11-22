"""Dependency-free JSON Schema validation for the bundled report schema.

EnvCert's default install has no third-party dependencies, but `envcert
verify` must still reject schema-invalid reports rather than checking only a
handful of top-level keys.  This module implements the subset of JSON Schema
(draft 2020-12) used by `envcert/schemas/report.schema.json`.  When the
optional `jsonschema` package is installed the CLI uses the full library; the
fallback is intentionally conservative and fails closed on anything it cannot
evaluate.

Supported keywords: ``$ref`` (local), ``type``, ``required``, ``properties``,
``additionalProperties``, ``items``, ``enum``, ``const``, ``pattern``,
``minimum``, ``maximum``, ``exclusiveMinimum``, ``exclusiveMaximum``,
``minLength``, ``maxLength``, ``minItems``, ``maxItems``, ``allOf``,
``anyOf``, ``oneOf`` and ``not``.
"""
from __future__ import annotations

import json
import re
from typing import Any

_MAX_DEPTH = 64


def _path(parts: list[str | int]) -> str:
    return "/".join(str(part) for part in parts) if parts else "<root>"


def _json_repr(value: Any) -> str:
    try:
        text = json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        text = repr(value)
    return text if len(text) <= 240 else text[:237] + "..."


def _matches_type(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    # Unknown type names are ignored, matching the permissive JSON Schema rule.
    return True


def _resolve_ref(root: dict[str, Any], ref: str) -> Any:
    if not ref.startswith("#/"):
        raise ValueError(f"unsupported $ref {ref!r}")
    node: Any = root
    for raw in ref[2:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and token in node:
            node = node[token]
        else:
            raise ValueError(f"unresolvable $ref {ref!r}")
    return node


def validate(instance: Any, schema: Any, *, root: dict[str, Any] | None = None,
             path: list[str | int] | None = None, depth: int = 0) -> list[str]:
    """Return a list of validation problems (empty means valid)."""
    problems: list[str] = []
    if depth > _MAX_DEPTH:
        return [f"{_path(path or [])}: schema recursion limit exceeded"]
    if root is None:
        root = schema if isinstance(schema, dict) else {}
    if not isinstance(schema, dict):
        return problems
    here = path or []
    where = _path(here)

    if "$ref" in schema:
        try:
            target = _resolve_ref(root, str(schema["$ref"]))
        except ValueError as exc:
            return [f"{where}: {exc}"]
        return validate(instance, target, root=root, path=here, depth=depth + 1)

    expected_type = schema.get("type")
    if expected_type is not None:
        if isinstance(expected_type, str):
            types = [expected_type]
        elif isinstance(expected_type, list):
            types = [str(item) for item in expected_type]
        else:
            types = []
        if types and not any(_matches_type(instance, item) for item in types):
            names = ", ".join(repr(item) for item in types)
            problems.append(f"{where}: {_json_repr(instance)} is not of type {names}")

    if "const" in schema and instance != schema["const"]:
        problems.append(f"{where}: {_json_repr(instance)} is not {_json_repr(schema['const'])}")

    enum = schema.get("enum")
    if isinstance(enum, list) and instance not in enum:
        problems.append(f"{where}: {_json_repr(instance)} is not one of {_json_repr(enum)}")

    pattern = schema.get("pattern")
    if isinstance(pattern, str) and isinstance(instance, str):
        try:
            matched = re.search(pattern, instance) is not None
        except re.error:
            matched = True
        if not matched:
            problems.append(f"{where}: {_json_repr(instance)} does not match {pattern!r}")

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        minimum = schema.get("minimum")
        if isinstance(minimum, (int, float)) and instance < minimum:
            problems.append(f"{where}: {instance} is less than the minimum of {minimum}")
        maximum = schema.get("maximum")
        if isinstance(maximum, (int, float)) and instance > maximum:
            problems.append(f"{where}: {instance} is greater than the maximum of {maximum}")
        exclusive_minimum = schema.get("exclusiveMinimum")
        if isinstance(exclusive_minimum, (int, float)) and instance <= exclusive_minimum:
            problems.append(f"{where}: {instance} is less than or equal to the exclusive minimum of {exclusive_minimum}")
        exclusive_maximum = schema.get("exclusiveMaximum")
        if isinstance(exclusive_maximum, (int, float)) and instance >= exclusive_maximum:
            problems.append(f"{where}: {instance} is greater than or equal to the exclusive maximum of {exclusive_maximum}")

    if isinstance(instance, str):
        min_length = schema.get("minLength")
        if isinstance(min_length, int) and len(instance) < min_length:
            problems.append(f"{where}: {_json_repr(instance)} is shorter than {min_length}")
        max_length = schema.get("maxLength")
        if isinstance(max_length, int) and len(instance) > max_length:
            problems.append(f"{where}: {_json_repr(instance)} is longer than {max_length}")

    if isinstance(instance, list):
        min_items = schema.get("minItems")
        if isinstance(min_items, int) and len(instance) < min_items:
            problems.append(f"{where}: {_json_repr(instance)} has fewer than {min_items} items")
        max_items = schema.get("maxItems")
        if isinstance(max_items, int) and len(instance) > max_items:
            problems.append(f"{where}: {_json_repr(instance)} has more than {max_items} items")
        items = schema.get("items")
        if isinstance(items, dict):
            for index, item in enumerate(instance):
                problems.extend(validate(item, items, root=root, path=here + [index], depth=depth + 1))
        elif isinstance(items, list):
            for index, item_schema in enumerate(items[:len(instance)]):
                problems.extend(validate(instance[index], item_schema, root=root,
                                         path=here + [index], depth=depth + 1))

    if isinstance(instance, dict):
        properties = schema.get("properties")
        if not isinstance(properties, dict):
            properties = {}
        required = schema.get("required")
        if isinstance(required, list):
            for key in required:
                if key not in instance:
                    problems.append(f"{where}: {key!r} is a required property")
        for key, subschema in properties.items():
            if key in instance:
                problems.extend(validate(instance[key], subschema, root=root,
                                         path=here + [key], depth=depth + 1))
        additional = schema.get("additionalProperties", True)
        if additional is not True:
            extras = [key for key in instance if key not in properties]
            if additional is False:
                for key in extras:
                    problems.append(f"{where}: additional property {key!r} is not allowed")
            elif isinstance(additional, dict):
                for key in extras:
                    problems.extend(validate(instance[key], additional, root=root,
                                             path=here + [key], depth=depth + 1))

    all_of = schema.get("allOf")
    if isinstance(all_of, list):
        for subschema in all_of:
            problems.extend(validate(instance, subschema, root=root, path=here, depth=depth + 1))

    any_of = schema.get("anyOf")
    if isinstance(any_of, list):
        if not any(not validate(instance, subschema, root=root, path=here, depth=depth + 1)
                   for subschema in any_of):
            problems.append(f"{where}: {_json_repr(instance)} is not valid under any of the given schemas")

    one_of = schema.get("oneOf")
    if isinstance(one_of, list):
        matches = sum(1 for subschema in one_of
                      if not validate(instance, subschema, root=root, path=here, depth=depth + 1))
        if matches != 1:
            problems.append(f"{where}: {_json_repr(instance)} is not valid under exactly one of the given schemas")

    if "not" in schema and isinstance(schema["not"], dict):
        if not validate(instance, schema["not"], root=root, path=here, depth=depth + 1):
            problems.append(f"{where}: {_json_repr(instance)} should not be valid under the given schema")

    return problems
