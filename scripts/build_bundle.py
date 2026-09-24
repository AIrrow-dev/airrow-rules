#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = REPOSITORY_ROOT / "rules"
SCHEMA_PATH = REPOSITORY_ROOT / "schemas" / "rule.schema.json"
CHANNELS_DIR = REPOSITORY_ROOT / "channels"


class ValidationError(Exception):
    pass


def load_json(path: Path) -> object:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def validate_schema(instance: object, schema: dict[str, object], path: str = "$") -> None:
    enum = schema.get("enum")
    if isinstance(enum, list) and instance not in enum:
        raise ValidationError(f"{path} must be one of: {', '.join(map(str, enum))}")

    expected_type = schema.get("type")
    if expected_type is None:
        return

    if expected_type == "object":
        if not isinstance(instance, dict):
            raise ValidationError(f"{path} must be an object")

        required = schema.get("required", [])
        for key in required:
            if key not in instance:
                raise ValidationError(f"{path}.{key} is required")

        properties = schema.get("properties", {})
        for key, value in instance.items():
            property_schema = properties.get(key)
            if property_schema is None:
                if schema.get("additionalProperties", True) is False:
                    raise ValidationError(f"{path}.{key} is not allowed")
                continue
            validate_schema(value, property_schema, f"{path}.{key}")
        return

    if expected_type == "array":
        if not isinstance(instance, list):
            raise ValidationError(f"{path} must be an array")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(instance):
                validate_schema(item, item_schema, f"{path}[{index}]")
        return

    if expected_type == "string":
        if not isinstance(instance, str):
            raise ValidationError(f"{path} must be a string")
        min_length = schema.get("minLength")
        if isinstance(min_length, int) and len(instance) < min_length:
            raise ValidationError(f"{path} must be at least {min_length} characters long")
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.fullmatch(pattern, instance) is None:
            raise ValidationError(f"{path} does not match pattern {pattern}")
    elif expected_type == "boolean":
        if not isinstance(instance, bool):
            raise ValidationError(f"{path} must be a boolean")
    else:
        raise ValidationError(f"{path} uses unsupported schema type: {expected_type}")


def load_channel(channel_name: str) -> dict[str, object]:
    channel_path = CHANNELS_DIR / f"{channel_name}.json"
    if not channel_path.exists():
        raise ValidationError(f"Channel file not found: {channel_path}")

    channel = load_json(channel_path)
    if not isinstance(channel, dict):
        raise ValidationError(f"{channel_path} must contain a JSON object")

    name = channel.get("name")
    if not isinstance(name, str) or not name:
        raise ValidationError(f"{channel_path} must declare a non-empty string in 'name'")

    rules = channel.get("rules")
    if not isinstance(rules, list) or not all(isinstance(rule, str) for rule in rules):
        raise ValidationError(f"{channel_path} must declare a string array in 'rules'")

    return channel


def build_bundle(channel_name: str) -> dict[str, object]:
    channel = load_channel(channel_name)
    schema = load_json(SCHEMA_PATH)
    if not isinstance(schema, dict):
        raise ValidationError(f"{SCHEMA_PATH} must contain a JSON object")

    bundled_rules = []
    for rule_filename in channel["rules"]:
        rule_path = RULES_DIR / rule_filename
        if not rule_path.exists():
            raise ValidationError(f"Rule file not found: {rule_path}")
        rule = load_json(rule_path)
        if not isinstance(rule, dict):
            raise ValidationError(f"{rule_path} must contain a JSON object")
        validate_schema(rule, schema)
        bundled_rules.append(rule)

    return {
        "channel": channel["name"],
        "rules": bundled_rules,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate and build channel bundles.")
    parser.add_argument("--channel", default="stable", help="Channel name to bundle")
    parser.add_argument("--output", help="Optional output path for the built bundle")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate inputs and print a summary without requiring an output file",
    )
    args = parser.parse_args()

    try:
        bundle = build_bundle(args.channel)
    except ValidationError as error:
        print(error, file=sys.stderr)
        return 1

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")

    if args.check:
        print(f"Validated {len(bundle['rules'])} rule(s) for channel '{bundle['channel']}'.")
    elif not args.output:
        print(json.dumps(bundle, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
