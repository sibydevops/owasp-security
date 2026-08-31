#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def yaml_scalar(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(value, ensure_ascii=False)


def convert_to_yaml(value, indent=0):
    prefix = "  " * indent

    if isinstance(value, dict):
        if not value:
            return f"{prefix}{{}}"
        lines = []
        for key, item in value.items():
            if isinstance(item, (dict, list)) and item:
                lines.append(f"{prefix}{key}:")
                lines.append(convert_to_yaml(item, indent + 1))
            else:
                lines.append(f"{prefix}{key}: {yaml_scalar(item)}")
        return "\n".join(lines)

    if isinstance(value, list):
        if not value:
            return f"{prefix}[]"
        lines = []
        for item in value:
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}-")
                nested = convert_to_yaml(item, indent + 1)
                if nested.strip():
                    lines.append(nested)
            else:
                lines.append(f"{prefix}- {yaml_scalar(item)}")
        return "\n".join(lines)

    return f"{prefix}{yaml_scalar(value)}"


def write_yaml_from_json(source_path, destination_path):
    source = Path(source_path)
    destination = Path(destination_path)
    data = json.loads(source.read_text(encoding="utf-8"))
    destination.write_text(convert_to_yaml(data), encoding="utf-8")


def main():
    if len(sys.argv) != 3:
        print("Usage: convert_json_to_yaml.py <input.json> <output.yaml>", file=sys.stderr)
        raise SystemExit(2)
    write_yaml_from_json(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    main()
