import importlib.util
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPOSITORY_ROOT / "scripts" / "build_bundle.py"


spec = importlib.util.spec_from_file_location("build_bundle", MODULE_PATH)
build_bundle = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(build_bundle)


class ValidateSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = build_bundle.load_json(REPOSITORY_ROOT / "schemas" / "rule.schema.json")

    def test_accepts_valid_rule(self) -> None:
        rule = build_bundle.load_json(REPOSITORY_ROOT / "rules" / "CUSTOM-SUSPICIOUS-CURL.json")

        build_bundle.validate_schema(rule, self.schema)

    def test_rejects_missing_required_field(self) -> None:
        with self.assertRaisesRegex(build_bundle.ValidationError, r"\$\.query is required"):
            build_bundle.validate_schema(
                {
                    "id": "CUSTOM-SUSPICIOUS-CURL",
                    "name": "Suspicious curl usage",
                    "description": "Detects shell commands that download remote content with curl.",
                    "severity": "medium",
                },
                self.schema,
            )

    def test_rejects_invalid_enum_value(self) -> None:
        with self.assertRaisesRegex(build_bundle.ValidationError, r"\$\.severity must be one of"):
            build_bundle.validate_schema(
                {
                    "id": "CUSTOM-SUSPICIOUS-CURL",
                    "name": "Suspicious curl usage",
                    "description": "Detects shell commands that download remote content with curl.",
                    "severity": "info",
                    "query": "curl http",
                },
                self.schema,
            )

    def test_rejects_invalid_pattern(self) -> None:
        with self.assertRaisesRegex(build_bundle.ValidationError, r"\$\.id does not match pattern"):
            build_bundle.validate_schema(
                {
                    "id": "custom-suspicious-curl",
                    "name": "Suspicious curl usage",
                    "description": "Detects shell commands that download remote content with curl.",
                    "severity": "medium",
                    "query": "curl http",
                },
                self.schema,
            )


if __name__ == "__main__":
    unittest.main()
