import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


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

    def test_build_bundle_for_stable_channel(self) -> None:
        bundle = build_bundle.build_bundle("stable")

        self.assertEqual(bundle["channel"], "stable")
        self.assertEqual(len(bundle["rules"]), 1)
        self.assertEqual(bundle["rules"][0]["id"], "CUSTOM-SUSPICIOUS-CURL")

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

    def test_rejects_additional_property(self) -> None:
        with self.assertRaisesRegex(build_bundle.ValidationError, r"\$\.extra is not allowed"):
            build_bundle.validate_schema(
                {
                    "id": "CUSTOM-SUSPICIOUS-CURL",
                    "name": "Suspicious curl usage",
                    "description": "Detects shell commands that download remote content with curl.",
                    "severity": "medium",
                    "query": "curl http",
                    "extra": "unexpected",
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

    def test_rejects_invalid_channel_name(self) -> None:
        with self.assertRaisesRegex(build_bundle.ValidationError, r"Invalid channel name"):
            build_bundle.load_channel("../schemas/rule.schema")

    def test_rejects_rule_path_outside_rules_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            channels_dir = temp_root / "channels"
            rules_dir = temp_root / "rules"
            channels_dir.mkdir()
            rules_dir.mkdir()

            (channels_dir / "stable.json").write_text(
                json.dumps({"name": "stable", "rules": ["../outside.json"]}),
                encoding="utf-8",
            )
            (temp_root / "outside.json").write_text("{}", encoding="utf-8")

            with mock.patch.object(build_bundle, "CHANNELS_DIR", channels_dir), mock.patch.object(
                build_bundle, "RULES_DIR", rules_dir
            ):
                with self.assertRaisesRegex(build_bundle.ValidationError, r"Path escapes base directory"):
                    build_bundle.build_bundle("stable")


if __name__ == "__main__":
    unittest.main()
