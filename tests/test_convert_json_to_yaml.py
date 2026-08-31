import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "convert_json_to_yaml",
    ROOT / "scripts" / "convert_json_to_yaml.py",
)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class JsonToYamlConversionTests(unittest.TestCase):
    def test_convert_nested_data(self):
        payload = {
            "site": [
                {
                    "url": "https://example.com",
                    "alerts": [
                        {
                            "pluginid": "40012",
                            "alert": "Cross Site Scripting",
                            "riskdesc": "High",
                            "count": 1,
                        }
                    ],
                }
            ]
        }

        yaml_text = module.convert_to_yaml(payload)
        self.assertIn("site:", yaml_text)
        self.assertIn('url: "https://example.com"', yaml_text)
        self.assertIn('alert: "Cross Site Scripting"', yaml_text)
        self.assertIn('riskdesc: "High"', yaml_text)

    def test_write_yaml_output(self):
        payload = {"site": []}
        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = Path(tmpdir) / "zap.json"
            yaml_path = Path(tmpdir) / "zap.yaml"
            json_path.write_text('{"site": []}', encoding="utf-8")

            module.write_yaml_from_json(json_path, yaml_path)

            self.assertTrue(yaml_path.exists())
            self.assertIn("site:", yaml_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
