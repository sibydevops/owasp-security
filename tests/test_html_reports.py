#!/usr/bin/env python3
"""
Test suite for HTML report generation.
Validates that generate-html-report.py works with sample data.
"""

import json
import tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent / 'scripts'))

from generate_html_report import generate_semgrep_html, generate_zap_html


def test_semgrep_html_generation():
    """Test Semgrep HTML report generation."""
    # Sample Semgrep JSON
    sample_data = {
        "results": [
            {
                "check_id": "test-rule-1",
                "path": "src/app.py",
                "start": {"line": 42, "col": 5},
                "extra": {
                    "severity": "HIGH",
                    "message": "Test security issue",
                    "metadata": {
                        "cwe": "CWE-89",
                        "owasp": ["A03:2021 - Injection"]
                    }
                }
            },
            {
                "check_id": "test-rule-2",
                "path": "src/utils.py",
                "start": {"line": 15, "col": 0},
                "extra": {
                    "severity": "MEDIUM",
                    "message": "Another test issue",
                    "metadata": {
                        "cwe": "CWE-400",
                        "owasp": ["A04:2021 - Insecure Design"]
                    }
                }
            }
        ],
        "errors": []
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = Path(tmpdir) / "test.json"
        html_path = Path(tmpdir) / "test.html"
        
        json_path.write_text(json.dumps(sample_data))
        generate_semgrep_html(str(json_path), str(html_path))
        
        assert html_path.exists(), "HTML file was not created"
        html_content = html_path.read_text()
        
        # Verify key elements are present
        assert "Semgrep SAST" in html_content, "Missing title"
        assert "test-rule-1" in html_content, "Missing finding 1"
        assert "test-rule-2" in html_content, "Missing finding 2"
        assert "HIGH" in html_content, "Missing severity badge"
        assert "src/app.py" in html_content, "Missing file path"
        assert "CWE-89" in html_content, "Missing CWE reference"
        
        print("✅ Semgrep HTML generation test PASSED")
        return True


def test_zap_html_generation():
    """Test ZAP HTML report generation."""
    # Sample ZAP JSON
    sample_data = {
        "site": [
            {
                "name": "https://example.com",
                "alerts": [
                    {
                        "name": "SQL Injection",
                        "riskcode": "3",
                        "riskdesc": "High",
                        "desc": "SQL Injection detected",
                        "solution": "Use parameterized queries",
                        "reference": "https://owasp.org/",
                        "uri": "https://example.com/search",
                        "instances": [
                            {
                                "method": "GET",
                                "uri": "https://example.com/search?q=test",
                                "param": "q"
                            }
                        ]
                    },
                    {
                        "name": "Missing Security Header",
                        "riskcode": "1",
                        "riskdesc": "Low",
                        "desc": "Security header missing",
                        "solution": "Add security headers",
                        "reference": "https://owasp.org/",
                        "uri": "https://example.com/",
                        "instances": []
                    }
                ]
            }
        ]
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = Path(tmpdir) / "test.json"
        html_path = Path(tmpdir) / "test.html"
        
        json_path.write_text(json.dumps(sample_data))
        generate_zap_html(str(json_path), str(html_path))
        
        assert html_path.exists(), "HTML file was not created"
        html_content = html_path.read_text()
        
        # Verify key elements are present
        assert "ZAP DAST" in html_content, "Missing title"
        assert "SQL Injection" in html_content, "Missing alert 1"
        assert "Missing Security Header" in html_content, "Missing alert 2"
        assert "High" in html_content or "high" in html_content, "Missing risk level"
        assert "example.com" in html_content, "Missing URL"
        
        print("✅ ZAP HTML generation test PASSED")
        return True


def test_empty_reports():
    """Test HTML generation with empty findings."""
    empty_semgrep = {"results": [], "errors": []}
    empty_zap = {"site": []}

    with tempfile.TemporaryDirectory() as tmpdir:
        # Test empty Semgrep
        json_path = Path(tmpdir) / "empty_semgrep.json"
        html_path = Path(tmpdir) / "empty_semgrep.html"
        json_path.write_text(json.dumps(empty_semgrep))
        generate_semgrep_html(str(json_path), str(html_path))
        assert html_path.exists()
        assert "No findings" in html_path.read_text()

        # Test empty ZAP
        json_path = Path(tmpdir) / "empty_zap.json"
        html_path = Path(tmpdir) / "empty_zap.html"
        json_path.write_text(json.dumps(empty_zap))
        generate_zap_html(str(json_path), str(html_path))
        assert html_path.exists()
        
        print("✅ Empty reports test PASSED")
        return True


if __name__ == "__main__":
    try:
        test_semgrep_html_generation()
        test_zap_html_generation()
        test_empty_reports()
        print("\n✅ All tests PASSED!")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Test FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
