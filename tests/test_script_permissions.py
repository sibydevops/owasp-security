import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_FILES = [
    ROOT / "scripts" / "clone-target.sh",
    ROOT / "scripts" / "detect-app.sh",
    ROOT / "scripts" / "dispatch-scan.sh",
    ROOT / "scripts" / "normalize-inputs.sh",
    ROOT / "scripts" / "run-semgrep.sh",
    ROOT / "scripts" / "run-zap.sh",
    ROOT / "scripts" / "validate-target.sh",
]


class ScriptPermissionTests(unittest.TestCase):
    def test_shell_scripts_are_executable(self):
        result = subprocess.run(
            ["git", "ls-files", "--stage", "--", "scripts/*.sh"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=True,
        )
        tracked_modes = {
            line.split()[-1]: line.split()[0] for line in result.stdout.splitlines() if line.strip()
        }

        missing = []
        for script in SCRIPT_FILES:
            rel_path = script.relative_to(ROOT).as_posix()
            if tracked_modes.get(rel_path) != "100755":
                missing.append(rel_path)

        self.assertFalse(
            missing,
            msg=f"Scripts missing executable permissions in Git index: {', '.join(missing)}",
        )


if __name__ == "__main__":
    unittest.main()
