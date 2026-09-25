import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "screen_bugsinpy_repair_cases",
    Path(__file__).with_name("screen-bugsinpy-repair-cases.py"),
)
SCREEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCREEN)


class ScreenRealControlTests(unittest.TestCase):
    def test_reproducing_case_hides_regression_from_agent_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            repo.mkdir()
            for argv in (["git", "init", "-q"],
                         ["git", "config", "user.email", "test@example.invalid"],
                         ["git", "config", "user.name", "Test"]):
                subprocess.run(argv, cwd=repo, check=True, capture_output=True)
            (repo / "app.py").write_text("VALUE = 0\n")
            (repo / "tests").mkdir()
            (repo / "tests" / "__init__.py").write_text("")
            (repo / "tests" / "test_app.py").write_text(
                "import unittest\n"
                "from app import VALUE\n"
                "class TestApp(unittest.TestCase):\n"
                "    def test_value(self): self.assertEqual(VALUE, 1)\n"
            )
            subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-qm", "buggy"], cwd=repo,
                           check=True, capture_output=True)
            buggy = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo,
                                            text=True).strip()
            (repo / "app.py").write_text("VALUE = 1\n")
            subprocess.run(["git", "commit", "-qam", "fixed"], cwd=repo,
                           check=True, capture_output=True)
            fixed = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo,
                                            text=True).strip()
            bug = root / "bug"  # The benchmark metadata is outside agent-visible source.
            bug.mkdir()
            (bug / "bug.info").write_text(
                f'buggy_commit_id="{buggy}"\nfixed_commit_id="{fixed}"\n'
                'test_file="tests/test_app.py"\n'
            )
            (bug / "run_test.sh").write_text(
                "python -m unittest -q tests.test_app.TestApp.test_value\n"
            )
            output = root / "output"
            result = SCREEN.screen_case("example", bug, repo, output, sys.executable, 30)
            self.assertEqual(result["status"], "reproduced")
            case = output / "example-bug"
            self.assertFalse((case / "buggy" / "tests").exists())
            self.assertFalse((case / "fixed" / "tests").exists())
            self.assertTrue((case / "hidden-tests" / "tests" / "test_app.py").exists())
            self.assertGreater(len((case / "source-records.jsonl").read_text().splitlines()), 0)
            self.assertEqual(json.loads((case / "control.json").read_text())["buggy_commit"], buggy)


if __name__ == "__main__":
    unittest.main()
