"""Validate that the real-repair evaluator safely applies one bounded line edit."""

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("eval-connected-bugsinpy-tqdm.py")
SPEC = importlib.util.spec_from_file_location("eval_connected_bugsinpy_tqdm", SCRIPT)
EVAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVAL)


class LineEditTests(unittest.TestCase):
    def test_matches_unique_line_without_requiring_model_to_copy_indentation(self):
        original = "def run():\n    return wrong()\n"
        self.assertEqual(
            EVAL.apply_line_edit(original, "return wrong()", "return right()"),
            "def run():\n    return right()\n",
        )

    def test_rejects_ambiguous_or_multiline_edits(self):
        original = "    return wrong()\n    return wrong()\n"
        self.assertIsNone(EVAL.apply_line_edit(original, "return wrong()", "return right()"))
        self.assertIsNone(EVAL.apply_line_edit("return wrong()\n", "return wrong()", "x\ny"))


if __name__ == "__main__":
    unittest.main()
