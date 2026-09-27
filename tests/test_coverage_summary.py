#!/usr/bin/env python3
import unittest
import tempfile
import os
import sys

# Import parse_lcov from scripts/coverage-summary.py
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scripts')))
import importlib.util
spec = importlib.util.spec_from_file_location("coverage_summary", os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scripts', 'coverage-summary.py')))
coverage_summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coverage_summary)

class TestCoverageSummary(unittest.TestCase):
    def test_parse_lcov_sample(self):
        sample_lcov = """
TN:
SF:src/rules/mod.rs
DA:1,1
DA:2,1
DA:3,0
DA:4,1
end_of_record
SF:src/proxy/handler.rs
DA:10,1
DA:11,1
DA:12,1
end_of_record
"""
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.info') as tmp:
            tmp.write(sample_lcov)
            tmp_path = tmp.name

        try:
            modules, total_hits, total_lines, overall_pct = coverage_summary.parse_lcov(tmp_path)
            self.assertIn('src/rules', modules)
            self.assertIn('src/proxy', modules)
            self.assertEqual(modules['src/rules'], [3, 4])  # 3 hits out of 4 lines
            self.assertEqual(modules['src/proxy'], [3, 3])  # 3 hits out of 3 lines
            self.assertEqual(total_hits, 6)
            self.assertEqual(total_lines, 7)
            self.assertAlmostEqual(overall_pct, 600.0 / 7.0, places=2)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

if __name__ == '__main__':
    unittest.main()
