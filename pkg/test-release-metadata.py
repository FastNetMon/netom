#!/usr/bin/env python3
"""Exercise release planning without Docker, network access, or publishing."""
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('release_metadata', Path(__file__).with_name('release-metadata.py'))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleasePlanningTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(os.environ, GITHUB_REF_TYPE='branch', GITHUB_REF_NAME='main')
        environment.start()
        self.addCleanup(environment.stop)

    def test_all_targets_have_a_native_build(self):
        plan = release.metadata()
        builds = {(row['format'], row['arch']): row for row in plan['build_matrix']['include']}
        self.assertEqual(len(builds), 4)
        self.assertEqual(len(plan['test_matrix']['include']), 14)
        for row in plan['test_matrix']['include']:
            build = builds[(row['format'], row['arch'])]
            self.assertEqual(row['runner'], build['runner'])
            self.assertEqual(row['runner'].endswith('-arm'), row['arch'] == 'arm64')
        for build in builds.values():
            self.assertIn(build, plan['test_matrix']['include'])

    def test_deb_only_still_tests_every_suite_and_architecture(self):
        plan = release.metadata('deb')
        self.assertEqual(len(plan['build_matrix']['include']), 2)
        self.assertEqual(len(plan['test_matrix']['include']), 8)
        self.assertEqual(len(plan['apt_suites']), 4)
        self.assertTrue(all(row['format'] == 'deb' for row in plan['test_matrix']['include']))

    def test_rpm_only(self):
        plan = release.metadata('rpm')
        self.assertEqual(len(plan['build_matrix']['include']), 2)
        self.assertEqual(len(plan['test_matrix']['include']), 6)

    def test_unknown_format_is_rejected(self):
        with self.assertRaises(ValueError):
            release.metadata('typo')

    def test_local_toolchain_defaults_match_ci(self):
        plan = release.metadata()
        dockerfile = Path(__file__).with_name('Dockerfile').read_text()
        for key in ('rust_version', 'cargo_deb_version'):
            self.assertIn(f'ARG {key.upper()}={plan[key]}\n', dockerfile)

    def test_matching_and_mismatched_release_tags(self):
        version = release.metadata()['version']
        with patch.dict(os.environ, GITHUB_REF_TYPE='tag', GITHUB_REF_NAME=f'v{version}'):
            self.assertEqual(release.metadata()['version'], version)
        with patch.dict(os.environ, GITHUB_REF_TYPE='tag', GITHUB_REF_NAME='v0.0.0-wrong'):
            with self.assertRaises(ValueError):
                release.metadata()


if __name__ == '__main__':
    unittest.main()
