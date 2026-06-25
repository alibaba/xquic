# Validation Guide

> Use `/validate` as the primary entry point for all build/test validation.

The `/validate` skill (`scripts/xqc_validate.sh` + `.claude/skills/validate/SKILL.md`) handles:
- Change detection and test scope mapping
- Build, unit tests, and integration tests
- Individual steps (`--detect`, `--build`, `--unit`, `--integration`) or combined (`--quick`, `--all`)
- Failure diagnosis and coverage gap analysis

For test architecture, pass criteria, and diagnostics details, see `docs_ai/testing/test_guide.md`.
