---
name: test-optimization
description: Rule for optimizing test execution, avoiding redundant runs on clean repos, and using cargo nextest.
activation: always
---

# Test Optimization & Execution Guidelines

To save time, machine resources, and context tokens, follow these strict rules regarding test execution:

## 1. Avoid Redundant Initial Test Runs
- **Before running tests at task startup:** Check `git status --porcelain`.
- If the repository working tree is clean (no uncommitted changes in `src/`, `Cargo.toml`, etc.), **do NOT run an initial full test suite**. Assume the existing repository state is sound and proceed directly with the task.
- If only checking whether the codebase compiles, use `cargo check` instead of a full test run.

## 2. Default Test Runner: `cargo-nextest`
- Always use `cargo-nextest` as the primary test runner:
  ```bash
  cargo nextest run --status-level fail
  ```
- This executes tests in parallel, runs significantly faster than standard `cargo test`, and `--status-level fail` ensures clean, token-efficient output (only failures and the final summary are printed).

## 3. Targeted Testing During Development
- During development and refactoring, do **NOT** run the entire test suite on every minor change.
- Target only the relevant module or test case:
  ```bash
  cargo nextest run <filter_string>
  ```
- Example: `cargo nextest run voucher::` or `cargo nextest run test_mint`

## 4. Full Suite Run Only at Completion
- Run the full test suite (`cargo nextest run --status-level fail`) only once when the task is complete, or when preparing for a commit/release.
