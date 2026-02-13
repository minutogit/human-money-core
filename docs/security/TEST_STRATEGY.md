# Test Strategy

To ensure the high security requirements of `human-money-core`, we move beyond simple Example-Based Testing to more rigorous methods.

## 1. Property-Based Testing (PBT)

Instead of testing specific values ("Input 5 gives 10"), we test **properties** that must always be true ("Input * 2 is always even").

We use tools like `proptest` to generate random inputs (valid and invalid) to verify:

- **Validation Rules**: `validate(generate_random_voucher())` should match the expected result from the [Privacy Matrix](./PRIVACY_MATRIX.md).
- **Roundtrip Identity**: `decode(encode(v))` == `v` for all possible vouchers.
- **Edge Cases**: Empty strings, max integers, special Unicode characters.

## 2. Mutation Testing

We use mutation testing (e.g., `cargo-mutants`) to verify the quality of our tests.
The tool automatically:
1.  Modifies source code (e.g., changes `if x > 0` to `if x < 0`).
2.  Runs the test suite.
3.  **Success**: At least one test MUST fail.
4.  **Failure**: If all tests pass, the modified code was not covered, indicating a gap in our strictness.

## 3. Negative Testing & Invariants

We explicitly test that invalid states are rejected. We define system **Invariants**:

1.  **Sum Conservation**: `Input Amount == Output Amount` (excluding fees/minting).
2.  **Chain Integrity**: `PreviousHash` matches the hash of the parent transaction.
3.  **Context Binding**: TrapData MUST match the current transaction context.

Our test harness attempts to break these invariants by systematically corrupting valid transactions (bit-flipping, nulling fields) and asserting that validation fails.
