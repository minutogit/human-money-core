# Privacy Matrix (State-Transition Analysis)

The following table defines the required presence and strictness of fields depending on the selected **Privacy Mode**.

| Field / Mode | **Public** | **Stealth** | **Flexible** |
| :--- | :--- | :--- | :--- |
| `sender_id` | **MUST** be present | **MUST NOT** be present | Optional |
| `sender_sig` | **MUST** be present | **MUST NOT** be present | Must be present IF `sender_id` is present |
| `trap_data` | Optional | **MUST** be present (Context Bound) | Must be present IF `sender_id` is missing |
| `recipient_id` | Full DID | Hashed / Blinded | Full DID or Hashed |

## Validation Logic

The validator MUST enforce these rules strictly.

- **Stealth Mode Violation**: If `mode == Stealth` AND `sender_id` is present -> **INVALID**.
- **Stealth Mode Integrity**: If `mode == Stealth` AND `trap_data` is missing -> **INVALID**.
- **Flexible Mode Consistency**: If `sender_id` is present but `sender_sig` is missing -> **INVALID**.

Any deviation from this matrix represents a potential security vulnerability or privacy leak.
