use cel_interpreter::{Context, Program, Value};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use rust_decimal::Decimal;
use std::str::FromStr;

/// Result enum for policy evaluation
#[derive(Debug, PartialEq)]
pub enum PolicyEngineError {
    CompilationError(String),
    EvaluationError(String),
    TypeMismatch(String),
}

// --- AUDIT-M03-005 evaluation budgets ---------------------------------------
//
// Rule expressions originate from signed `[immutable]` standard zones but are
// still attacker-influencable content (compromised/malicious issuer, socially
// engineered `.standard` files), and they are evaluated against
// attacker-controlled voucher state. cel-parser/cel-interpreter recursion has
// no built-in depth guard and overflows the thread stack at very small
// nesting depths (measured: paren nesting depth 12 evaluates fine, depth 16
// aborts the whole process with an uncatchable stack-overflow SIGABRT).
// Therefore a cheap STATIC pre-scan runs BEFORE any parsing, and the own AST
// walk enforces recursion/iteration budgets as defense-in-depth.

/// Maximum characters accepted for a single rule expression. Real-world
/// standards use expressions well below this bound; it only rejects
/// pathological inputs.
const MAX_RULE_EXPRESSION_CHARS: usize = 4096;

/// Maximum structural nesting depth of a rule expression. Must stay far below
/// the measured parser stack-overflow cliff (>12) while comfortably above any
/// realistic business rule (~4); also keeps wasm32's small stacks safe.
const MAX_RULE_NESTING_DEPTH: usize = 8;

/// Maximum recursion depth of the project-owned strict AST pre-check.
const MAX_AST_RECURSION_DEPTH: usize = 512;

/// Maximum total comprehension iterations per rule evaluation. The engine
/// clones the entire environment per iteration (`loop_env = env.clone()`),
/// making cost O(n²) in the iterated array size. Real-world standards
/// comprehend over tiny lists (signature roles); 1_000 is far above any
/// legitimate use while capping quadratic blowup.
const MAX_COMPREHENSION_ITERATIONS: usize = 1_000;

/// The policy engine evaluates CEL rules against a given state
pub struct DynamicPolicyEngine;

impl DynamicPolicyEngine {
    /// Evaluates a single CEL expression against the provided voucher and transaction JSON states.
    pub fn evaluate_rule(
        expression: &str,
        voucher_state: &JsonValue,
        transaction_state: Option<&JsonValue>,
    ) -> Result<bool, PolicyEngineError> {
        // AUDIT-M03-005: static budget check BEFORE any parsing — the
        // third-party parser aborts the process on deeply nested input, so it
        // must never see unbounded expressions.
        Self::check_expression_budget(expression)?;

        let program = Program::compile(expression)
            .map_err(|e| PolicyEngineError::CompilationError(format!("{:?}", e)))?;

        // Parse AST with cel_parser to perform strict path-existence and fail-closed pre-checks
        let ast = cel_parser::Parser::new()
            .parse(expression)
            .map_err(|e| PolicyEngineError::CompilationError(format!("{:?}", e)))?;

        let mut env: HashMap<String, JsonValue> = HashMap::new();
        env.insert("Voucher".to_string(), voucher_state.clone());
        if let Some(t_state) = transaction_state {
            env.insert("Transaction".to_string(), t_state.clone());
        }

        // Run AST strict pre-check (validates missing keys, OOB indices,
        // short-circuit paths) under a hard comprehension-iteration budget.
        let mut iteration_budget = MAX_COMPREHENSION_ITERATIONS;
        Self::eval_and_check_ast(&ast, &env, 0, &mut iteration_budget)?;

        let mut context = Context::default();

        let v_val = Self::json_to_cel(voucher_state)?;
        let _ = context.add_variable("Voucher", v_val);

        if let Some(t_state) = transaction_state {
            let t_val = Self::json_to_cel(t_state)?;
            let _ = context.add_variable("Transaction", t_val);
        }

        // Register custom functions
        Self::register_custom_functions(&mut context);

        let result = program
            .execute(&context)
            .map_err(|e| PolicyEngineError::EvaluationError(format!("{:?}", e)))?;

        match result {
            Value::Bool(b) => Ok(b),
            _ => Err(PolicyEngineError::TypeMismatch(
                "Expression did not evaluate to a boolean".into(),
            )),
        }
    }

    /// AUDIT-M03-005: cheap static budget scan over the raw expression string,
    /// executed BEFORE `Program::compile`. Bounds expression length and
    /// structural bracket nesting so that neither the third-party parser nor
    /// the interpreter can recurse into an uncatchable stack overflow.
    /// String literals are skipped (quote-aware, with escape handling) to
    /// avoid false rejections; worst-case over-counting still only fails
    /// closed.
    fn check_expression_budget(expression: &str) -> Result<(), PolicyEngineError> {
        if expression.chars().count() > MAX_RULE_EXPRESSION_CHARS {
            return Err(PolicyEngineError::CompilationError(format!(
                "Rule expression exceeds maximum length of {MAX_RULE_EXPRESSION_CHARS} characters"
            )));
        }

        let mut depth: usize = 0;
        let mut open_quote: Option<char> = None;
        let mut escaped = false;

        for ch in expression.chars() {
            if let Some(q) = open_quote {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == q {
                    open_quote = None;
                }
                continue;
            }
            match ch {
                '\'' | '"' => open_quote = Some(ch),
                '(' | '[' | '{' => {
                    depth += 1;
                    if depth > MAX_RULE_NESTING_DEPTH {
                        return Err(PolicyEngineError::CompilationError(format!(
                            "Rule expression exceeds maximum nesting depth of \
                             {MAX_RULE_NESTING_DEPTH}"
                        )));
                    }
                }
                ')' | ']' | '}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }

        Ok(())
    }

    /// Evaluates the parsed AST strictly against JSON environment to enforce fail-closed semantics
    /// for missing keys and out-of-bounds indices.
    fn eval_and_check_ast(
        ided_expr: &cel_parser::ast::IdedExpr,
        env: &HashMap<String, JsonValue>,
        depth: usize,
        iter_budget: &mut usize,
    ) -> Result<JsonValue, PolicyEngineError> {
        // AUDIT-M03-005 defense-in-depth: bound our own recursion regardless of
        // what the parser accepted.
        if depth > MAX_AST_RECURSION_DEPTH {
            return Err(PolicyEngineError::EvaluationError(format!(
                "AST recursion depth exceeds evaluation budget ({MAX_AST_RECURSION_DEPTH})"
            )));
        }
        use cel_parser::ast::{EntryExpr, Expr};
        use cel_parser::reference::Val;

        match &ided_expr.expr {
            Expr::Unspecified => Ok(JsonValue::Null),
            Expr::Literal(val) => match val {
                Val::String(s) => Ok(JsonValue::String(s.clone())),
                Val::Boolean(b) => Ok(JsonValue::Bool(*b)),
                Val::Int(i) => Ok(JsonValue::Number((*i).into())),
                Val::UInt(u) => Ok(JsonValue::Number((*u).into())),
                Val::Double(d) => {
                    if let Some(n) = serde_json::Number::from_f64(*d) {
                        Ok(JsonValue::Number(n))
                    } else {
                        Ok(JsonValue::Null)
                    }
                }
                Val::Bytes(b) => {
                    let elems = b.iter().map(|byte| JsonValue::Number((*byte).into())).collect();
                    Ok(JsonValue::Array(elems))
                }
                Val::Null => Ok(JsonValue::Null),
            },
            Expr::Ident(name) => {
                if let Some(val) = env.get(name) {
                    Ok(val.clone())
                } else {
                    Err(PolicyEngineError::EvaluationError(format!(
                        "NoSuchKey(\"{}\")",
                        name
                    )))
                }
            }
            Expr::Select(select) => {
                let target = Self::eval_and_check_ast(&select.operand, env, depth + 1, iter_budget)?;
                if select.test {
                    // has(target.field)
                    match target {
                        JsonValue::Object(map) => Ok(JsonValue::Bool(map.contains_key(&select.field))),
                        _ => Ok(JsonValue::Bool(false)),
                    }
                } else {
                    match target {
                        JsonValue::Object(map) => {
                            if let Some(val) = map.get(&select.field) {
                                Ok(val.clone())
                            } else {
                                Err(PolicyEngineError::EvaluationError(format!(
                                    "NoSuchKey(\"{}\")",
                                    select.field
                                )))
                            }
                        }
                        _ => Err(PolicyEngineError::EvaluationError(format!(
                            "NoSuchKey(\"{}\")",
                            select.field
                        ))),
                    }
                }
            }
            Expr::Call(call) => {
                let func_name = call.func_name.as_str();

                // Bracket indexing: _[_]
                if func_name == "_[_]" {
                    if call.args.len() != 2 {
                        return Err(PolicyEngineError::CompilationError(
                            "Invalid index call args length".into(),
                        ));
                    }
                    let target = Self::eval_and_check_ast(&call.args[0], env, depth + 1, iter_budget)?;
                    let idx_val = Self::eval_and_check_ast(&call.args[1], env, depth + 1, iter_budget)?;

                    match target {
                        JsonValue::Object(map) => match idx_val {
                            JsonValue::String(k) => {
                                if let Some(v) = map.get(&k) {
                                    Ok(v.clone())
                                } else {
                                    Err(PolicyEngineError::EvaluationError(format!(
                                        "NoSuchKey(\"{}\")",
                                        k
                                    )))
                                }
                            }
                            _ => Err(PolicyEngineError::CompilationError(
                                "Map bracket index must evaluate to a string".into(),
                            )),
                        },
                        JsonValue::Array(arr) => {
                            let idx = match idx_val {
                                JsonValue::Number(n) => {
                                    if let Some(i) = n.as_i64() {
                                        if i < 0 {
                                            return Err(PolicyEngineError::EvaluationError(format!(
                                                "IndexOutOfBounds({})",
                                                i
                                            )));
                                        }
                                        i as usize
                                    } else if let Some(u) = n.as_u64() {
                                        u as usize
                                    } else {
                                        return Err(PolicyEngineError::CompilationError(
                                            "Array index must be an integer".into(),
                                        ));
                                    }
                                }
                                _ => {
                                    return Err(PolicyEngineError::CompilationError(
                                        "Array index must be an integer".into(),
                                    ))
                                }
                            };

                            if idx < arr.len() {
                                Ok(arr[idx].clone())
                            } else {
                                Err(PolicyEngineError::EvaluationError(format!(
                                    "IndexOutOfBounds({})",
                                    idx
                                )))
                            }
                        }
                        JsonValue::String(s) => {
                            let idx = match idx_val {
                                JsonValue::Number(n) => {
                                    if let Some(i) = n.as_i64() {
                                        if i < 0 {
                                            return Err(PolicyEngineError::EvaluationError(format!(
                                                "IndexOutOfBounds({})",
                                                i
                                            )));
                                        }
                                        i as usize
                                    } else if let Some(u) = n.as_u64() {
                                        u as usize
                                    } else {
                                        return Err(PolicyEngineError::CompilationError(
                                            "String index must be an integer".into(),
                                        ));
                                    }
                                }
                                _ => {
                                    return Err(PolicyEngineError::CompilationError(
                                        "String index must be an integer".into(),
                                    ))
                                }
                            };

                            // SECURITY (AUDIT-W4-CEL-103): exact fail-closed
                            // contract for string indexing. The third-party
                            // interpreter slices BYTES (`str::get(idx..idx+1)`)
                            // and coalesces out-of-range AND misaligned
                            // (non-char-boundary) AND multibyte accesses to
                            // `Null` — which makes negated positional rules
                            // vacuously true. The previous pre-check modeled
                            // CHAR indices and fabricated '\0' via
                            // `unwrap_or('\0')`, so the verdict depended on
                            // which evaluator won. Indexing is now defined
                            // ONLY for in-range ASCII positions; anything else
                            // fails closed.
                            if idx >= s.len()
                                || !s.is_char_boundary(idx)
                                || !s.as_bytes()[idx].is_ascii()
                            {
                                return Err(PolicyEngineError::EvaluationError(format!(
                                    "StringIndexUndefined({}): string indexing is only \
                                     defined for in-range single-byte character positions",
                                    idx
                                )));
                            }
                            Ok(JsonValue::String(
                                (s.as_bytes()[idx] as char).to_string(),
                            ))
                        }
                        _ => Err(PolicyEngineError::EvaluationError(
                            "Cannot index into non-container type".into(),
                        )),
                    }
                } else if func_name == "_&&_" {
                    if call.args.len() != 2 {
                        return Err(PolicyEngineError::CompilationError(
                            "Invalid && call args length".into(),
                        ));
                    }
                    let lhs = Self::eval_and_check_ast(&call.args[0], env, depth + 1, iter_budget)?;
                    if lhs == JsonValue::Bool(false) {
                        Ok(JsonValue::Bool(false))
                    } else if lhs == JsonValue::Bool(true) {
                        let rhs = Self::eval_and_check_ast(&call.args[1], env, depth + 1, iter_budget)?;
                        if let JsonValue::Bool(b) = rhs {
                            Ok(JsonValue::Bool(b))
                        } else {
                            Ok(rhs)
                        }
                    } else {
                        let _ = Self::eval_and_check_ast(&call.args[1], env, depth + 1, iter_budget)?;
                        Ok(JsonValue::Bool(false))
                    }
                } else if func_name == "_||_" {
                    if call.args.len() != 2 {
                        return Err(PolicyEngineError::CompilationError(
                            "Invalid || call args length".into(),
                        ));
                    }
                    let lhs = Self::eval_and_check_ast(&call.args[0], env, depth + 1, iter_budget)?;
                    if lhs == JsonValue::Bool(true) {
                        Ok(JsonValue::Bool(true))
                    } else if lhs == JsonValue::Bool(false) {
                        let rhs = Self::eval_and_check_ast(&call.args[1], env, depth + 1, iter_budget)?;
                        if let JsonValue::Bool(b) = rhs {
                            Ok(JsonValue::Bool(b))
                        } else {
                            Ok(rhs)
                        }
                    } else {
                        let _ = Self::eval_and_check_ast(&call.args[1], env, depth + 1, iter_budget)?;
                        Ok(JsonValue::Bool(true))
                    }
                } else if func_name == "!_" {
                    if call.args.len() != 1 {
                        return Err(PolicyEngineError::CompilationError(
                            "Invalid ! call args length".into(),
                        ));
                    }
                    let arg = Self::eval_and_check_ast(&call.args[0], env, depth + 1, iter_budget)?;
                    if let JsonValue::Bool(b) = arg {
                        Ok(JsonValue::Bool(!b))
                    } else {
                        Ok(JsonValue::Null)
                    }
                } else if func_name == "_?_:_" {
                    if call.args.len() != 3 {
                        return Err(PolicyEngineError::CompilationError(
                            "Invalid ternary call args length".into(),
                        ));
                    }
                    let cond = Self::eval_and_check_ast(&call.args[0], env, depth + 1, iter_budget)?;
                    if cond == JsonValue::Bool(true) {
                        Self::eval_and_check_ast(&call.args[1], env, depth + 1, iter_budget)
                    } else if cond == JsonValue::Bool(false) {
                        Self::eval_and_check_ast(&call.args[2], env, depth + 1, iter_budget)
                    } else {
                        let _ = Self::eval_and_check_ast(&call.args[1], env, depth + 1, iter_budget)?;
                        let _ = Self::eval_and_check_ast(&call.args[2], env, depth + 1, iter_budget)?;
                        Ok(JsonValue::Null)
                    }
                } else if func_name == "_==_" {
                    if call.args.len() != 2 {
                        return Err(PolicyEngineError::CompilationError(
                            "Invalid == call args length".into(),
                        ));
                    }
                    let lhs = Self::eval_and_check_ast(&call.args[0], env, depth + 1, iter_budget)?;
                    let rhs = Self::eval_and_check_ast(&call.args[1], env, depth + 1, iter_budget)?;
                    Ok(JsonValue::Bool(lhs == rhs))
                } else if func_name == "_!=_" {
                    if call.args.len() != 2 {
                        return Err(PolicyEngineError::CompilationError(
                            "Invalid != call args length".into(),
                        ));
                    }
                    let lhs = Self::eval_and_check_ast(&call.args[0], env, depth + 1, iter_budget)?;
                    let rhs = Self::eval_and_check_ast(&call.args[1], env, depth + 1, iter_budget)?;
                    Ok(JsonValue::Bool(lhs != rhs))
                } else if matches!(
                    func_name,
                    "_<_" | "_<=_" | "_>_" | "_>=_"
                ) {
                    // AUDIT-M03-003 fail-closed guard: cel-interpreter compares two
                    // strings LEXICOGRAPHICALLY ("15" < "9" -> true), which lets
                    // magnitude limits over string-typed decimal amounts pass for
                    // violating values. Ordering is only delegated to the
                    // interpreter when BOTH operands are JSON numbers; every other
                    // combination (notably decimal strings) is rejected here.
                    // This intentionally leaves amount serialization (String)
                    // untouched; authors must use domain-aware helpers such as
                    // `check_decimals` or exact membership (`in [...]`) instead of
                    // raw ordering over string amounts.
                    if call.args.len() != 2 {
                        return Err(PolicyEngineError::CompilationError(
                            "Invalid ordering operator args length".into(),
                        ));
                    }
                    let lhs = Self::eval_and_check_ast(&call.args[0], env, depth + 1, iter_budget)?;
                    let rhs = Self::eval_and_check_ast(&call.args[1], env, depth + 1, iter_budget)?;
                    match (&lhs, &rhs) {
                        (JsonValue::Number(_), JsonValue::Number(_)) => Ok(JsonValue::Null),
                        _ => Err(PolicyEngineError::EvaluationError(format!(
                            "Ordering comparison '{func_name}' requires numeric operands \
                             (lexicographic string ordering is not permitted), got: {lhs:?} vs {rhs:?}"
                        ))),
                    }
                } else if func_name == "_in_" {
                    if call.args.len() != 2 {
                        return Err(PolicyEngineError::CompilationError(
                            "Invalid in call args length".into(),
                        ));
                    }
                    let item = Self::eval_and_check_ast(&call.args[0], env, depth + 1, iter_budget)?;
                    let container = Self::eval_and_check_ast(&call.args[1], env, depth + 1, iter_budget)?;
                    match container {
                        JsonValue::Array(arr) => Ok(JsonValue::Bool(arr.contains(&item))),
                        JsonValue::Object(map) => {
                            if let JsonValue::String(k) = item {
                                Ok(JsonValue::Bool(map.contains_key(&k)))
                            } else {
                                Ok(JsonValue::Bool(false))
                            }
                        }
                        _ => Ok(JsonValue::Bool(false)),
                    }
                } else if func_name == "size" {
                    let target = if let Some(t) = &call.target {
                        Self::eval_and_check_ast(t, env, depth + 1, iter_budget)?
                    } else if !call.args.is_empty() {
                        Self::eval_and_check_ast(&call.args[0], env, depth + 1, iter_budget)?
                    } else {
                        return Err(PolicyEngineError::CompilationError(
                            "size requires an argument".into(),
                        ));
                    };
                    match target {
                        JsonValue::Array(arr) => Ok(JsonValue::Number((arr.len() as i64).into())),
                        JsonValue::String(s) => Ok(JsonValue::Number((s.len() as i64).into())),
                        JsonValue::Object(map) => Ok(JsonValue::Number((map.len() as i64).into())),
                        _ => Ok(JsonValue::Number(0.into())),
                    }
                } else if func_name == "check_decimals" {
                    if call.args.len() != 2 {
                        return Err(PolicyEngineError::CompilationError(
                            "check_decimals requires 2 arguments".into(),
                        ));
                    }
                    let amt = Self::eval_and_check_ast(&call.args[0], env, depth + 1, iter_budget)?;
                    let places = Self::eval_and_check_ast(&call.args[1], env, depth + 1, iter_budget)?;
                    if let (JsonValue::String(s), JsonValue::Number(n)) = (amt, places) {
                        if let Some(p) = n.as_i64() {
                            if !(0..=18).contains(&p) {
                                return Ok(JsonValue::Bool(false));
                            }
                            if let Ok(dec) = Decimal::from_str(&s) {
                                return Ok(JsonValue::Bool(dec.scale() <= p as u32));
                            }
                        }
                    }
                    Ok(JsonValue::Bool(false))
                } else {
                    if let Some(target) = &call.target {
                        let _ = Self::eval_and_check_ast(target, env, depth + 1, iter_budget)?;
                    }
                    for arg in &call.args {
                        let _ = Self::eval_and_check_ast(arg, env, depth + 1, iter_budget)?;
                    }
                    Ok(JsonValue::Null)
                }
            }
            Expr::List(list) => {
                let mut elements = Vec::new();
                for elem in &list.elements {
                    elements.push(Self::eval_and_check_ast(elem, env, depth + 1, iter_budget)?);
                }
                Ok(JsonValue::Array(elements))
            }
            Expr::Map(map) => {
                let mut obj = serde_json::Map::new();
                for entry in &map.entries {
                    if let EntryExpr::MapEntry(me) = &entry.expr {
                        let key_val = Self::eval_and_check_ast(&me.key, env, depth + 1, iter_budget)?;
                        let val = Self::eval_and_check_ast(&me.value, env, depth + 1, iter_budget)?;
                        if let JsonValue::String(k) = key_val {
                            obj.insert(k, val);
                        }
                    }
                }
                Ok(JsonValue::Object(obj))
            }
            Expr::Comprehension(comp) => {                let range_val = Self::eval_and_check_ast(&comp.iter_range, env, depth + 1, iter_budget)?;
                // AUDIT-M03-007 / AUDIT-M03-008: cel-interpreter 0.10.0 supports
                // ONLY List and Map ranges: every other range type ends in an
                // uncatchable `todo!()` panic (objects.rs), and Map ranges
                // iterate a RandomState HashMap whose order rotates per
                // instance (non-deterministic verdicts). Both violate the
                // fail-closed and determinism invariants, therefore ANY
                // non-array range is rejected here before reaching the
                // interpreter. Legitimate rules comprehend over arrays.
                let arr = match range_val {
                    JsonValue::Array(arr) => arr,
                    JsonValue::Null => {
                        return Err(PolicyEngineError::EvaluationError(
                            "cannot iterate non-array comprehension range (got null)".into(),
                        ));
                    }
                    JsonValue::Bool(_) => {
                        return Err(PolicyEngineError::EvaluationError(
                            "cannot iterate non-array comprehension range (got boolean)".into(),
                        ));
                    }
                    JsonValue::Number(_) => {
                        return Err(PolicyEngineError::EvaluationError(
                            "cannot iterate non-array comprehension range (got number)".into(),
                        ));
                    }
                    JsonValue::String(_) => {
                        return Err(PolicyEngineError::EvaluationError(
                            "cannot iterate non-array comprehension range (got string)".into(),
                        ));
                    }
                    JsonValue::Object(_) => {
                        return Err(PolicyEngineError::EvaluationError(
                            "cannot iterate non-array comprehension range (map ranges are \
                             unsupported because key iteration order is non-deterministic)"
                                .into(),
                        ));
                    }
                };
                let mut accu = Self::eval_and_check_ast(&comp.accu_init, env, depth + 1, iter_budget)?;
                for item in arr {
                    // AUDIT-M03-005: the whole environment (including the
                    // iterated state) is cloned per iteration -> O(n²).
                    // Enforce a hard total-iteration budget.
                    if *iter_budget == 0 {
                        return Err(PolicyEngineError::EvaluationError(
                            "CEL comprehension iteration budget exceeded".into(),
                        ));
                    }
                    *iter_budget -= 1;
                    let mut loop_env = env.clone();
                    loop_env.insert(comp.iter_var.clone(), item);
                    loop_env.insert(comp.accu_var.clone(), accu.clone());

                    let cond = Self::eval_and_check_ast(&comp.loop_cond, &loop_env, depth + 1, iter_budget)?;
                    if cond == JsonValue::Bool(false) {
                        break;
                    }

                    accu = Self::eval_and_check_ast(&comp.loop_step, &loop_env, depth + 1, iter_budget)?;
                }
                let mut final_env = env.clone();
                final_env.insert(comp.accu_var.clone(), accu);
                Self::eval_and_check_ast(&comp.result, &final_env, depth + 1, iter_budget)
            }
            // SECURITY (AUDIT-W4-CEL-101): message/struct literals (`T{...}`)
            // previously fell through the catch-all WITHOUT visiting any
            // child, so `Program::execute` later hit the third-party
            // interpreter's uncatchable `todo!("Support structs!")`
            // (cel-interpreter objects.rs) — a process abort during routine
            // voucher validation. Fail closed with a normal error instead.
            Expr::Struct(_) => Err(PolicyEngineError::EvaluationError(
                "Message/struct literals are not supported by the policy engine".into(),
            )),
        }
    }

    /// Recursively converts `serde_json::Value` to `cel_interpreter::Value`
    fn json_to_cel(json: &JsonValue) -> Result<Value, PolicyEngineError> {
        match json {
            JsonValue::Null => Ok(Value::Null),
            JsonValue::Bool(b) => Ok(Value::Bool(*b)),
            JsonValue::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(Value::Int(i))
                } else if let Some(u) = n.as_u64() {
                    // CEL natively supports UInt (u64) for large positive limits
                    Ok(Value::UInt(u))
                } else if let Some(f) = n.as_f64() {
                    Ok(Value::Float(f))
                } else {
                    Err(PolicyEngineError::TypeMismatch(
                        "Unsupported number type".into(),
                    ))
                }
            }
            JsonValue::String(s) => Ok(Value::String(s.clone().into())),
            JsonValue::Array(arr) => {
                let mut cel_arr = Vec::new();
                for item in arr {
                    cel_arr.push(Self::json_to_cel(item)?);
                }
                Ok(Value::List(cel_arr.into()))
            }
            JsonValue::Object(obj) => {
                let mut cel_map: HashMap<String, Value> = HashMap::new();
                for (k, v) in obj {
                    cel_map.insert(k.clone(), Self::json_to_cel(v)?);
                }
                Ok(Value::Map(cel_map.into()))
            }
        }
    }

    /// Registers the custom functions needed for checking domains (like Decimal checks)
    fn register_custom_functions(context: &mut Context) {
        // Implementation of the custom function specified in .dev/Business Rules Engines.md
        context.add_function("check_decimals", |amount_str: std::sync::Arc<String>, max_places: i64| -> bool {
            if !(0..=18).contains(&max_places) {
                return false;
            }
            if let Ok(dec) = Decimal::from_str(&amount_str) {
                return dec.scale() <= max_places as u32;
            }
            false
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_evaluate_dynamic_rules_cel_engine_core() {
        let voucher_json = json!({
            "nominal_value": {
                "amount": "50.000",
                "unit": "Minuto"
            },
            "signatures": [
                { "role": "creator" },
                { "role": "guarantor", "details": { "gender": "1" } },
                { "role": "guarantor", "details": { "gender": "2" } }
            ]
        });

        // Basic object access
        assert_eq!(
            DynamicPolicyEngine::evaluate_rule("Voucher.nominal_value.unit == 'Minuto'", &voucher_json, None),
            Ok(true)
        );

        // Test the injected custom function check_decimals
        // 50.000 has 3 decimal places
        assert_eq!(
            DynamicPolicyEngine::evaluate_rule("check_decimals(Voucher.nominal_value.amount, 3)", &voucher_json, None),
            Ok(true)
        );
        assert_eq!(
            DynamicPolicyEngine::evaluate_rule("check_decimals(Voucher.nominal_value.amount, 2)", &voucher_json, None),
            Ok(false) // Fails correctly because 3 > 2
        );
    }
}
