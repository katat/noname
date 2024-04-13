use std::{collections::{HashMap, HashSet}, ops::Neg as _};

use once_cell::sync::Lazy;

use ark_ff::{One, Zero};

use crate::{
    backends::Backend,
    circuit_writer::{CircuitWriter, VarInfo},
    constants::Span,
    error::{Error, ErrorKind, Result},
    imports::{FnHandle, FnKind},
    lexer::Token,
    parser::{
        types::{FnSig, TyKind},
        ParserCtx,
    },
    type_checker::FnInfo,
    var::{ConstOrCell, Var},
};

use self::crypto::get_crypto_fn;

pub mod crypto;

//
// Builtins or utils (imported by default)
// TODO: give a name that's useful for the user,
//       not something descriptive internally like "builtins"

pub const QUALIFIED_BUILTINS: &str = "std/builtins";

const ASSERT_FN: &str = "assert(condition: Bool)";
const ASSERT_EQ_FN: &str = "assert_eq(lhs: Field, rhs: Field)";

/// List of builtin function signatures.
pub const BUILTIN_SIGS: &[&str] = &[ASSERT_FN, ASSERT_EQ_FN];

// Unique set of builtin function names, derived from function signatures.
pub static BUILTIN_FN_NAMES: Lazy<HashSet<String>> = Lazy::new(|| {
    BUILTIN_SIGS
        .iter()
        .map(|s| {
            let ctx = &mut ParserCtx::default();
            let mut tokens = Token::parse(0, s).unwrap();
            let sig = FnSig::parse(ctx, &mut tokens).unwrap();
            sig.name.value
        })
        .collect()
});

pub fn get_builtin_fn<B: Backend>(name: &str) -> Option<FnInfo<B>> {
    let ctx = &mut ParserCtx::default();
    let mut tokens = Token::parse(0, name).unwrap();
    let sig = FnSig::parse(ctx, &mut tokens).unwrap();

    let fn_handle = match name {
        ASSERT_FN => assert,
        ASSERT_EQ_FN => assert_eq,
        _ => return None,
    };

    Some(FnInfo {
        kind: FnKind::BuiltIn(sig, fn_handle),
        span: Span::default(),
    })
}

/// a function returns builtin functions
pub fn builtin_fns<B: Backend>() -> Vec<FnInfo<B>> {
    BUILTIN_SIGS
        .iter()
        .map(|sig| get_builtin_fn(sig).unwrap())
        .collect()
}

/// Asserts that two vars are equal.
fn assert_eq<B: Backend>(backend: &mut B, vars: &[VarInfo<B::Field>], span: Span) -> Result<Option<Var<B::Field>>> {
    // we get two vars
    assert_eq!(vars.len(), 2);
    let lhs_info = &vars[0];
    let rhs_info = &vars[1];

    // they are both of type field
    if !matches!(lhs_info.typ, Some(TyKind::Field | TyKind::BigInt)) {
        panic!(
            "the lhs of assert_eq must be of type Field or BigInt. It was of type {:?}",
            lhs_info.typ
        );
    }

    if !matches!(rhs_info.typ, Some(TyKind::Field | TyKind::BigInt)) {
        panic!(
            "the rhs of assert_eq must be of type Field or BigInt. It was of type {:?}",
            rhs_info.typ
        );
    }

    // retrieve the values
    let lhs_var = &lhs_info.var;
    assert_eq!(lhs_var.len(), 1);
    let lhs_cvar = &lhs_var[0];

    let rhs_var = &rhs_info.var;
    assert_eq!(rhs_var.len(), 1);
    let rhs_cvar = &rhs_var[0];

    match (lhs_cvar, rhs_cvar) {
        // two constants
        (ConstOrCell::Const(a), ConstOrCell::Const(b)) => {
            if a != b {
                return Err(Error::new(
                    "constraint-generation",
                    ErrorKind::AssertionFailed,
                    span,
                ));
            }
        }

        // a const and a var
        (ConstOrCell::Const(cst), ConstOrCell::Cell(cvar))
        | (ConstOrCell::Cell(cvar), ConstOrCell::Const(cst)) => {
            backend.add_generic_gate(
                "constrain var - cst = 0 to check equality",
                vec![Some(*cvar)],
                vec![
                    B::Field::one(),
                    B::Field::zero(),
                    B::Field::zero(),
                    B::Field::zero(),
                    cst.neg(),
                ],
                span,
            );
        }
        (ConstOrCell::Cell(lhs), ConstOrCell::Cell(rhs)) => {
            // TODO: use permutation to check that
            backend.add_generic_gate(
                "constrain lhs - rhs = 0 to assert that they are equal",
                vec![Some(*lhs), Some(*rhs)],
                vec![B::Field::one(), B::Field::one().neg()],
                span,
            );
        }
    }

    Ok(None)
}

fn assert<B: Backend>(
    backend: &mut B,
    vars: &[VarInfo<B::Field>],
    span: Span,
) -> Result<Option<Var<B::Field>>> {
    // we get a single var
    assert_eq!(vars.len(), 1);

    // of type bool
    let var_info = &vars[0];
    assert!(matches!(var_info.typ, Some(TyKind::Bool)));

    // of only one field element
    let var = &var_info.var;
    assert_eq!(var.len(), 1);
    let cond = &var[0];

    match cond {
        ConstOrCell::Const(cst) => {
            assert!(cst.is_one());
        }
        ConstOrCell::Cell(cvar) => {
            // TODO: use permutation to check that
            let zero = B::Field::zero();
            let one = B::Field::one();
            backend.add_generic_gate(
                "constrain 1 - X = 0 to assert that X is true",
                vec![None, Some(*cvar)],
                // use the constant to constrain 1 - X = 0
                vec![zero, one.neg(), zero, zero, one],
                span,
            );
        }
    }

    Ok(None)
}
