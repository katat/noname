use std::{collections::HashMap, ops::Neg as _, str::FromStr};

use ark_ff::{One as _, Zero};
use once_cell::sync::Lazy;

use crate::{
    circuit_writer::{CircuitWriter, VarInfo},
    constants::{Field, Span},
    error::{Error, ErrorKind, Result},
    imports::{BuiltInFunctions, BuiltinModule, FnHandle, FnKind},
    lexer::Token,
    parser::{
        types::{FnSig, TyKind},
        ParserCtx,
    },
    type_checker::FnInfo,
    var::{ConstOrCell, Var},
};

use self::crypto::CRYPTO_FNS;

pub mod crypto;

pub static CRYPTO_MODULE: Lazy<BuiltinModule> = Lazy::new(|| {
    let functions = parse_fn_sigs(&CRYPTO_FNS);
    BuiltinModule { functions }
});

pub fn get_std_fn<F: Field>(submodule: &str, fn_name: &str, span: Span) -> Result<FnInfo<F>> {
    match submodule {
        "crypto" => CRYPTO_MODULE
            .functions
            .get(fn_name)
            .cloned()
            .ok_or_else(|| {
                Error::new(
                    "type-checker",
                    ErrorKind::UnknownExternalFn(submodule.to_string(), fn_name.to_string()),
                    span,
                )
            }),
        _ => Err(Error::new(
            "type-checker",
            ErrorKind::StdImport(submodule.to_string()),
            span,
        )),
    }
}

/// Takes a list of function signatures (as strings) and their associated function pointer,
/// returns the same list but with the parsed functions (as [FunctionSig]).
pub fn parse_fn_sigs<F: Field>(fn_sigs: &[(&str, FnHandle<F>)]) -> HashMap<String, FnInfo<F>> {
    let mut functions = HashMap::new();
    let ctx = &mut ParserCtx::default();

    for (sig, fn_ptr) in fn_sigs {
        // filename_id 0 is for builtins
        let mut tokens = Token::parse(0, sig).unwrap();

        let sig = FnSig::parse(ctx, &mut tokens).unwrap();

        functions.insert(
            sig.name.value.clone(),
            FnInfo {
                kind: FnKind::BuiltIn(sig, *fn_ptr),
                span: Span::default(),
            },
        );
    }

    functions
}

//
// Builtins or utils (imported by default)
// TODO: give a name that's useful for the user,
//       not something descriptive internally like "builtins"

pub const QUALIFIED_BUILTINS: &str = "std/builtins";

const ASSERT_FN: &str = "assert(condition: Bool)";
const ASSERT_EQ_FN: &str = "assert_eq(lhs: Field, rhs: Field)";

/// Asserts that two vars are equal.
fn assert_eq<F: Field>(compiler: &mut CircuitWriter<F>, vars: &[VarInfo<F>], span: Span) -> Result<Option<Var<F>>> {
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
            compiler.add_generic_gate(
                "constrain var - cst = 0 to check equality",
                vec![Some(*cvar)],
                vec![
                    Field::one(),
                    Field::zero(),
                    Field::zero(),
                    Field::zero(),
                    cst.neg(),
                ],
                span,
            );
        }
        (ConstOrCell::Cell(lhs), ConstOrCell::Cell(rhs)) => {
            // TODO: use permutation to check that
            compiler.add_generic_gate(
                "constrain lhs - rhs = 0 to assert that they are equal",
                vec![Some(*lhs), Some(*rhs)],
                vec![Field::one(), Field::one().neg()],
                span,
            );
        }
    }

    Ok(None)
}

/// Asserts that a condition is true.
fn assert<F: Field>(compiler: &mut CircuitWriter<F>, vars: &[VarInfo<F>], span: Span) -> Result<Option<Var<F>>> {
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
            let zero = Field::zero();
            let one = Field::one();
            compiler.add_generic_gate(
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

impl<F: Field> FromStr for BuiltInFunctions<F> {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<BuiltInFunctions<F>, ()> {
        let parse_fn = |sig: &'static str, fn_ptr: fn()| -> Result<FnInfo, ()> {
            let ctx = &mut ParserCtx::default();
            // filename_id 0 is for builtins
            let mut tokens = Token::parse(0, sig)?;
            let sig = FnSig::parse(ctx, &mut tokens)?;

            // The closure now returns an instance of BuiltInFunctions<F>
            let builtin_fn = match sig.name.value {
                ASSERT_FN => BuiltInFunctions::Assert(FnInfo {
                    kind: FnKind::BuiltIn(sig, fn_ptr),
                    span: Span::default(),
                }),
                ASSERT_EQ_FN => BuiltInFunctions::AssertEq(FnInfo {
                    kind: FnKind::BuiltIn(sig, fn_ptr),
                    span: Span::default(),
                }),
                _ => return Err(()),
            };

            Ok(builtin_fn)
        };

        match s {
            // TODO: cache parsed functions
            ASSERT_FN => parse_fn(ASSERT_FN, assert),
            ASSERT_EQ_FN => parse_fn(ASSERT_EQ_FN, assert_eq),
            _ => Err(()),
        }
    }
}
