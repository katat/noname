use std::{collections::HashMap, fmt};

use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

use crate::{
    circuit_writer::{CircuitWriter, VarInfo}, constants::{Field, Span}, error::Result, lexer::Token, parser::{types::{FnSig, FunctionDef}, ParserCtx}, type_checker::{FnInfo, TypeChecker}, var::Var
};

#[derive(Debug)]
pub struct Module<F> where F: Field {
    pub name: String,
    pub kind: ModuleKind<F>,
}

#[derive(Debug)]
pub enum ModuleKind<F> where F: Field {
    /// A module that contains only built-in functions.
    BuiltIn(BuiltinModule<F>),

    /// A module that contains both built-in functions and native functions.
    Native(TypeChecker<F>),
}

#[derive(Debug, Clone)]
pub struct BuiltinModule<F> where F: Field {
    pub functions: HashMap<String, FnInfo<F>>,
}

/*
impl std::fmt::Debug for BuiltinModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ImportedModule {{ name: {:?}, functions: {:?}, span: {:?} }}",
            self.name,
            self.functions.keys(),
            self.span
        )
    }
}
*/

/// An actual handle to the internal function to call to resolve a built-in function call.
///
/// Note that the signature of a `FnHandle` is designed to:
/// * `&mut CircuitWriter`: take a mutable reference to the circuit writer, this is because built-ins need to be able to register new variables and add gates to the circuit
/// * `&[Var]`: take an unbounded list of variables, this is because built-ins can take any number of arguments, and different built-ins might take different types of arguments
/// * `Span`: take a span to return user-friendly errors
/// * `-> Result<Option<Var>>`: return a `Result` with an `Option` of a `Var`. This is because built-ins can return a variable, or they can return nothing. If they return nothing, then the `Option` will be `None`. If they return a variable, then the `Option` will be `Some(Var)`.
pub type FnHandle<F: Field> = fn(&mut CircuitWriter<F>, &[VarInfo<F>], Span) -> Result<Option<Var<F>>>;

/// The different types of a noname function.
#[derive(Clone, Serialize, Deserialize)]
pub enum FnKind<F> where F: Field {
    /// A built-in is just a handle to a function written in Rust.
    #[serde(skip)]
    BuiltIn(FnSig, FnHandle<F>),

    /// A native function is represented as an AST.
    Native(FunctionDef),
}

impl<F: Field> fmt::Debug for FnKind<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<fnkind>")
    }
}


const ASSERT_FN: &str = "assert(condition: Bool)";
const ASSERT_EQ_FN: &str = "assert_eq(lhs: Field, rhs: Field)";

#[derive(EnumIter)]
pub enum BuiltInFunctions<F: Field> {
    Assert(FnInfo<F>),
    AssertEq(FnInfo<F>),
}

// TODO: this makes the code difficult to maintain. there are probably better ways to do this.
impl<F: Field> BuiltInFunctions<F> {
    pub fn fn_info(&self) -> &FnInfo<F> {
        match self {
            BuiltInFunctions::Assert(fn_info) => fn_info,
            BuiltInFunctions::AssertEq(fn_info) => fn_info,
        }
    }
}

