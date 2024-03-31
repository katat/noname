use std::{collections::HashMap, fmt};

use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

use crate::{
    backends::Backend,
    circuit_writer::{CircuitWriter, VarInfo},
    constants::{Field, Span},
    error::Result,
    helpers::PrettyField,
    lexer::Token,
    parser::{
        types::{FnSig, FunctionDef},
        ParserCtx,
    },
    type_checker::{FnInfo, TypeChecker},
    var::Var,
};

#[derive(Debug)]
pub struct Module<F>
where
    F: Field,
{
    pub name: String,
    pub kind: ModuleKind<F>,
}

#[derive(Debug)]
pub enum ModuleKind<F>
where
    F: Field,
{
    /// A module that contains only built-in functions.
    BuiltIn(BuiltinModule<F>),

    /// A module that contains both built-in functions and native functions.
    Native(TypeChecker<F>),
}

#[derive(Debug, Clone)]
pub struct BuiltinModule<F>
where
    F: Field,
{
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
pub type FnHandle<F: Field, B: Backend<F>> =
    fn(&mut CircuitWriter<F, B>, &[VarInfo<F>], Span) -> Result<Option<Var<F>>>;

/// The different types of a noname function.
#[derive(Clone, Serialize, Deserialize)]
pub enum FnKind<F, B>
where
    F: Field, B: Backend<F>
{
    /// A built-in is just a handle to a function written in Rust.
    #[serde(skip)]
    BuiltIn(FnSig, FnHandle<F, B>),

    /// A native function is represented as an AST.
    Native(FunctionDef),
}

impl<F: Field, B: Backend<F>> fmt::Debug for FnKind<F, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<fnkind>")
    }
}

const ASSERT_FN: &str = "assert(condition: Bool)";
const ASSERT_EQ_FN: &str = "assert_eq(lhs: Field, rhs: Field)";

pub enum BuiltInFunctions<F: Field> {
    Assert(FnInfo<F>),
    AssertEq(FnInfo<F>),
}

impl<F: Field + PrettyField> BuiltInFunctions<F> {
    pub fn fn_info(&self) -> &FnInfo<F> {
        match self {
            BuiltInFunctions::Assert(fn_info) => fn_info,
            BuiltInFunctions::AssertEq(fn_info) => fn_info,
        }
    }

    // TODO: cache the functions, so it won't need to rerun this code that is unnecesasry
    pub fn functions() -> Vec<BuiltInFunctions<F>> {
        // TODO: this makes the code difficult to maintain. there are probably better ways to do this.
        let fn_names = [ASSERT_FN, ASSERT_EQ_FN];

        // create a collection of FnInfo from fn_names
        fn_names
            .iter()
            .map(|fn_name| BuiltInFunctions::<F>::from_str(fn_name).unwrap())
            .collect::<Vec<BuiltInFunctions<F>>>()
    }
}
