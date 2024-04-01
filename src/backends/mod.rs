use ark_ff::Field;

use crate::{circuit_writer::GateKind, constants::Span, helpers::PrettyField, var::{CellVar, ConstOrCell, Value, Var}};

pub mod kimchi;
pub mod r1cs;

pub trait Backend<F: Field + PrettyField> {
    fn new_internal_var<B: Backend<F>>(&mut self, val: Value<F, B>, span: Span) -> CellVar;
    
    fn add_constant(&mut self, label: Option<&'static str>, value: F, span: Span) -> CellVar;

    // TODO: change gate related functions to be more generic for different backends
    fn add_gate(
        &mut self,
        note: &'static str,
        typ: GateKind,
        vars: Vec<Option<CellVar>>,
        coeffs: Vec<F>,
        span: Span,
    );

    fn add_generic_gate(
        &mut self,
        label: &'static str,
        vars: Vec<Option<CellVar>>,
        coeffs: Vec<F>,
        span: Span,
    );

    // boolean constraints
    fn is_valid(&self, f: F) -> bool {
        f.is_one() || f.is_zero()
    }

    fn check(
        &self,
        xx: &ConstOrCell<F>,
        span: Span,
    );

    fn and(
        &self,
        lhs: &ConstOrCell<F>,
        rhs: &ConstOrCell<F>,
        span: Span,
    ) -> Var<F>;

    fn not(
        &self,
        var: &ConstOrCell<F>,
        span: Span,
    ) -> Var<F>;

    fn or(
        &self,
        lhs: &ConstOrCell<F>,
        rhs: &ConstOrCell<F>,
        span: Span,
    ) -> Var<F>;

    // field constraints
    fn add(
        &self,
        lhs: &ConstOrCell<F>,
        rhs: &ConstOrCell<F>,
        span: Span,
    ) -> Var<F>;

    fn sub(
        &self,
        lhs: &ConstOrCell<F>,
        rhs: &ConstOrCell<F>,
        span: Span,
    ) -> Var<F>;

    fn mul(
        &self,
        lhs: &ConstOrCell<F>,
        rhs: &ConstOrCell<F>,
        span: Span,
    ) -> Var<F>;

    fn equal(
        &self,
        lhs: &Var<F>,
        rhs: &Var<F>,
        span: Span,
    ) -> Var<F>;

    fn equal_cells(
        &self,
        x1: &ConstOrCell<F>,
        x2: &ConstOrCell<F>,
        span: Span,
    ) -> Var<F>;

    fn if_else(
        &self,
        cond: &Var<F>,
        then_: &Var<F>,
        else_: &Var<F>,
        span: Span,
    ) -> Var<F>;

    fn if_else_inner(
        &self,
        cond: &ConstOrCell<F>,
        then_: &ConstOrCell<F>,
        else_: &ConstOrCell<F>,
        span: Span,
    ) -> Var<F>;
}