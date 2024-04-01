use ark_ff::Field;

use crate::{
    backends::Backend, circuit_writer::CircuitWriter, constants::Span, helpers::PrettyField, var::{ConstOrCell, Var}
};

// pub mod boolean;
// pub mod field;

pub trait BooleanConstraints<F: Field + PrettyField, B: Backend<F>> {
    fn is_valid(&self, f: F) -> bool {
        f.is_one() || f.is_zero()
    }

    fn check(
        &self,
        compiler: &mut CircuitWriter<F, B>,
        xx: &ConstOrCell<F>,
        span: Span,
    );

    fn and(
        &self,
        compiler: &mut CircuitWriter<F, B>,
        lhs: &ConstOrCell<F>,
        rhs: &ConstOrCell<F>,
        span: Span,
    ) -> Var<F>;

    fn not(
        &self,
        compiler: &mut CircuitWriter<F, B>,
        var: &ConstOrCell<F>,
        span: Span,
    ) -> Var<F>;

    fn or(
        &self,
        compiler: &mut CircuitWriter<F, B>,
        lhs: &ConstOrCell<F>,
        rhs: &ConstOrCell<F>,
        span: Span,
    ) -> Var<F>;
}

pub trait FieldConstraints<F: Field + PrettyField, B: Backend<F>> {
    fn add(
        &self,
        compiler: &mut CircuitWriter<F, B>,
        lhs: &ConstOrCell<F>,
        rhs: &ConstOrCell<F>,
        span: Span,
    ) -> Var<F>;

    fn sub(
        &self,
        compiler: &mut CircuitWriter<F, B>,
        lhs: &ConstOrCell<F>,
        rhs: &ConstOrCell<F>,
        span: Span,
    ) -> Var<F>;

    fn mul(
        &self,
        compiler: &mut CircuitWriter<F, B>,
        lhs: &ConstOrCell<F>,
        rhs: &ConstOrCell<F>,
        span: Span,
    ) -> Var<F>;

    fn equal(
        &self,
        compiler: &mut CircuitWriter<F, B>,
        lhs: &Var<F>,
        rhs: &Var<F>,
        span: Span,
    ) -> Var<F>;

    fn equal_cells(
        &self,
        compiler: &mut CircuitWriter<F, B>,
        x1: &ConstOrCell<F>,
        x2: &ConstOrCell<F>,
        span: Span,
    ) -> Var<F>;

    fn if_else(
        &self,
        compiler: &mut CircuitWriter<F, B>,
        cond: &Var<F>,
        then_: &Var<F>,
        else_: &Var<F>,
        span: Span,
    ) -> Var<F>;

    fn if_else_inner(
        &self,
        compiler: &mut CircuitWriter<F, B>,
        cond: &ConstOrCell<F>,
        then_: &ConstOrCell<F>,
        else_: &ConstOrCell<F>,
        span: Span,
    ) -> Var<F>;
}
