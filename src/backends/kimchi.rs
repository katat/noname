use std::collections::HashMap;

use ark_ff::Field;
use kimchi::circuits::polynomials::generic::{GENERIC_COEFFS, GENERIC_REGISTERS};

use crate::{
    circuit_writer::{
        writer::{AnnotatedCell, Cell, PendingGate},
        DebugInfo, Gate, GateKind, Wiring,
    },
    constants::{Span, NUM_REGISTERS},
    constraints::{BooleanConstraints, FieldConstraints},
    helpers::PrettyField,
    imports::BuiltInFunctions,
    var::{CellVar, ConstOrCell, Value, Var},
};

use super::Backend;

#[derive(Debug)]
pub struct KimchiBackend<F>
where
    F: Field,
{
    /// The gates created by the circuit generation.
    pub gates: Vec<Gate<F>>,

    /// The wiring of the circuit.
    /// It is created during circuit generation.
    pub(crate) wiring: HashMap<usize, Wiring>,

    /// If set to false, a single generic gate will be used per double generic gate.
    /// This can be useful for debugging.
    pub(crate) double_generic_gate_optimization: bool,

    /// This is used to implement the double generic gate,
    /// which encodes two generic gates.
    pub(crate) pending_generic_gate: Option<PendingGate<F>>,

    /// The execution trace table with vars as placeholders.
    /// It is created during circuit generation,
    /// and used by the witness generator.
    pub(crate) rows_of_vars: Vec<Vec<Option<CellVar>>>,

    /// A vector of debug information that maps to each row of the created circuit.
    pub(crate) debug_info: Vec<DebugInfo>,
}

impl<F: Field> KimchiBackend<F> {
    /// creates a new gate, and the associated row in the witness/execution trace.
    // TODO: add_gate instead of gates?
    pub fn add_gate(
        &mut self,
        note: &'static str,
        typ: GateKind,
        vars: Vec<Option<CellVar>>,
        coeffs: Vec<F>,
        span: Span,
    ) {
        // sanitize
        assert!(coeffs.len() <= NUM_REGISTERS);
        assert!(vars.len() <= NUM_REGISTERS);

        // construct the execution trace with vars, for the witness generation
        self.rows_of_vars.push(vars.clone());

        // get current row
        // important: do that before adding the gate below
        let row = self.gates.len();

        // add gate
        self.gates.push(Gate { typ, coeffs });

        // add debug info related to that gate
        let debug_info = DebugInfo {
            span,
            note: note.to_string(),
        };
        self.debug_info.push(debug_info.clone());

        // wiring (based on vars)
        for (col, var) in vars.iter().enumerate() {
            if let Some(var) = var {
                let curr_cell = Cell { row, col };
                let annotated_cell = AnnotatedCell {
                    cell: curr_cell,
                    debug: debug_info.clone(),
                };

                self.wiring
                    .entry(var.index)
                    .and_modify(|w| match w {
                        Wiring::NotWired(old_cell) => {
                            *w = Wiring::Wired(vec![old_cell.clone(), annotated_cell.clone()])
                        }
                        Wiring::Wired(ref mut cells) => {
                            cells.push(annotated_cell.clone());
                        }
                    })
                    .or_insert(Wiring::NotWired(annotated_cell));
            }
        }
    }

    pub fn add_generic_gate(
        &mut self,
        label: &'static str,
        mut vars: Vec<Option<CellVar>>,
        mut coeffs: Vec<F>,
        span: Span,
    ) {
        // padding
        let coeffs_padding = GENERIC_COEFFS.checked_sub(coeffs.len()).unwrap();
        coeffs.extend(std::iter::repeat(F::zero()).take(coeffs_padding));

        let vars_padding = GENERIC_REGISTERS.checked_sub(vars.len()).unwrap();
        vars.extend(std::iter::repeat(None).take(vars_padding));

        // if the double gate optimization is not set, just add the gate
        if !self.double_generic_gate_optimization {
            self.add_gate(label, GateKind::DoubleGeneric, vars, coeffs, span);
            return;
        }

        // only add a double generic gate if we have two of them
        if let Some(generic_gate) = self.pending_generic_gate.take() {
            coeffs.extend(generic_gate.coeffs);
            vars.extend(generic_gate.vars);

            // TODO: what to do with the label and span?

            self.add_gate(label, GateKind::DoubleGeneric, vars, coeffs, span);
        } else {
            // otherwise queue it
            self.pending_generic_gate = Some(PendingGate {
                label,
                coeffs,
                vars,
                span,
            });
        }
    }
}

impl<F: Field + PrettyField, B: Backend<F>> BooleanConstraints<F, B> for KimchiBackend<F> {
    fn check(
        &self,
        compiler: &mut crate::circuit_writer::CircuitWriter<F, B>,
        xx: &crate::var::ConstOrCell<F>,
        span: Span,
    ) {
        let zero = F::zero();
        let one = F::one();

        match xx {
            ConstOrCell::Const(ff) => assert!(self.is_valid(*ff)),
            ConstOrCell::Cell(var) => self.add_generic_gate(
                "constraint to validate a boolean (`x(x-1) = 0`)",
                // x^2 - x = 0
                vec![Some(*var), Some(*var), None],
                vec![one.neg(), zero, zero, one],
                span,
            ),
        };
    }

    fn and(
        &self,
        compiler: &mut crate::circuit_writer::CircuitWriter<F, B>,
        lhs: &crate::var::ConstOrCell<F>,
        rhs: &crate::var::ConstOrCell<F>,
        span: Span,
    ) -> crate::var::Var<F> {
        match (lhs, rhs) {
            // two constants
            (ConstOrCell::Const(lhs), ConstOrCell::Const(rhs)) => {
                Var::new_constant(*lhs * *rhs, span)
            }

            // constant and a var
            (ConstOrCell::Const(cst), ConstOrCell::Cell(cvar))
            | (ConstOrCell::Cell(cvar), ConstOrCell::Const(cst)) => {
                if cst.is_one() {
                    Var::new_var(*cvar, span)
                } else {
                    Var::new_constant(*cst, span)
                }
            }

            // two vars
            (ConstOrCell::Cell(lhs), ConstOrCell::Cell(rhs)) => {
                // create a new variable to store the result
                let res = compiler.new_internal_var(Value::Mul(*lhs, *rhs), span);

                // create a gate to constrain the result
                let zero = F::zero();
                let one = F::one();
                self.add_generic_gate(
                    "constrain the AND as lhs * rhs",
                    vec![Some(*lhs), Some(*rhs), Some(res)],
                    vec![zero, zero, one.neg(), one], // mul
                    span,
                );

                // return the result
                Var::new_var(res, span)
            }
        }
    }

    fn not(
        &self,
        compiler: &mut crate::circuit_writer::CircuitWriter<F, B>,
        var: &crate::var::ConstOrCell<F>,
        span: Span,
    ) -> crate::var::Var<F> {
        match var {
            ConstOrCell::Const(cst) => {
                let value = if cst.is_one() { F::zero() } else { F::one() };

                Var::new_constant(value, span)
            }

            // constant and a var
            ConstOrCell::Cell(cvar) => {
                let zero = F::zero();
                let one = F::one();

                // create a new variable to store the result
                let lc = Value::LinearCombination(vec![(one.neg(), *cvar)], one); // 1 - X
                let res = compiler.new_internal_var(lc, span);

                // create a gate to constrain the result
                self.add_generic_gate(
                    "constrain the NOT as 1 - X",
                    vec![None, Some(*cvar), Some(res)],
                    // we use the constant to do 1 - X
                    vec![zero, one.neg(), one.neg(), zero, one],
                    span,
                );

                // return the result
                Var::new_var(res, span)
            }
        }
    }

    fn or(
        &self,
        compiler: &mut crate::circuit_writer::CircuitWriter<F, B>,
        lhs: &crate::var::ConstOrCell<F>,
        rhs: &crate::var::ConstOrCell<F>,
        span: Span,
    ) -> crate::var::Var<F> {
        let not_lhs = self.not(compiler, lhs, span);
        let not_rhs = self.not(compiler, rhs, span);
        let both_false = self.and(compiler, &not_lhs[0], &not_rhs[0], span);
        self.not(compiler, &both_false[0], span)
    }
}

impl<F: Field + PrettyField, B: Backend<F>> FieldConstraints<F, B> for KimchiBackend<F> {
    fn add(
        &self,
        compiler: &mut crate::circuit_writer::CircuitWriter<F, B>,
        lhs: &ConstOrCell<F>,
        rhs: &ConstOrCell<F>,
        span: Span,
    ) -> Var<F> {
        let zero = F::zero();
        let one = F::one();

        match (lhs, rhs) {
            // 2 constants
            (ConstOrCell::Const(lhs), ConstOrCell::Const(rhs)) => {
                Var::new_constant(*lhs + *rhs, span)
            }

            // const and a var
            (ConstOrCell::Const(cst), ConstOrCell::Cell(cvar))
            | (ConstOrCell::Cell(cvar), ConstOrCell::Const(cst)) => {
                // if the constant is zero, we can ignore this gate
                if cst.is_zero() {
                    // TODO: that span is incorrect, it should come from lhs or rhs...
                    return Var::new_var(*cvar, span);
                }

                // create a new variable to store the result
                let res = compiler
                    .new_internal_var(Value::LinearCombination(vec![(one, *cvar)], *cst), span);

                self.add_generic_gate(
                    "add a constant with a variable",
                    vec![Some(*cvar), None, Some(res)],
                    vec![one, zero, one.neg(), zero, *cst],
                    span,
                );

                Var::new_var(res, span)
            }
            (ConstOrCell::Cell(lhs), ConstOrCell::Cell(rhs)) => {
                // create a new variable to store the result
                let res = compiler.new_internal_var(
                    Value::LinearCombination(vec![(F::one(), *lhs), (F::one(), *rhs)], F::zero()),
                    span,
                );

                self.add_generic_gate(
                    "add two variables together",
                    vec![Some(*lhs), Some(*rhs), Some(res)],
                    vec![F::one(), F::one(), F::one().neg()],
                    span,
                );

                Var::new_var(res, span)
            }
        }
    }

    fn sub(
        &self,
        compiler: &mut crate::circuit_writer::CircuitWriter<F, B>,
        lhs: &ConstOrCell<F>,
        rhs: &ConstOrCell<F>,
        span: Span,
    ) -> Var<F> {
        let zero = F::zero();
        let one = F::one();

        match (lhs, rhs) {
            // const1 - const2
            (ConstOrCell::Const(lhs), ConstOrCell::Const(rhs)) => {
                Var::new_constant(*lhs - *rhs, span)
            }

            // const - var
            (ConstOrCell::Const(cst), ConstOrCell::Cell(cvar)) => {
                // create a new variable to store the result
                let res = compiler.new_internal_var(
                    Value::LinearCombination(vec![(one.neg(), *cvar)], *cst),
                    span,
                );

                // create a gate to store the result
                self.add_generic_gate(
                    "constant - variable",
                    vec![Some(*cvar), None, Some(res)],
                    // cst - cvar - out = 0
                    vec![one.neg(), zero, one.neg(), zero, *cst],
                    span,
                );

                Var::new_var(res, span)
            }

            // var - const
            (ConstOrCell::Cell(cvar), ConstOrCell::Const(cst)) => {
                // if the constant is zero, we can ignore this gate
                if cst.is_zero() {
                    // TODO: that span is incorrect, it should come from lhs or rhs...
                    return Var::new_var(*cvar, span);
                }

                // create a new variable to store the result
                let res = compiler.new_internal_var(
                    Value::LinearCombination(vec![(one, *cvar)], cst.neg()),
                    span,
                );

                // create a gate to store the result
                // TODO: we should use an add_generic function that takes advantage of the double generic gate
                self.add_generic_gate(
                    "variable - constant",
                    vec![Some(*cvar), None, Some(res)],
                    // var - cst - out = 0
                    vec![one, zero, one.neg(), zero, cst.neg()],
                    span,
                );

                Var::new_var(res, span)
            }

            // lhs - rhs
            (ConstOrCell::Cell(lhs), ConstOrCell::Cell(rhs)) => {
                // create a new variable to store the result
                let res = compiler.new_internal_var(
                    Value::LinearCombination(vec![(one, *lhs), (one.neg(), *rhs)], zero),
                    span,
                );

                // create a gate to store the result
                self.add_generic_gate(
                    "var1 - var2",
                    vec![Some(*lhs), Some(*rhs), Some(res)],
                    // lhs - rhs - out = 0
                    vec![one, one.neg(), one.neg()],
                    span,
                );

                Var::new_var(res, span)
            }
        }
    }

    fn mul(
        &self,
        compiler: &mut crate::circuit_writer::CircuitWriter<F, B>,
        lhs: &ConstOrCell<F>,
        rhs: &ConstOrCell<F>,
        span: Span,
    ) -> Var<F> {
        let zero = F::zero();
        let one = F::one();

        match (lhs, rhs) {
            // 2 constants
            (ConstOrCell::Const(lhs), ConstOrCell::Const(rhs)) => {
                Var::new_constant(*lhs * *rhs, span)
            }

            // const and a var
            (ConstOrCell::Const(cst), ConstOrCell::Cell(cvar))
            | (ConstOrCell::Cell(cvar), ConstOrCell::Const(cst)) => {
                // if the constant is zero, we can ignore this gate
                if cst.is_zero() {
                    let zero = compiler.add_constant(
                        Some("encoding zero for the result of 0 * var"),
                        F::zero(),
                        span,
                    );
                    return Var::new_var(zero, span);
                }

                // create a new variable to store the result
                let res = compiler.new_internal_var(Value::Scale(*cst, *cvar), span);

                // create a gate to store the result
                // TODO: we should use an add_generic function that takes advantage of the double generic gate
                self.add_generic_gate(
                    "add a constant with a variable",
                    vec![Some(*cvar), None, Some(res)],
                    vec![*cst, zero, one.neg(), zero, *cst],
                    span,
                );

                Var::new_var(res, span)
            }

            // everything is a var
            (ConstOrCell::Cell(lhs), ConstOrCell::Cell(rhs)) => {
                // create a new variable to store the result
                let res = compiler.new_internal_var(Value::Mul(*lhs, *rhs), span);

                // create a gate to store the result
                self.add_generic_gate(
                    "add two variables together",
                    vec![Some(*lhs), Some(*rhs), Some(res)],
                    vec![zero, zero, one.neg(), one],
                    span,
                );

                Var::new_var(res, span)
            }
        }
    }

    fn equal(
        &self,
        compiler: &mut crate::circuit_writer::CircuitWriter<F, B>,
        lhs: &Var<F>,
        rhs: &Var<F>,
        span: Span,
    ) -> Var<F> {
        // sanity check
        assert_eq!(lhs.len(), rhs.len());

        if lhs.len() == 1 {
            return self.equal_cells(compiler, &lhs[0], &rhs[0], span);
        }

        // create an accumulator
        let one = F::one();

        let acc = compiler.add_constant(
            Some("start accumulator at 1 for the equality check"),
            one,
            span,
        );
        let mut acc = Var::new_var(acc, span);

        for (l, r) in lhs.cvars.iter().zip(&rhs.cvars) {
            let res = self.equal_cells(compiler, l, r, span);
            acc = self.and(compiler, &res[0], &acc[0], span);
        }

        acc
    }

    fn equal_cells(
        &self,
        compiler: &mut crate::circuit_writer::CircuitWriter<F, B>,
        x1: &ConstOrCell<F>,
        x2: &ConstOrCell<F>,
        span: Span,
    ) -> Var<F> {
        // These four constraints are enough:
        //
        // 1. `diff = x2 - x1`
        // 2. `one_minus_res + res = 1`
        // 3. `res * diff = 0`
        // 4. `diff_inv * diff = one_minus_res`
        //
        // To prove this, it suffices to prove that:
        //
        // a. `diff = 0 => res = 1`.
        // b. `diff != 0 => res = 0`.
        //
        // Proof:
        //
        // a. if `diff = 0`,
        //      then using (4) `one_minus_res = 0`,
        //      then using (2) `res = 1`
        //
        // b. if `diff != 0`
        //      then using (3) `res = 0`
        //

        let zero = F::zero();
        let one = F::one();

        match (x1, x2) {
            // two constants
            (ConstOrCell::Const(x1), ConstOrCell::Const(x2)) => {
                let res = if x1 == x2 { one } else { F::zero() };
                Var::new_constant(res, span)
            }

            (x1, x2) => {
                let x1 = match x1 {
                    ConstOrCell::Const(cst) => compiler.add_constant(
                        Some("encode the lhs constant of the equality check in the circuit"),
                        *cst,
                        span,
                    ),
                    ConstOrCell::Cell(cvar) => *cvar,
                };

                let x2 = match x2 {
                    ConstOrCell::Const(cst) => compiler.add_constant(
                        Some("encode the rhs constant of the equality check in the circuit"),
                        *cst,
                        span,
                    ),
                    ConstOrCell::Cell(cvar) => *cvar,
                };

                // compute the result
                let res = compiler.new_internal_var(
                    Value::Hint(Box::new(move |compiler, env| {
                        let x1 = compiler.compute_var(env, x1)?;
                        let x2 = compiler.compute_var(env, x2)?;
                        if x1 == x2 {
                            Ok(F::one())
                        } else {
                            Ok(F::zero())
                        }
                    })),
                    span,
                );

                // 1. diff = x2 - x1
                let diff = compiler.new_internal_var(
                    Value::LinearCombination(vec![(one, x2), (one.neg(), x1)], zero),
                    span,
                );

                self.add_generic_gate(
                    "constraint #1 for the equals gadget (x2 - x1 - diff = 0)",
                    vec![Some(x2), Some(x1), Some(diff)],
                    // x2 - x1 - diff = 0
                    vec![one, one.neg(), one.neg()],
                    span,
                );

                // 2. one_minus_res = 1 - res
                let one_minus_res = compiler
                    .new_internal_var(Value::LinearCombination(vec![(one.neg(), res)], one), span);

                self.add_generic_gate(
                    "constraint #2 for the equals gadget (one_minus_res + res - 1 = 0)",
                    vec![Some(one_minus_res), Some(res)],
                    // we constrain one_minus_res + res - 1 = 0
                    // so that we can encode res and wire it elsewhere
                    // (and not -res)
                    vec![one, one, zero, zero, one.neg()],
                    span,
                );

                // 3. res * diff = 0
                self.add_generic_gate(
                    "constraint #3 for the equals gadget (res * diff = 0)",
                    vec![Some(res), Some(diff)],
                    // res * diff = 0
                    vec![zero, zero, zero, one],
                    span,
                );

                // 4. diff_inv * diff = one_minus_res
                let diff_inv = compiler.new_internal_var(Value::Inverse(diff), span);

                self.add_generic_gate(
                    "constraint #4 for the equals gadget (diff_inv * diff = one_minus_res)",
                    vec![Some(diff_inv), Some(diff), Some(one_minus_res)],
                    // diff_inv * diff - one_minus_res = 0
                    vec![zero, zero, one.neg(), one],
                    span,
                );

                Var::new_var(res, span)
            }
        }
    }

    fn if_else(
        &self,
        compiler: &mut crate::circuit_writer::CircuitWriter<F, B>,
        cond: &Var<F>,
        then_: &Var<F>,
        else_: &Var<F>,
        span: Span,
    ) -> Var<F> {
        assert_eq!(cond.len(), 1);
        assert_eq!(then_.len(), else_.len());

        let cond = cond[0];

        let mut vars = vec![];

        for (then_, else_) in then_.cvars.iter().zip(&else_.cvars) {
            let var = self.if_else_inner(compiler, &cond, then_, else_, span);
            vars.push(var[0]);
        }

        Var::new(vars, span)
    }

    fn if_else_inner(
        &self,
        compiler: &mut crate::circuit_writer::CircuitWriter<F, B>,
        cond: &ConstOrCell<F>,
        then_: &ConstOrCell<F>,
        else_: &ConstOrCell<F>,
        span: Span,
    ) -> Var<F> {
        // we need to constrain:
        //
        // * res = (1 - cond) * else + cond * then
        //

        // if cond is constant, easy
        let cond_cell = match cond {
            ConstOrCell::Const(cond) => {
                if cond.is_one() {
                    return Var::new_cvar(*then_, span);
                } else {
                    return Var::new_cvar(*else_, span);
                }
            }
            ConstOrCell::Cell(cond) => *cond,
        };

        match (&then_, &else_) {
            // if the branches are constant,
            // we can create the following constraints:
            //
            // res = (1 - cond) * else + cond * then
            //
            // translates to
            //
            // cond_then = cond * then
            // temp = (1 - cond) * else =>
            //      - either
            //          - one_minus_cond = 1 - cond
            //          - one_minus_cond * else
            //      - or
            //          - cond_else = cond * else
            //          - else - cond_else
            // res - temp + cond_then = 0
            // res - X = 0
            //
            (ConstOrCell::Const(_), ConstOrCell::Const(_)) => {
                let cond_then = self.mul(compiler, then_, cond, span);
                let one = ConstOrCell::Const(F::one());
                let one_minus_cond = self.sub(compiler, &one, cond, span);
                let temp = self.mul(compiler, &one_minus_cond[0], else_, span);
                self.add(compiler, &cond_then[0], &temp[0], span)
            }

            // if one of them is a var
            //
            // res = (1 - cond) * else + cond * then
            //
            // translates to
            //
            // cond_then = cond * then
            // temp = (1 - cond) * else =>
            //      - either
            //          - one_minus_cond = 1 - cond
            //          - one_minus_cond * else
            //      - or
            //          - cond_else = cond * else
            //          - else - cond_else
            // res - temp + cond_then = 0
            // res - X = 0
            //
            _ => {
                //            let cond_inner = cond.clone();
                let then_clone = *then_;
                let else_clone = *else_;

                let res = compiler.new_internal_var(
                    Value::Hint(Box::new(move |compiler, env| {
                        let cond = compiler.compute_var(env, cond_cell)?;
                        let res_var = if cond.is_one() {
                            &then_clone
                        } else {
                            &else_clone
                        };
                        match res_var {
                            ConstOrCell::Const(cst) => Ok(*cst),
                            ConstOrCell::Cell(var) => compiler.compute_var(env, *var),
                        }
                    })),
                    span,
                );

                let then_m_else = self.sub(compiler, then_, else_, span)[0]
                    .cvar()
                    .cloned()
                    .unwrap();
                let res_m_else = self.sub(compiler, &ConstOrCell::Cell(res), else_, span)[0]
                    .cvar()
                    .cloned()
                    .unwrap();

                let zero = F::zero();
                let one = F::one();

                self.add_generic_gate(
                    "constraint for ternary operator: cond * (then - else) = res - else",
                    vec![Some(cond_cell), Some(then_m_else), Some(res_m_else)],
                    // cond * (then - else) = res - else
                    vec![zero, zero, one.neg(), one],
                    span,
                );

                Var::new_var(res, span)
            }
        }
    }
}
