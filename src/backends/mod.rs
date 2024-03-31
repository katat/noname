use ark_ff::Field;

use crate::constraints::{BooleanConstraints, FieldConstraints};

pub mod kimchi;
pub mod r1cs;

pub trait Backend<F: Field>: BooleanConstraints<F, Self> + FieldConstraints<F, Self> {}