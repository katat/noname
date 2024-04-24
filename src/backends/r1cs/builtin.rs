use ark_bls12_381::Fr;

use crate::{
    circuit_writer::{CircuitWriter, GateKind, VarInfo},
    constants::Span,
    error::{ErrorKind, Result},
    parser::types::TyKind,
    var::{ConstOrCell, Value, Var},
};

use super::R1CS;

pub fn poseidon(
    compiler: &mut CircuitWriter<R1CS>,
    vars: &[VarInfo<Fr>],
    span: Span,
) -> Result<Option<Var<Fr>>> {
    // dummy for now
    Ok(Some(Var::new_constant(Fr::from(0), span)))
}
