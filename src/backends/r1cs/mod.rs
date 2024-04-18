use std::collections::HashMap;

use ark_bls12_381::Fq;
use ark_ff::fields::Field;
use ark_ff::BigInteger;

use crate::{
    helpers::PrettyField,
    var::{CellVar, ConstOrCell, Value},
};

use super::Backend;

#[derive(Clone)]
pub struct R1CS {
    pub constraints: Vec<Constraint>,
    pub next_variable: usize,
    pub witness_vars: HashMap<usize, Value<R1CS>>,
}

#[derive(Clone)]
pub struct Constraint {
    pub a: LinearCombination,
    pub b: LinearCombination,
    pub c: LinearCombination,
}

#[derive(Clone)]
pub struct LinearCombination {
    pub terms: Vec<(Fq, CellVar)>,
}

impl Constraint {
    pub fn as_array(&self) -> [&LinearCombination; 3] {
        [&self.a, &self.b, &self.c]
    }
}

impl R1CS {
    pub fn new() -> Self {
        Self {
            constraints: Vec::new(),
            next_variable: 0,
            witness_vars: HashMap::new(),
        }
    }

    pub fn add_constraint(
        &mut self,
        a: LinearCombination,
        b: LinearCombination,
        c: LinearCombination,
    ) {
        self.constraints.push(Constraint { a, b, c });
    }
}

#[derive(Debug)]
pub struct GeneratedWitness {
    pub witness: HashMap<usize, Fq>,
}

impl Backend for R1CS {
    type Field = Fq;

    type GeneratedWitness = GeneratedWitness;

    fn witness_vars(&self) -> &std::collections::HashMap<usize, crate::var::Value<Self>> {
        &self.witness_vars
    }

    fn poseidon() -> crate::imports::FnHandle<Self> {
        todo!()
    }

    fn new_internal_var(
        &mut self,
        val: crate::var::Value<Self>,
        span: crate::constants::Span,
    ) -> CellVar {
        let var = CellVar::new(self.next_variable, span);
        self.next_variable += 1;

        // store it in the circuit_writer
        self.witness_vars.insert(var.index, val);

        var
    }

    fn add_constant(
        &mut self,
        label: Option<&'static str>,
        value: Self::Field,
        span: crate::constants::Span,
    ) -> CellVar {
        todo!()
    }

    fn add_gate(
        &mut self,
        note: &'static str,
        typ: crate::circuit_writer::GateKind,
        vars: Vec<Option<CellVar>>,
        coeffs: Vec<Self::Field>,
        span: crate::constants::Span,
    ) {
        todo!()
    }

    fn add_generic_gate(
        &mut self,
        label: &'static str,
        vars: Vec<Option<CellVar>>,
        coeffs: Vec<Self::Field>,
        span: crate::constants::Span,
    ) {
        todo!()
    }

    fn finalize_circuit(
        &mut self,
        public_output: Option<crate::var::Var<Self::Field>>,
        returned_cells: Option<Vec<CellVar>>,
        private_input_indices: Vec<usize>,
        main_span: crate::constants::Span,
    ) -> crate::error::Result<()> {
        todo!()
    }

    fn generate_witness(
        &self,
        witness_env: &mut crate::witness::WitnessEnv<Self::Field>,
        public_input_size: usize,
    ) -> crate::error::Result<Self::GeneratedWitness> {
        let mut witness = HashMap::<usize, Fq>::new();
        for constraint in &self.constraints {
            for lc in &constraint.as_array() {
                for (_, var) in &lc.terms {
                    if witness.contains_key(&var.index) {
                        continue;
                    }
                    let val = self.compute_var(witness_env, *var)?;
                    witness.insert(var.index, val);
                }
            }
        }

        Ok(GeneratedWitness { witness })
    }

    fn generate_asm(&self, sources: &crate::compiler::Sources, debug: bool) -> String {
        todo!()
    }
}

// test
#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ark_ff::PrimeField;
    use num_bigint::BigUint;

    use crate::{constants::Span, var::Value, witness::WitnessEnv};

    use super::*;

    fn print_decimal<F: PrimeField>(field_elem: F) {
        // Convert field element to its representative big integer
        let big_int = field_elem.into_repr();

        // Assuming big_int can be converted to a byte array (you need to check how to do this)
        let bytes = big_int.to_bytes_le(); // or to_bytes_be() depending on endian-ness

        // Convert bytes to BigUint
        let big_uint = BigUint::from_bytes_le(&bytes); // Make sure to match endian-ness with the line above

        // Print the BigUint as a decimal string
        println!("{}", big_uint.to_string());
    }

    #[test]
    fn test_arith() {
        let a = Fq::from(9);
        let b = Fq::from(10);

        assert_eq!(a, Fq::from(9)); // 26 =  9 mod 17
                                    // assert_eq!(a - b, Fq::from(16));      // -1 = 16 mod 17
        assert_eq!(a + b, Fq::from(19)); // 19 =  2 mod 17
        assert_eq!(a * b, Fq::from(90)); // 90 =  5 mod 17
                                         // assert_eq!(a.square(), Fq::from(13)); // 81 = 13 mod 17
                                         // assert_eq!(b.double(), Fq::from(3));  // 20 =  3 mod 17
                                         // assert_eq!(a / b, a * b.inverse().unwrap()); // need to unwrap since `b` could be 0 which is not invertible
                                         // assert_eq!(a.pow(b.into_bigint()), Fq::from(13)); // pow takes BigInt as input
    }

    #[test]
    fn test_constraint() {
        // a, b, d are inputs
        // e is constant

        // a + b = c
        let mut r1cs = R1CS::new();

        // first var of r1cs is always 1
        let first_var = r1cs.new_internal_var(Value::Constant(Fq::from(1)), Span::default());

        // public input a, b and e
        let var_a = r1cs.new_internal_var(Value::Constant(Fq::from(1)), Span::default());
        let var_b = r1cs.new_internal_var(Value::Constant(Fq::from(2)), Span::default());

        // a + b = c
        let var_c = r1cs.new_internal_var(
            Value::LinearCombination(
                vec![(Fq::from(1), var_a), (Fq::from(1), var_b)],
                Fq::from(0),
            ),
            Span::default(),
        );

        // create and add constraint
        // ma * mb = mc
        // = (a + b)*1 - c = 0
        let ma = LinearCombination {
            terms: vec![(Fq::from(1), var_a), (Fq::from(1), var_b)],
        };
        let mb = LinearCombination {
            terms: vec![(Fq::from(1), first_var)],
        };
        let mc = LinearCombination {
            terms: vec![(Fq::from(-1), var_c)],
        };

        r1cs.add_constraint(ma, mb, mc);

        // check witness
        let witness_env = &mut WitnessEnv::default();
        let generated_witness = r1cs.generate_witness(witness_env, 2).unwrap();

        // sort key in asc and print each witness in decimal
        let sorted_keys = generated_witness.witness.keys().collect::<Vec<_>>();
        for key in sorted_keys {
            let val = generated_witness.witness.get(key).unwrap();
            print_decimal(*val);
        }

        // c + e = f
        // let f = CellVar::new(5, Span::default());
        // witness_vars.insert(
        //     f.index,
        //     Value::<R1CS>::LinearCombination(vec![(Fq::from(1), c), (Fq::from(1), e)], Fq::from(0)),
        // );

        // a * b = c
        // c * d = f
    }
}
