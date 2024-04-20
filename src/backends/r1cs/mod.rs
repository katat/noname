use std::collections::HashMap;

// use num_bigint::{BigUint, ToBigUint};

use ark_bls12_381::Fr;
use ark_ff::BigInteger;
use ark_ff::{fields::Field, BigInteger384};
use num_bigint_dig::{BigInt, BigUint};

use crate::{
    helpers::PrettyField,
    var::{CellVar, ConstOrCell, Value},
};

use super::Backend;

#[derive(Clone)]
pub struct R1CS {
    // pub prime: 
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
    pub terms: Vec<(Fr, CellVar)>,
}

// todo: replace with this form
// pub struct LinearCombination {
//     pub terms: HashMap<CellVar, Fq>,
//     pub constant: Fq,
// }

impl Constraint {
    pub fn as_array(&self) -> [&LinearCombination; 3] {
        [&self.a, &self.b, &self.c]
    }
}

use ark_ff::fields::PrimeField;

impl LinearCombination {
    pub fn to_bigint_values(&self) -> HashMap<usize, BigInt> {
        let mut values = HashMap::new();
        for (val, var) in &self.terms {
            let converted_bigint =
                BigInt::from_bytes_le(num_bigint_dig::Sign::Plus, &val.into_repr().to_bytes_le());
            values.insert(var.index, converted_bigint);
        }
        values
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
    pub witness: HashMap<usize, Fr>,
}

impl Backend for R1CS {
    type Field = Fr;

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
        let mut witness = HashMap::<usize, Fr>::new();
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
    use std::error::Error;
    use std::fs::OpenOptions;
    use std::io::{BufWriter, Seek, SeekFrom, Write};
    use std::{collections::HashMap, fs::File};

    use ark_ff::PrimeField;
    use constraint_writers::r1cs_writer::{
        ConstraintSection, HeaderData, R1CSWriter, SignalSection,
    };
    use kimchi::o1_utils::FieldHelpers;

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

    pub fn port_r1cs(output: &str, r1cs_data: R1CS) -> Result<(), ()> {
        let prime = BigInt::from_bytes_le(
            num_bigint_dig::Sign::Plus,
            &Fr::modulus_biguint().to_bytes_le(),
        );
        let field_size = if prime.bits() % 64 == 0 {
            prime.bits() / 8
        } else {
            (prime.bits() / 64 + 1) * 8
        };

        println!(
            "Field size: {}, size in bits: {}",
            field_size,
            Fr::size_in_bits()
        );

        let r1cs = R1CSWriter::new(output.to_string(), field_size as usize, false).unwrap();
        let mut constraint_section = R1CSWriter::start_constraints_section(r1cs).unwrap();
        let mut written = 0;

        for constraint in r1cs_data.constraints {
            // convert constraint terms to hashmap<usize, bigint>

            ConstraintSection::write_constraint_usize(
                &mut constraint_section,
                &constraint.a.to_bigint_values(),
                &constraint.b.to_bigint_values(),
                &constraint.c.to_bigint_values(),
            );
            written += 1;
        }

        let r1cs = constraint_section.end_section().unwrap();
        let mut header_section = R1CSWriter::start_header_section(r1cs).unwrap();
        let header_data = HeaderData {
            field: prime,
            public_outputs: 0,
            public_inputs: 2,
            private_inputs: 0,
            total_wires: r1cs_data.witness_vars.len(),
            number_of_labels: 0,
            number_of_constraints: written,
        };
        header_section.write_section(header_data);
        let r1cs = header_section.end_section().unwrap();
        let mut signal_section = R1CSWriter::start_signal_section(r1cs).unwrap();

        for id in r1cs_data.witness_vars.keys() {
            SignalSection::write_signal_usize(&mut signal_section, *id);
        }
        let r1cs = signal_section.end_section().unwrap();
        R1CSWriter::finish_writing(r1cs);

        Ok(())
    }

    struct WitnessWriter {
        inner: BufWriter<File>,
        writing_section: Option<WritingSection>,
        section_size_position: u64,
    }

    struct WritingSection;

    impl WitnessWriter {
        // Initialize a FileWriter
        pub fn new(
            path: &str,
            file_type: &str,
            version: u32,
            n_sections: u32,
        ) -> Result<WitnessWriter, ()> {
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)
                .unwrap();
            let mut writer = BufWriter::new(file);

            // Write the file type (magic string) as bytes
            let file_type_bytes = file_type.as_bytes();
            if file_type_bytes.len() != 4 {
                panic!("File type must be 4 characters long");
            }
            writer.write_all(file_type_bytes);

            // Write the version as a 32-bit unsigned integer in little endian
            writer.write_all(&version.to_le_bytes());

            // Write the number of sections as a 32-bit unsigned integer in little endian
            writer.write_all(&n_sections.to_le_bytes());

            let current_position = writer.stream_position().unwrap();

            Ok(WitnessWriter {
                inner: writer,
                writing_section: None,
                section_size_position: current_position,
            })
        }

        // Start a new section for writing
        pub fn start_write_section(&mut self, id_section: u32) -> Result<(), ()> {
            // if self.writing_section.is_some() {
            //     return Err(anyhow::anyhow!("Already writing a section"));
            // }

            self.inner.write_all(&id_section.to_le_bytes()); // Write the section ID as ULE32
            self.section_size_position = self.inner.stream_position().unwrap(); // Get the current position
            self.inner.write_all(&0u64.to_le_bytes()); // Temporarily write 0 as ULE64 for the section size
            self.writing_section = Some(WritingSection);

            Ok(())
        }

        // End the current section
        pub fn end_write_section(&mut self) -> Result<(), ()> {
            let current_pos = self.inner.stream_position().unwrap();
            let section_size = current_pos - self.section_size_position - 8; // Calculate the size of the section

            self.inner.seek(SeekFrom::Start(self.section_size_position)); // Move back to where the size needs to be written
            self.inner.write_all(&section_size.to_le_bytes()); // Write the actual section size
            self.inner.seek(SeekFrom::Start(current_pos)); // Return to the end of the section
            self.inner.flush(); // Flush the buffer to ensure all data is written to the file

            self.writing_section = None;

            Ok(())
        }
        pub fn write(&mut self, witness: &GeneratedWitness, prime: BigInt) -> Result<(), ()> {
            self.start_write_section(1);
            let n8 = ((prime.bits() - 1) / 64 + 1) * 8;
            self.inner.write_all(&(n8 as u32).to_le_bytes());
            self.write_big_int(prime, n8);
            self.inner.write_all(&(witness.witness.len() as u32).to_le_bytes());
            
            self.end_write_section();

            self.start_write_section(2);

            let sorted_witness_id = witness.witness.keys().collect::<Vec<_>>();

            let sorted_witness = sorted_witness_id
                .iter()
                .map(|id| witness.witness.get(id).unwrap())
                .collect::<Vec<_>>();
            // map to big int
            // BigInt::from_bytes_le(num_bigint_dig::Sign::Plus, &val.into_repr().to_bytes_le())
            let witness = sorted_witness
                .iter()
                .map(|val| {
                    BigInt::from_bytes_le(
                        num_bigint_dig::Sign::Plus,
                        &val.into_repr().to_bytes_le(),
                    )
                })
                .collect::<Vec<_>>();

            for value in witness {
                self.write_big_int(value, n8 as usize);
            }
            self.end_write_section();

            Ok(())
        }
        // Function to write a BigInt to the file
        fn write_big_int(&mut self, value: BigInt, size: usize) {
            let bytes = value.to_bytes_le().1;
            // if bytes.len() > size {
            //     return Err(anyhow::anyhow!("Big integer too large for specified size"));
            // }

            let mut buffer = vec![0u8; size];
            buffer[..bytes.len()].copy_from_slice(&bytes);
            self.inner.write_all(&buffer);
        }
    }

    #[test]
    fn test_arith() {
        let a = Fr::from(9);
        let b = Fr::from(10);

        assert_eq!(a, Fr::from(9)); // 26 =  9 mod 17
                                    // assert_eq!(a - b, Fr::from(16));      // -1 = 16 mod 17
        assert_eq!(a + b, Fr::from(19)); // 19 =  2 mod 17
        assert_eq!(a * b, Fr::from(90)); // 90 =  5 mod 17
                                         // assert_eq!(a.square(), Fr::from(13)); // 81 = 13 mod 17
                                         // assert_eq!(b.double(), Fr::from(3));  // 20 =  3 mod 17
                                         // assert_eq!(a / b, a * b.inverse().unwrap()); // need to unwrap since `b` could be 0 which is not invertible
                                         // assert_eq!(a.pow(b.into_bigint()), Fr::from(13)); // pow takes BigInt as input
    }

    #[test]
    fn test_constraint() {
        // a, b, d are inputs
        // e is constant

        // a + b = c
        let mut r1cs = R1CS::new();

        // first var of r1cs is always 1
        let first_var = r1cs.new_internal_var(Value::Constant(Fr::from(1)), Span::default());

        // public input a, b and e
        let var_a = r1cs.new_internal_var(Value::Constant(Fr::from(1)), Span::default());
        let var_b = r1cs.new_internal_var(Value::Constant(Fr::from(2)), Span::default());

        // a + b = c
        let var_c = r1cs.new_internal_var(
            Value::LinearCombination(
                vec![(Fr::from(1), var_a), (Fr::from(1), var_b)],
                Fr::from(0),
            ),
            Span::default(),
        );

        // create and add constraint
        // ma * mb = mc
        // = (a + b)*1 - c = 0
        let ma = LinearCombination {
            terms: vec![(Fr::from(1), var_a), (Fr::from(1), var_b)],
        };
        let mb = LinearCombination {
            terms: vec![(Fr::from(1), first_var)],
        };
        let mc = LinearCombination {
            terms: vec![(Fr::from(-1), var_c)],
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

        let output_file = "./test.r1cs";
        port_r1cs(&output_file, r1cs);
        println!("R1CS file written to {}", output_file);

        let mut witness_writer = WitnessWriter::new("./test.wtns", "wtns", 2, 2).unwrap();

        let prime = BigInt::from_bytes_le(
            num_bigint_dig::Sign::Plus,
            &Fr::modulus_biguint().to_bytes_le(),
        );
        witness_writer.write(&generated_witness, prime);
        println!("Witness file written to ./test.wtns");

        // c + e = f
        // let f = CellVar::new(5, Span::default());
        // witness_vars.insert(
        //     f.index,
        //     Value::<R1CS>::LinearCombination(vec![(Fr::from(1), c), (Fr::from(1), e)], Fr::from(0)),
        // );

        // a * b = c
        // c * d = f
    }
}
