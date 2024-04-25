pub mod builtin;

use std::backtrace::Backtrace;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::{collections::HashMap, io::{BufWriter, Write}};

// use num_bigint::{BigUint, ToBigUint};
use std::ops::Neg;
use ark_bls12_381::Fr;
use ark_ff::{BigInteger, Zero, Field};
use constraint_writers::r1cs_writer::{ConstraintSection, HeaderData, R1CSWriter, SignalSection};
use itertools::Itertools;
use kimchi::o1_utils::FieldHelpers as _;
use num_bigint_dig::BigInt;

use crate::{circuit_writer::DebugInfo, var::{CellVar, Value}};

use self::builtin::poseidon;

use super::Backend;

#[derive(Clone)]
pub struct R1CS {
    // pub prime: 
    pub constraints: Vec<Constraint>,
    pub next_variable: usize,
    pub witness_vars: HashMap<usize, Value<R1CS>>,
    pub debug_info: Vec<DebugInfo>,
    pub public_input_size: usize,
    pub public_output_size: usize,
}

#[derive(Clone, Debug)]
pub struct Constraint {
    pub a: LinearCombination,
    pub b: LinearCombination,
    pub c: LinearCombination,
}

#[derive(Clone, Debug)]
pub struct LinearCombination {
    pub terms: Option<HashMap<CellVar, Fr>>,
    // todo: how do we use this constant?
    pub constant: Option<Fr>,
}

impl Constraint {
    pub fn as_array(&self) -> [&LinearCombination; 3] {
        [&self.a, &self.b, &self.c]
    }
}

use ark_ff::fields::PrimeField;

impl LinearCombination {
    /// Convert to the circom format 
    pub fn to_bigint_values(&self) -> HashMap<usize, BigInt> {
        let mut values = HashMap::new();
        if let Some(terms) = &self.terms {
            for (var, factor) in terms {
                let factor_bigint =
                    BigInt::from_bytes_le(num_bigint_dig::Sign::Plus, &factor.into_repr().to_bytes_le());
                values.insert(var.index, factor_bigint);
            }
        }

        // todo: should the constant be the factor of the first var which is always 1? is this correct way to constraint a constant?
        if let Some(constant) = &self.constant {
            let constant_bigint = BigInt::from_bytes_le(
                num_bigint_dig::Sign::Plus,
                &constant.into_repr().to_bytes_le(),
            );

            // var at 0 index always has the value 1
            values.insert(0, constant_bigint);
        }

        values
    }

    /// Evaluate the linear combination with the given witness
    pub fn evaluate(&self, witness: &HashMap<usize, Fr>) -> Fr {
        let mut sum = Fr::zero();

        if let Some(terms) = &self.terms {
            for (var, factor) in terms {
                sum += *witness.get(&var.index).unwrap() * factor;
            }
        }

        if let Some(constant) = &self.constant {
            sum += constant;
        }

        sum
    }
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
    ) -> Result<WitnessWriter, ()> {
        let file_type = "wtns";
        let version = 2u32;
        let n_sections = 2u32;

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

        let sorted_witness = witness.witness.keys().sorted()
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

        println!("Witnesses: ");

        for value in witness {
            println!("{}", value.to_string());
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

impl R1CS {
    pub fn new() -> Self {
        Self {
            constraints: Vec::new(),
            next_variable: 0,
            witness_vars: HashMap::new(),
            debug_info: Vec::new(),
            public_input_size: 0,
            public_output_size: 0,
        }
    }

    pub fn add_constraint(
        &mut self,
        note: &str,
        c: Constraint,
        span: crate::constants::Span,
    ) {
        let debug_info = DebugInfo {
            note: note.to_string(),
            span,
        };
        self.debug_info.push(debug_info);

        self.constraints.push(c);
    }

    pub fn gen_r1cs_file(&self, file: &str) -> Result<(), ()> {
        let prime = BigInt::from_bytes_le(
            num_bigint_dig::Sign::Plus,
            // todo: this function is from kimchi library, need to find a better way to get the modulus
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

        let r1cs = R1CSWriter::new(file.to_string(), field_size as usize, false).unwrap();
        let mut constraint_section = R1CSWriter::start_constraints_section(r1cs).unwrap();
        let mut written = 0;

        for constraint in &self.constraints {
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
            public_outputs: self.public_output_size,
            public_inputs: self.public_input_size,
            // todo: need to store private inputs in this backend
            private_inputs: 0,
            total_wires: self.witness_vars.len(),
            // this is for circom lang debugging, so we don't need it
            number_of_labels: 0,
            number_of_constraints: written,
        };
        header_section.write_section(header_data);
        let r1cs = header_section.end_section().unwrap();
        let mut signal_section = R1CSWriter::start_signal_section(r1cs).unwrap();

        for id in self.witness_vars.keys() {
            SignalSection::write_signal_usize(&mut signal_section, *id);
        }
        let r1cs = signal_section.end_section().unwrap();
        R1CSWriter::finish_writing(r1cs);

        Ok(())
    }

    pub fn gen_wtns_file(&self, file: &str, witness: GeneratedWitness) -> Result<(), ()> {
        let mut witness_writer = WitnessWriter::new(file).unwrap();

        let prime = BigInt::from_bytes_le(
            num_bigint_dig::Sign::Plus,
            &Fr::modulus_biguint().to_bytes_le(),
        );

        witness_writer.write(&witness, prime).unwrap();

        Ok(())
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
        // return empty function
        poseidon
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
        let x = self.new_internal_var(Value::Constant(value), span);
        self.constraint_eq_const(&x, value, span);

        x
    }

    fn finalize_circuit(
        &mut self,
        public_output: Option<crate::var::Var<Self::Field>>,
        returned_cells: Option<Vec<CellVar>>,
        private_input_indices: Vec<usize>,
        main_span: crate::constants::Span,
    ) -> crate::error::Result<()> {
        // todo: what to check for r1cs?

        Ok(())
    }

    fn generate_witness(
        &self,
        witness_env: &mut crate::witness::WitnessEnv<Self::Field>,
    ) -> crate::error::Result<Self::GeneratedWitness> {
        let mut witness = HashMap::<usize, Fr>::new();
        for constraint in &self.constraints {
            for lc in &constraint.as_array() {
                if let Some(terms) = &lc.terms {
                    for var in terms.keys() {
                        if witness.contains_key(&var.index) {
                            continue;
                        }
                        let val = self.compute_var(witness_env, *var)?;
                        witness.insert(var.index, val);
                    }
                }
            }
            // assert a * b = c
            assert_eq!(
                constraint.a.evaluate(&witness) * constraint.b.evaluate(&witness), 
                constraint.c.evaluate(&witness)
            );
        }

        Ok(GeneratedWitness { witness })
    }

    fn generate_asm(&self, sources: &crate::compiler::Sources, debug: bool) -> String {
        todo!()
    }
    
    /// to constraint:
    /// x + (-x) = 0
    /// given:
    /// a * b = c
    /// then:
    /// a = x + (-x)
    /// b = 1
    /// c = 0
    fn constraint_neg(&mut self, x: &CellVar, span: crate::constants::Span) -> CellVar {
        let one = Fr::from(1);
        let zero = Fr::from(0);

        let x_neg = self.new_internal_var(Value::LinearCombination(vec![(one.neg(), *x)], zero), span);

        let a = LinearCombination {
            terms: Some(HashMap::from_iter(vec![(*x, one), (x_neg, one)])),
            constant: None,
        };
        let b = LinearCombination {
            terms: None,
            constant: Some(one),
        };
        let c = LinearCombination {
            terms: None,
            constant: Some(zero),
        };

        self.add_constraint(
            "neg constraint: x + (-x) = 0",
            Constraint{a, b, c},
            span
        );

        x_neg
    }
    
    /// to constraint:
    /// lhs + rhs = res
    /// given:
    /// a * b = c
    /// then:
    /// a = lhs + rhs
    /// b = 1
    /// c = res
    fn constraint_add(&mut self, lhs: &CellVar, rhs: &CellVar, span: crate::constants::Span) -> CellVar {
        let one = Fr::from(1);
        let zero = Fr::from(0);

        let res = self.new_internal_var(Value::LinearCombination(vec![(one, *lhs), (one, *rhs)], zero), span);

        // IMPORTANT: since terms use CellVar as key,
        // HashMap automatically overrides it to single one term if the two vars are the same CellVar
        let a = if lhs == rhs {
            LinearCombination {
                terms: Some(HashMap::from_iter(vec![(*lhs, Fr::from(2))])),
                constant: None,
            }
        } else {
            LinearCombination {
                terms: Some(HashMap::from_iter(vec![(*lhs, one), (*rhs, one)])),
                constant: None,
            }
        };

        let b = LinearCombination {
            terms: None,
            constant: Some(one),
        };

        let c = LinearCombination {
            terms: Some(HashMap::from_iter(vec![(res, one)])),
            constant: None,
        };

        self.add_constraint(
            "add constraint: lhs + rhs = res",
            Constraint{a, b, c},
            span
        );

        res
    }
    
    /// to constraint:
    /// x + cst = res
    /// given:
    /// a * b = c
    /// then:
    /// a = x + cst
    /// b = 1
    /// c = res
    fn constraint_add_const(&mut self, x: &CellVar, cst: &Self::Field, span: crate::constants::Span) -> CellVar {
        let one = Fr::from(1);

        let res = self.new_internal_var(Value::LinearCombination(vec![(one, *x)], *cst), span);

        let a = LinearCombination {
            terms: Some(HashMap::from_iter(vec![(*x, one)])),
            constant: Some(*cst),
        };

        let b = LinearCombination {
            terms: None,
            constant: Some(one),
        };

        let c = LinearCombination {
            terms: Some(HashMap::from_iter(vec![(res, one)])),
            constant: None,
        };

        self.add_constraint(
            "add constraint: x + cst = res",
            Constraint{a, b, c},
            span
        );

        res
    }
    
    /// to constraint:
    /// lhs * rhs = res
    /// given:
    /// a * b = c
    /// then:
    /// a = lhs
    /// b = rhs
    /// c = res
    fn constraint_mul(&mut self, lhs: &CellVar, rhs: &CellVar, span: crate::constants::Span) -> CellVar {
        let one = Fr::from(1);

        let res = self.new_internal_var(Value::Mul(*lhs, *rhs), span);

        let a = LinearCombination {
            terms: Some(HashMap::from_iter(vec![(*lhs, one)])),
            constant: None,
        };

        let b = LinearCombination {
            terms: Some(HashMap::from_iter(vec![(*rhs, one)])),
            constant: None,
        };

        let c = LinearCombination {
            terms: Some(HashMap::from_iter(vec![(res, one)])),
            constant: None,
        };

        self.add_constraint(
            "mul constraint: lhs * rhs = res",
            Constraint{a, b, c},
            span
        );

        res
    }
    
    /// to constraint:
    /// x * cst = res
    /// given:
    /// a * b = c
    /// then:
    /// a = x
    /// b = cst
    /// c = res
    fn constraint_mul_const(&mut self, x: &CellVar, cst: &Self::Field, span: crate::constants::Span) -> CellVar {
        let one = Fr::from(1);

        let res = self.new_internal_var(Value::Scale(*cst, *x), span);

        let a = LinearCombination {
            terms: Some(HashMap::from_iter(vec![(*x, one)])),
            constant: None,
        };

        let b = LinearCombination {
            terms: None,
            constant: Some(*cst),
        };

        let c = LinearCombination {
            terms: Some(HashMap::from_iter(vec![(res, one)])),
            constant: None,
        };

        self.add_constraint(
            "mul constraint: x * cst = res",
            Constraint{a, b, c},
            span
        );

        res
    }
    
    /// to constraint:
    /// x = cst
    /// given:
    /// a * b = c
    /// then:
    /// a = x
    /// b = 1
    /// c = cst
    fn constraint_eq_const(&mut self, x: &CellVar, cst: Self::Field, span: crate::constants::Span) {
        let one = Fr::from(1);

        let a = LinearCombination {
            terms: Some(HashMap::from_iter(vec![(*x, one)])),
            constant: None,
        };

        let b = LinearCombination {
            terms: None,
            constant: Some(one),
        };

        let c = LinearCombination {
            terms: None,
            constant: Some(cst),
        };

        self.add_constraint(
            "eq constraint: x = cst",
            Constraint{a, b, c},
            span
        );
    }

    /// to constraint:
    /// lhs = rhs
    /// given:
    /// a * b = c
    /// then:
    /// a = lhs
    /// b = 1
    /// c = rhs
    fn constraint_eq_var(&mut self, lhs: &CellVar, rhs: &CellVar, span: crate::constants::Span) {
        let one = Fr::from(1);

        let a = LinearCombination {
            terms: Some(HashMap::from_iter(vec![(*lhs, one)])),
            constant: None,
        };

        let b = LinearCombination {
            terms: None,
            constant: Some(one),
        };

        let c = LinearCombination {
            terms: Some(HashMap::from_iter(vec![(*rhs, one)])),
            constant: None,
        };

        self.add_constraint(
            "eq constraint: lhs = rhs",
            Constraint{a, b, c},
            span
        );
    }
    
    /// todo: how does circom constraint this?
    fn constraint_public_input(&mut self, val: Value<Self>, span: crate::constants::Span) -> CellVar {
        self.public_input_size += 1;
        self.new_internal_var(val, span)
    }
    
    /// todo: how does circom constraint this?
    fn constraint_public_output(&mut self, val: Value<Self>, span: crate::constants::Span) -> CellVar {
        self.public_output_size += 1;
        self.new_internal_var(val, span)
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
    use itertools::Itertools;
    use kimchi::o1_utils::FieldHelpers;
    use num_bigint_dig::BigUint;

    use crate::{constants::Span, var::Value, witness::WitnessEnv};

    use super::*;

    fn format_decimal<F: PrimeField>(field_elem: F) -> String {
        // Convert field element to its representative big integer
        let big_int = field_elem.into_repr();

        // Assuming big_int can be converted to a byte array (you need to check how to do this)
        let bytes = big_int.to_bytes_le(); // or to_bytes_be() depending on endian-ness

        // Convert bytes to BigUint
        let big_uint = BigUint::from_bytes_le(&bytes); // Make sure to match endian-ness with the line above

        // Print the BigUint as a decimal string
        big_uint.to_string()
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
            terms: Some(HashMap::from_iter(vec![(var_a, Fr::from(1)), (var_b, Fr::from(1))])),
            constant: None,
        };
        let mb = LinearCombination {
            terms: None,
            constant: Some(Fr::from(1)),
        };
        let mc = LinearCombination {
            terms: Some(HashMap::from_iter(vec![(var_c, Fr::from(1))])),
            constant: None,
        };

        r1cs.add_constraint("", Constraint{a: ma, b: mb, c: mc}, Span::default());

        // check witness
        let witness_env = &mut WitnessEnv::default();
        let generated_witness = r1cs.generate_witness(witness_env).unwrap();

        // sort key in asc and print each witness in decimal
        let sorted_keys = generated_witness.witness.keys().sorted();
        println!("Witnesses: id / value");
        for key in sorted_keys {
            let val = generated_witness.witness.get(key).unwrap();
            println!("{}: {}", key, format_decimal(*val));
        }

        let output_file = "./test.r1cs";
        r1cs.gen_r1cs_file(&output_file);
        println!("R1CS file written to {}", output_file);

        let mut witness_writer = WitnessWriter::new("./test.wtns").unwrap();

        let prime = BigInt::from_bytes_le(
            num_bigint_dig::Sign::Plus,
            &Fr::modulus_biguint().to_bytes_le(),
        );
        witness_writer.write(&generated_witness, prime);
        println!("Witness file written to ./test.wtns");

        // snarkjs powersoftau new bls12-381 12 pot12_0000.ptau -v\n
        // snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="First contribution" -v\n
        // snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau -v\n
        // snarkjs groth16 setup test.r1cs pot12_final.ptau test_0000.zkey\n
        // snarkjs zkey contribute test_0000.zkey test_0001.zkey --name="1st Contributor Name" -v\n
        // snarkjs zkey export verificationkey test_0001.zkey verification_key.json\n
        // snarkjs groth16 prove test_0001.zkey test.wtns proof.json public.json\n
        // snarkjs groth16 verify verification_key.json public.json proof.json\n
        // should display "snarkJS: OK!"

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
