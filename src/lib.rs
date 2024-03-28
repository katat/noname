//! This is a high-level language to write circuits that you can prove in kimchi.
//! Refer to the [book](https://mimoo.github.io/noname/) for more information.
//!

pub mod asm;
pub mod circuit_writer;
pub mod cli;
pub mod compiler;
pub mod constants;
pub mod constraints;
pub mod error;
pub mod imports;
pub mod inputs;
pub mod lexer;
pub mod name_resolution;
pub mod parser;
pub mod prover;
pub mod serialization;
pub mod stdlib;
pub mod syntax;
pub mod type_checker;
pub mod var;
pub mod witness;

#[cfg(test)]
pub mod tests;

#[cfg(test)]
pub mod negative_tests;

//
// Helpers
//

pub mod helpers {
    use kimchi::mina_poseidon::{
        constants::PlonkSpongeConstantsKimchi,
        pasta::fp_kimchi,
        poseidon::{ArithmeticSponge, Sponge},
    };

    // use crate::constants::Field;
    use kimchi::mina_curves::pasta::Fp;

    /// A trait to display [Field] in pretty ways.
    pub trait PrettyField: ark_ff::PrimeField {
        /// Print a field in a negative form if it's past the half point.
        fn pretty(&self) -> String {
            let bigint: num_bigint::BigUint = (*self).into();
            let inv: num_bigint::BigUint = self.neg().into(); // gettho way of splitting the field into positive and negative elements
            if inv < bigint {
                format!("-{}", inv)
            } else {
                bigint.to_string()
            }
        }
    }

    impl PrettyField for Fp {}

    pub fn poseidon(input: [Fp; 2]) -> Fp {
        let mut sponge: ArithmeticSponge<Fp, PlonkSpongeConstantsKimchi> =
            ArithmeticSponge::new(fp_kimchi::static_params());
        sponge.absorb(&input);
        sponge.squeeze()
    }
}
