use ark_ff::{Field, test_rng, UniformRand, One};
// We'll use these interfaces to construct our circuit.
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

// Bring in some tools for using pairing-friendly curves
// We're going to use the BLS12-377 pairing-friendly elliptic curve.
use ark_bls12_377::{Bls12_377, Fr};

#[macro_use]
extern crate criterion;

use criterion::Criterion;

/// This is our demo circuit for proving knowledge of the
/// preimage of a MiMC hash invocation.
#[derive(Clone, Copy)]
struct TestCircuit<F: Field> {
    pub num_variables: usize,
    pub a: F,
    pub b: F,
}

impl<F: Field> ConstraintSynthesizer<F> for TestCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let _a = cs.new_witness_variable(|| Ok(self.a.clone()))?;
        let b = cs.new_witness_variable(|| Ok(self.b.clone()))?;
        let c = cs.new_input_variable(|| {
            let a = self.a.clone();
            let b = self.b.clone();

            Ok(a * b)
        })?;

        for _ in 0..(self.num_variables - 3) {
            let d = cs.new_witness_variable(|| Ok(self.a.clone()))?;
            cs.enforce_constraint(lc!() + d, lc!() + b, lc!() + c)?;
        }

        cs.enforce_constraint(lc!(), lc!(), lc!())?;

        Ok(())
    }
}


fn bench_prove() {
    use ark_groth16::{
        create_random_proof, generate_random_parameters
    };

    let rng = &mut test_rng();
    let c = TestCircuit::<Fr> {
        a: Fr::rand(rng),
        b: Fr::rand(rng),
        num_variables: 2097152,
    };

    let params = generate_random_parameters::<Bls12_377, _, _>(c, rng).unwrap();

    create_random_proof(c.clone(), &params, rng).unwrap();
}

fn bench_prove_2() {
    use ark_groth16::{
        create_random_proof, generate_random_parameters
    };

    let rng = &mut test_rng();
    let c = TestCircuit::<Fr> {
        a: Fr::one(),
        b: Fr::one(),
        num_variables: 2097152,
    };

    let params = generate_random_parameters::<Bls12_377, _, _>(c, rng).unwrap();

    create_random_proof(c.clone(), &params, rng).unwrap();
}


fn main() {
    bench_prove();
    bench_prove_2();
}

/*criterion_group! {
    name = zexe_rand;
    config = Criterion::default().sample_size(10);
    targets = bench_prove
}

criterion_group! {
    name = zexe_zero_one;
    config = Criterion::default().sample_size(10);
    targets = bench_prove_2
}

criterion_main!(zexe_rand, zexe_zero_one);*/