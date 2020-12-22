#![allow(non_snake_case)]

use crate::poseidon::builder::Poseidon;
use curve25519_dalek::scalar::Scalar;
use bulletproofs::r1cs::{ConstraintSystem, R1CSError, Prover, Verifier};
use bulletproofs::{PedersenGens};
use bulletproofs::r1cs::LinearCombination;
use crate::utils::{AllocatedScalar, constrain_lc_with_scalar};



pub mod sbox;
pub use sbox::*;
pub mod builder;
pub use builder::*;

#[cfg(test)]
pub mod tests;


fn Poseidon_permutation(
    input: &[Scalar],
    params: &Poseidon,
) -> Vec<Scalar>
{
    let width = params.width;
    assert_eq!(input.len(), width);

    let full_rounds_beginning = params.full_rounds_beginning;
    let partial_rounds = params.partial_rounds;
    let full_rounds_end = params.full_rounds_end;

    let mut current_state = input.to_owned();
    let mut current_state_temp = vec![Scalar::zero(); width];

    let mut round_keys_offset = 0;

    // full Sbox rounds
    for _ in 0..full_rounds_beginning {
        // Sbox layer
        for i in 0..width {
            current_state[i] += params.round_keys[round_keys_offset];
            current_state[i] = params.sbox.apply_sbox(&current_state[i]);
            round_keys_offset += 1;
        }

        // linear layer
        for j in 0..width {
            for i in 0..width {
                current_state_temp[i] += current_state[j] * params.mds_matrix[i][j];
            }
        }

        // Output of this round becomes input to next round
        for i in 0..width {
            current_state[i] = current_state_temp[i];
            current_state_temp[i] = Scalar::zero();
        }
    }

    // middle partial Sbox rounds
    for _ in full_rounds_beginning..(full_rounds_beginning+partial_rounds) {
        for i in 0..width {
            current_state[i] += &params.round_keys[round_keys_offset];
            round_keys_offset += 1;
        }

        // partial Sbox layer, apply Sbox to only 1 element of the state.
        // Here the last one is chosen but the choice is arbitrary.
        current_state[width-1] = params.sbox.apply_sbox(&current_state[width-1]);

        // linear layer
        for j in 0..width {
            for i in 0..width {
                current_state_temp[i] += current_state[j] * params.mds_matrix[i][j];
            }
        }

        // Output of this round becomes input to next round
        for i in 0..width {
            current_state[i] = current_state_temp[i];
            current_state_temp[i] = Scalar::zero();
        }
    }

    // last full Sbox rounds
    for _ in full_rounds_beginning+partial_rounds..(full_rounds_beginning+partial_rounds+full_rounds_end) {
        // Sbox layer
        for i in 0..width {
            current_state[i] += params.round_keys[round_keys_offset];
            current_state[i] = params.sbox.apply_sbox(&current_state[i]);
            round_keys_offset += 1;
        }

        // linear layer
        for j in 0..width {
            for i in 0..width {
                current_state_temp[i] += current_state[j] * params.mds_matrix[i][j];
            }
        }

        // Output of this round becomes input to next round
        for i in 0..width {
            current_state[i] = current_state_temp[i];
            current_state_temp[i] = Scalar::zero();
        }
    }

    // Finally the current_state becomes the output
    current_state
}

pub fn Poseidon_permutation_constraints<'a, CS: ConstraintSystem>(
    cs: &mut CS,
    input: Vec<LinearCombination>,
    params: &'a Poseidon,
) -> Result<Vec<LinearCombination>, R1CSError> {
    let width = params.width;
    assert_eq!(input.len(), width);

    fn apply_linear_layer(
        width: usize,
        sbox_outs: Vec<LinearCombination>,
        next_inputs: &mut Vec<LinearCombination>,
        mds_matrix: &Vec<Vec<Scalar>>,
    ) {
        for j in 0..width {
            for i in 0..width {
                next_inputs[i] = next_inputs[i].clone() + sbox_outs[j].clone() * mds_matrix[i][j];
            }
        }
    }

    let mut input_vars: Vec<LinearCombination> = input;

    let mut round_keys_offset = 0;

    let full_rounds_beginning = params.full_rounds_beginning;
    let partial_rounds = params.partial_rounds;
    let full_rounds_end = params.full_rounds_end;

    // ------------ First rounds with full SBox begin --------------------

    for _k in 0..full_rounds_beginning {
        let mut sbox_outputs: Vec<LinearCombination> = vec![LinearCombination::default(); width];

        // Substitution (S-box) layer
        for i in 0..width {
            let round_key = params.round_keys[round_keys_offset];
            sbox_outputs[i] = params.sbox.synthesize_sbox(cs, input_vars[i].clone(), round_key)?.into();

            round_keys_offset += 1;
        }

        let mut next_input_vars: Vec<LinearCombination> = vec![LinearCombination::default(); width];

        apply_linear_layer(width, sbox_outputs, &mut next_input_vars, &params.mds_matrix);

        for i in 0..width {
            // replace input_vars with next_input_vars
            input_vars[i] = next_input_vars.remove(0);
        }
    }

    // ------------ First rounds with full SBox begin --------------------

    // ------------ Middle rounds with partial SBox begin --------------------

    for _k in full_rounds_beginning..(full_rounds_beginning+partial_rounds) {
        let mut sbox_outputs: Vec<LinearCombination> = vec![LinearCombination::default(); width];

        // Substitution (S-box) layer
        for i in 0..width {
            let round_key = params.round_keys[round_keys_offset];

            // apply Sbox to only 1 element of the state.
            // Here the last one is chosen but the choice is arbitrary.
            if i == width-1 {
                sbox_outputs[i] = params.sbox.synthesize_sbox(cs, input_vars[i].clone(), round_key)?.into();
            } else {
                sbox_outputs[i] = input_vars[i].clone() + LinearCombination::from(round_key);
            }

            round_keys_offset += 1;
        }

        // Linear layer

        let mut next_input_vars: Vec<LinearCombination> = vec![LinearCombination::default(); width];

        apply_linear_layer(width, sbox_outputs, &mut next_input_vars, &params.mds_matrix);

        for i in 0..width {
            // replace input_vars with simplified next_input_vars
            input_vars[i] = next_input_vars.remove(0).simplify();
        }
    }

    // ------------ Middle rounds with partial SBox end --------------------

    // ------------ Last rounds with full SBox begin --------------------

    for _k in (full_rounds_beginning+partial_rounds)..(full_rounds_beginning+partial_rounds+full_rounds_end) {
        let mut sbox_outputs: Vec<LinearCombination> = vec![LinearCombination::default(); width];

        // Substitution (S-box) layer
        for i in 0..width {
            let round_key = params.round_keys[round_keys_offset];
            sbox_outputs[i] = params.sbox.synthesize_sbox(cs, input_vars[i].clone(), round_key)?.into();

            round_keys_offset += 1;
        }

        // Linear layer

        let mut next_input_vars: Vec<LinearCombination> = vec![LinearCombination::default(); width];

        apply_linear_layer(width, sbox_outputs, &mut next_input_vars, &params.mds_matrix);

        for i in 0..width {
            // replace input_vars with next_input_vars
            input_vars[i] = next_input_vars.remove(0);
        }
    }

    // ------------ Last rounds with full SBox end --------------------

    Ok(input_vars)
}


pub fn Poseidon_permutation_gadget<'a, CS: ConstraintSystem>(
    cs: &mut CS,
    input: Vec<AllocatedScalar>,
    params: &'a Poseidon,
    output: &[Scalar]
) -> Result<(), R1CSError> {
    let width = params.width;
    assert_eq!(output.len(), width);

    let input_vars: Vec<LinearCombination> = input.iter().map(|e| e.variable.into()).collect();
    let permutation_output = Poseidon_permutation_constraints::<CS>(cs, input_vars, params)?;

    for i in 0..width {
        constrain_lc_with_scalar::<CS>(cs, permutation_output[i].to_owned(), &output[i]);
    }

    Ok(())
}

/// 2:1 (2 inputs, 1 output) hash from the permutation by passing the first input as zero, 2 of the next 4 as non-zero, a padding constant and rest zero. Choose one of the outputs.

// Choice is arbitrary
pub const PADDING_CONST: u64 = 101;
pub const ZERO_CONST: u64 = 0;

pub fn Poseidon_hash_2(xl: Scalar, xr: Scalar, params: &Poseidon) -> Scalar {
    // Only 2 inputs to the permutation are set to the input of this hash function,
    // one is set to the padding constant and rest are 0. Always keep the 1st input as 0

    let input = vec![
        Scalar::from(ZERO_CONST),
        xl,
        xr,
        Scalar::from(PADDING_CONST),
        Scalar::from(ZERO_CONST),
        Scalar::from(ZERO_CONST)
    ];

    // Never take the first output
    Poseidon_permutation(&input, params)[1]
}

pub fn Poseidon_hash_2_constraints<'a, CS: ConstraintSystem>(
    cs: &mut CS,
    xl: LinearCombination,
    xr: LinearCombination,
    statics: Vec<LinearCombination>,
    params: &'a Poseidon,
) -> Result<LinearCombination, R1CSError> {
    let width = params.width;
    // Only 2 inputs to the permutation are set to the input of this hash function.
    assert_eq!(statics.len(), width-2);

    // Always keep the 1st input as 0
    let mut inputs = vec![statics[0].to_owned()];
    inputs.push(xl);
    inputs.push(xr);

    // statics correspond to committed variables with values as PADDING_CONST and 0s and randomness as 0
    for i in 1..statics.len() {
        inputs.push(statics[i].to_owned());
    }
    let permutation_output = Poseidon_permutation_constraints::<CS>(cs, inputs, params)?;
    Ok(permutation_output[1].to_owned())
}

pub fn Poseidon_hash_2_gadget<'a, CS: ConstraintSystem>(
    cs: &mut CS,
    xl: AllocatedScalar,
    xr: AllocatedScalar,
    statics: Vec<AllocatedScalar>,
    params: &'a Poseidon,
    output: &Scalar
) -> Result<(), R1CSError> {

    let statics: Vec<LinearCombination> = statics.iter().map(|s| s.variable.into()).collect();
    let hash = Poseidon_hash_2_constraints::<CS>(cs, xl.variable.into(), xr.variable.into(), statics, params)?;

    constrain_lc_with_scalar::<CS>(cs, hash, output);

    Ok(())
}

pub fn Poseidon_hash_4(inputs: [Scalar; 4], params: &Poseidon) -> Scalar {
    // Only 4 inputs to the permutation are set to the input of this hash function,
    // one is set to the padding constant and one is set to 0. Always keep the 1st input as 0

    let input = vec![
        Scalar::from(ZERO_CONST),
        inputs[0],
        inputs[1],
        inputs[2],
        inputs[3],
        Scalar::from(PADDING_CONST)
    ];

    // Never take the first output
    Poseidon_permutation(&input, params)[1]
}

pub fn Poseidon_hash_4_constraints<'a, CS: ConstraintSystem>(
    cs: &mut CS,
    input: [LinearCombination; 4],
    statics: Vec<LinearCombination>,
    params: &'a Poseidon,
) -> Result<LinearCombination, R1CSError> {

    let width = params.width;
    // Only 4 inputs to the permutation are set to the input of this hash function.
    assert_eq!(statics.len(), width-4);

    // Always keep the 1st input as 0
    let mut inputs = vec![statics[0].to_owned()];
    inputs.push(input[0].clone());
    inputs.push(input[1].clone());
    inputs.push(input[2].clone());
    inputs.push(input[3].clone());

    // statics correspond to committed variables with values as PADDING_CONST and 0s and randomness as 0
    for i in 1..statics.len() {
        inputs.push(statics[i].to_owned());
    }
    let permutation_output = Poseidon_permutation_constraints::<CS>(cs, inputs, params)?;
    Ok(permutation_output[1].to_owned())
}

pub fn Poseidon_hash_4_gadget<'a, CS: ConstraintSystem>(
    cs: &mut CS,
    input: Vec<AllocatedScalar>,
    statics: Vec<AllocatedScalar>,
    params: &'a Poseidon,
    output: &Scalar
) -> Result<(), R1CSError> {

    let statics: Vec<LinearCombination> = statics.iter().map(|s| s.variable.into()).collect();
    let mut input_arr: [LinearCombination; 4] = [
        LinearCombination::default(),
        LinearCombination::default(),
        LinearCombination::default(),
        LinearCombination::default()
    ];
    for i in 0..input.len() {
        input_arr[i] = input[i].variable.into();
    }
    let hash = Poseidon_hash_4_constraints::<CS>(cs, input_arr, statics, params)?;

    constrain_lc_with_scalar::<CS>(cs, hash, output);

    Ok(())
}

/// Allocate padding constant and zeroes for Prover
pub fn allocate_statics_for_prover(prover: &mut Prover, num_statics: usize) -> Vec<AllocatedScalar> {
    let mut statics = vec![];
    let (_, var) = prover.commit(Scalar::from(ZERO_CONST), Scalar::zero());
    statics.push(AllocatedScalar {
        variable: var,
        assignment: Some(Scalar::from(ZERO_CONST)),
    });

    // Commitment to PADDING_CONST with blinding as 0
    let (_, var) = prover.commit(Scalar::from(PADDING_CONST), Scalar::zero());
    statics.push(AllocatedScalar {
        variable: var,
        assignment: Some(Scalar::from(PADDING_CONST)),
    });

    // Commit to 0 with randomness 0 for the rest of the elements of width
    for _ in 2..num_statics {
        let (_, var) = prover.commit(Scalar::from(ZERO_CONST), Scalar::zero());
        statics.push(AllocatedScalar {
            variable: var,
            assignment: Some(Scalar::from(ZERO_CONST)),
        });
    }
    statics
}

/// Allocate padding constant and zeroes for Verifier
pub fn allocate_statics_for_verifier(verifier: &mut Verifier, num_statics: usize, pc_gens: &PedersenGens) -> Vec<AllocatedScalar> {
    let mut statics = vec![];
    // Commitment to PADDING_CONST with blinding as 0
    let pad_comm = pc_gens.commit(Scalar::from(PADDING_CONST), Scalar::zero()).compress();

    // Commitment to 0 with blinding as 0
    let zero_comm = pc_gens.commit(Scalar::from(ZERO_CONST), Scalar::zero()).compress();

    let v = verifier.commit(zero_comm.clone());
    statics.push(AllocatedScalar {
        variable: v,
        assignment: None,
    });

    let v = verifier.commit(pad_comm);
    statics.push(AllocatedScalar {
        variable: v,
        assignment: None,
    });
    for _ in 2..num_statics {
        let v = verifier.commit(zero_comm.clone());
        statics.push(AllocatedScalar {
            variable: v,
            assignment: None,
        });
    }
    statics
}
