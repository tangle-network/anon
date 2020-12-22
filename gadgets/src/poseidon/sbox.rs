use crate::zero_nonzero::is_nonzero_gadget;
use crate::utils::{AllocatedScalar, constrain_lc_with_scalar};
use bulletproofs::r1cs::{ConstraintSystem, R1CSError, Variable, LinearCombination};
use curve25519_dalek::scalar::Scalar;

/// An S-Box that can be used with Poseidon.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PoseidonSbox {
    Exponentiation3,
    Exponentiation5,
    Inverse,
}

impl PoseidonSbox {
    pub fn apply_sbox(&self, elem: &Scalar) -> Scalar {
        match self {
            PoseidonSbox::Exponentiation3 => (elem * elem) * elem,
            PoseidonSbox::Exponentiation5 => {
            	let sqr = elem * elem;
            	(sqr * sqr) * elem
            },
            PoseidonSbox::Inverse => elem.invert()
        }
    }

    pub fn synthesize_sbox<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
        input_var: LinearCombination,
        round_key: Scalar
    ) -> Result<Variable, R1CSError> {
        match self {
            PoseidonSbox::Exponentiation3 => Self::synthesize_exp3_sbox(cs, input_var, round_key),
            PoseidonSbox::Exponentiation5 => Self::synthesize_exp5_sbox(cs, input_var, round_key),
            PoseidonSbox::Inverse => Self::synthesize_inverse_sbox(cs, input_var, round_key),
        }
    }

    // Allocate variables in circuit and enforce constraints when Sbox as cube
    fn synthesize_exp3_sbox<CS: ConstraintSystem>(
        cs: &mut CS,
        input_var: LinearCombination,
        round_key: Scalar
    ) -> Result<Variable, R1CSError> {
        let inp_plus_const: LinearCombination = input_var + round_key;
        let (i, _, sqr) = cs.multiply(inp_plus_const.clone(), inp_plus_const);
        let (_, _, cube) = cs.multiply(sqr.into(), i.into());
        Ok(cube)
    }

    // Allocate variables in circuit and enforce constraints when Sbox as cube
    fn synthesize_exp5_sbox<CS: ConstraintSystem>(
        cs: &mut CS,
        input_var: LinearCombination,
        round_key: Scalar
    ) -> Result<Variable, R1CSError> {
        let inp_plus_const: LinearCombination = input_var + round_key;
        let (i, _, sqr) = cs.multiply(inp_plus_const.clone(), inp_plus_const);
        let (_, _, fourth) = cs.multiply(sqr.into(), sqr.into());
        let (_, _, fifth) = cs.multiply(fourth.into(), i.into());
        Ok(fifth)
    }

    // Allocate variables in circuit and enforce constraints when Sbox as inverse
    fn synthesize_inverse_sbox<CS: ConstraintSystem>(
        cs: &mut CS,
        input_var: LinearCombination,
        round_key: Scalar
    ) -> Result<Variable, R1CSError> {
        let inp_plus_const: LinearCombination = (input_var + round_key).simplify();

        let val_l = cs.evaluate_lc(&inp_plus_const);
        let val_r = val_l.map(|l| l.invert());

        let (var_l, _) = cs.allocate_single(val_l)?;
        let (var_r, var_o) = cs.allocate_single(val_r)?;

        // Ensure `inp_plus_const` is not zero. As a side effect, `is_nonzero_gadget` also ensures that arguments passes are inverse of each other
        let l_scalar = AllocatedScalar { variable: var_l, assignment: val_l };
        let r_scalar = AllocatedScalar { variable: var_r, assignment: val_r };
        is_nonzero_gadget(cs, l_scalar, r_scalar)?;

        // Constrain product of `inp_plus_const` and its inverse to be 1.
        constrain_lc_with_scalar::<CS>(cs, var_o.unwrap().into(), &Scalar::one());

        Ok(var_r)
    }
}
