#![allow(non_snake_case)]
use halo2_base::{
    gates::{
        builder::{GateThreadBuilder, RangeCircuitBuilder},
        RangeChip,
    },
    halo2_proofs::{
        dev::MockProver,
        halo2curves::ed25519::{Ed25519Affine, Fq, Fr},
    },
    utils::{bigint_to_fe, fe_to_bigint, BigPrimeField},
    Context,
};
use halo2_ecc::{
    bigint::OverflowInteger,
    fields::{fp::FpChip, FieldChip, PrimeField},
};
use num_bigint::BigInt;
use num_traits::Zero;
use rand_core::OsRng;

use super::ecc::EccChip;

#[cfg(test)]
pub fn to_bigint<F>(overflow_integer: OverflowInteger<F>, limb_bits: usize) -> BigInt
where
    F: BigPrimeField,
{
    overflow_integer
        .limbs
        .iter()
        .rev()
        .fold(BigInt::zero(), |acc, acell| {
            (acc << limb_bits) + fe_to_bigint(acell.value())
        })
}

#[cfg(test)]
fn basic_tests<F: PrimeField>(
    ctx: &mut Context<F>,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    P: Ed25519Affine,
    Q: Ed25519Affine,
) {
    std::env::set_var("LOOKUP_BITS", lookup_bits.to_string());
    let range = RangeChip::<F>::default(lookup_bits);
    let fp_chip = FpChip::<F, Fq>::new(&range, limb_bits, num_limbs);
    let chip = EccChip::new(&fp_chip);

    let P_assigned = chip.load_private(ctx, (P.x, P.y));
    let Q_assigned = chip.load_private(ctx, (Q.x, Q.y));

    // test add_unequal
    chip.field_chip.enforce_less_than(ctx, P_assigned.x());
    chip.field_chip.enforce_less_than(ctx, Q_assigned.x());
    let sum = chip.add::<Ed25519Affine>(ctx, &P_assigned, &Q_assigned);
    assert_eq!(to_bigint(sum.x.truncation, limb_bits), sum.x.value);
    assert_eq!(to_bigint(sum.y.truncation, limb_bits), sum.y.value);
    {
        let actual_sum = Ed25519Affine::from(P + Q);
        assert_eq!(bigint_to_fe::<Fq>(&sum.x.value), actual_sum.x);
        assert_eq!(bigint_to_fe::<Fq>(&sum.y.value), actual_sum.y);
    }
    println!("add unequal witness OK");

    // test double
    let doub = chip.double::<Ed25519Affine>(ctx, &P_assigned);
    assert_eq!(to_bigint(doub.x.truncation, limb_bits), doub.x.value);
    assert_eq!(to_bigint(doub.y.truncation, limb_bits), doub.y.value);
    {
        let actual_doub = Ed25519Affine::from(P * Fr::from(2u64));
        assert_eq!(bigint_to_fe::<Fq>(&doub.x.value), actual_doub.x);
        assert_eq!(bigint_to_fe::<Fq>(&doub.y.value), actual_doub.y);
    }
    println!("double witness OK");
}

#[test]
fn test_ecc() {
    let k = 23;
    let P = Ed25519Affine::random(OsRng);
    let Q = Ed25519Affine::random(OsRng);

    let mut builder = GateThreadBuilder::<Fr>::mock();
    basic_tests(builder.main(0), k - 1, 88, 3, P, Q);

    builder.config(k, Some(20));
    let circuit = RangeCircuitBuilder::mock(builder);

    MockProver::run(k as u32, &circuit, vec![])
        .unwrap()
        .assert_satisfied();
}
