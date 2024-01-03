#![allow(non_snake_case)]
use halo2_base::{
    gates::circuit::{builder::BaseCircuitBuilder, CircuitBuilderStage},
    halo2_proofs::{
        dev::MockProver,
        halo2curves::{
            bn256,
            ed25519::{Ed25519Affine, Fq as Fp, Fr as Fq},
        },
    },
    utils::{bigint_to_fe, fe_to_bigint, BigPrimeField},
};
use halo2_ecc::{
    bigint::ProperCrtUint,
    fields::{fp::FpChip, FieldChip},
};
use num_bigint::BigInt;
use num_traits::Zero;
use rand_core::OsRng;

use super::ecc::EccChip;

#[cfg(test)]
pub fn to_bigint<F>(proper_crt_uint: ProperCrtUint<F>, limb_bits: usize) -> BigInt
where
    F: BigPrimeField,
{
    proper_crt_uint
        .limbs()
        .iter()
        .rev()
        .fold(BigInt::zero(), |acc, acell| {
            (acc << limb_bits) + fe_to_bigint(acell.value())
        })
}

fn basic_tests<F: BigPrimeField>(
    builder: &mut BaseCircuitBuilder<F>,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    P: Ed25519Affine,
    Q: Ed25519Affine,
) {
    builder.set_lookup_bits(lookup_bits);
    let range = builder.range_chip();
    let ctx = builder.main(0);
    let fp_chip = FpChip::<F, Fp>::new(&range, limb_bits, num_limbs);
    let chip = EccChip::new(&fp_chip);

    let P_assigned = chip.load_private_unchecked(ctx, (P.x, P.y));
    let Q_assigned = chip.load_private_unchecked(ctx, (Q.x, Q.y));

    // test add_unequal
    chip.field_chip
        .enforce_less_than(ctx, P_assigned.x().clone());
    chip.field_chip
        .enforce_less_than(ctx, Q_assigned.x().clone());
    let sum = chip.add::<Ed25519Affine>(ctx, &P_assigned, &Q_assigned);
    assert_eq!(to_bigint(sum.x.clone(), limb_bits), sum.x.value().into());
    assert_eq!(to_bigint(sum.y.clone(), limb_bits), sum.y.value().into());
    {
        let actual_sum = Ed25519Affine::from(P + Q);
        assert_eq!(bigint_to_fe::<Fp>(&sum.x.value().into()), actual_sum.x);
        assert_eq!(bigint_to_fe::<Fp>(&sum.y.value().into()), actual_sum.y);
    }
    println!("add witness OK");

    // test double
    let doub = chip.double::<Ed25519Affine>(ctx, &P_assigned);
    assert_eq!(to_bigint(doub.x.clone(), limb_bits), doub.x.value().into());
    assert_eq!(to_bigint(doub.y.clone(), limb_bits), doub.y.value().into());
    {
        let actual_doub = Ed25519Affine::from(P * Fq::from(2u64));
        assert_eq!(bigint_to_fe::<Fp>(&doub.x.value().into()), actual_doub.x);
        assert_eq!(bigint_to_fe::<Fp>(&doub.y.value().into()), actual_doub.y);
    }
    println!("double witness OK");
}

#[test]
fn test_ecc() {
    let k = 23;
    let P = Ed25519Affine::random(OsRng);
    let Q = Ed25519Affine::random(OsRng);

    let mut builder =
        BaseCircuitBuilder::<bn256::Fr>::from_stage(CircuitBuilderStage::Mock).use_k(k);
    basic_tests(&mut builder, k - 1, 88, 3, P, Q);

    builder.calculate_params(Some(20));

    MockProver::run(k as u32, &builder, vec![])
        .unwrap()
        .assert_satisfied();
}
