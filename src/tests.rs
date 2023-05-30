#![allow(non_snake_case)]
use halo2_base::{
    gates::{
        builder::{GateThreadBuilder, RangeCircuitBuilder},
        RangeChip,
    },
    halo2_proofs::{
        dev::MockProver,
        halo2curves::ed25519::{Ed25519Affine, Fq as Fp, Fr as Fq},
    },
    utils::{bigint_to_fe, fe_to_bigint, BigPrimeField},
    Context,
};
use halo2_ecc::{
    bigint::ProperCrtUint,
    fields::{fp::FpChip, FieldChip, PrimeField},
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

    let mut builder = GateThreadBuilder::<Fq>::mock();
    basic_tests(builder.main(0), k - 1, 88, 3, P, Q);

    builder.config(k, Some(20));
    let circuit = RangeCircuitBuilder::mock(builder);

    MockProver::run(k as u32, &circuit, vec![])
        .unwrap()
        .assert_satisfied();
}

#[cfg(feature = "dev-graph")]
#[test]
fn plot_ecc() {
    let k = 23;
    use plotters::prelude::*;

    let root = BitMapBackend::new("layout.png", (512, 16384)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root.titled("Ecc Layout", ("sans-serif", 60)).unwrap();

    let P = Ed25519Affine::random(OsRng);
    let Q = Ed25519Affine::random(OsRng);

    let mut builder = GateThreadBuilder::<Fq>::keygen();
    basic_tests(builder.main(0), k - 1, 88, 3, P, Q);

    builder.config(k, Some(20));
    let circuit = RangeCircuitBuilder::mock(builder);

    halo2_base::halo2_proofs::dev::CircuitLayout::default()
        .render(k as u32, &circuit, &root)
        .unwrap();
}
