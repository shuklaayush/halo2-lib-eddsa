use halo2_base::{
    utils::{biguint_to_fe, BigPrimeField, CurveAffineExt},
    AssignedValue, Context,
};
use halo2_ecc::bigint::ProperCrtUint;
use halo2_ecc::{
    ecc::EcPoint,
    fields::{fp::FpChip, FieldChip},
};
use num_bigint::BigUint;

use super::ecc::{ec_sub, scalar_multiply, EccChip};
use super::fixed_base;

// CF is the coordinate field of GA
// SF is the scalar field of GA
// p = coordinate field modulus
// n = scalar field modulus
// Assumes `s` is proper CRT integer
/// TODO: Check `pubkey` should not be the identity point
#[allow(non_snake_case)]
pub fn eddsa_verify<F: BigPrimeField, CF: BigPrimeField, SF: BigPrimeField, GA>(
    chip: &EccChip<F, FpChip<F, CF>>,
    ctx: &mut Context<F>,
    pubkey: EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>, // A
    R: EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>,
    s: ProperCrtUint<F>,
    msghash: ProperCrtUint<F>,
    var_window_bits: usize,
    fixed_window_bits: usize,
) -> AssignedValue<F>
where
    GA: CurveAffineExt<Base = CF, ScalarExt = SF>,
{
    let base_chip = chip.field_chip;
    let scalar_chip =
        FpChip::<F, SF>::new(base_chip.range, base_chip.limb_bits, base_chip.num_limbs);

    // Check s < L
    scalar_chip.enforce_less_than_p(ctx, s.clone());

    // Compute h = H(R || A || M)
    let k = msghash;

    // Compute sB
    let sB = fixed_base::scalar_multiply(
        base_chip,
        ctx,
        &GA::generator(),
        s.limbs().to_vec(),
        base_chip.limb_bits,
        fixed_window_bits,
    );
    // Compute kA
    let kA = scalar_multiply::<F, FpChip<F, CF>, GA>(
        base_chip,
        ctx,
        pubkey,
        k.limbs().to_vec(),
        base_chip.limb_bits,
        var_window_bits,
    );

    // Compute R' = sB - kA
    let R_prime = ec_sub::<F, FpChip<F, CF>, GA>(base_chip, ctx, &sB, &kA);

    let sub = ec_sub::<F, FpChip<F, CF>, GA>(base_chip, ctx, &R, &R_prime);
    // TODO: Load cofactor from Curve trait
    //       EdDSA should be curve agnostic
    let cofactor = scalar_chip.load_constant(ctx, biguint_to_fe(&(BigUint::from(8u32))));

    let sub_mul_cofactor = scalar_multiply::<F, FpChip<F, CF>, GA>(
        base_chip,
        ctx,
        sub,
        cofactor.limbs().to_vec(),
        base_chip.limb_bits,
        var_window_bits,
    );

    // Check if 8(R - R') = O
    base_chip.is_zero(ctx, &sub_mul_cofactor.x)
}

// TODO: Decode R, s inside circuit
//       Don't prehash
