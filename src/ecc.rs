#![allow(non_snake_case)]
use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    halo2_proofs::arithmetic::CurveAffine,
    utils::{modulus, CurveAffineExt},
    AssignedValue, Context,
};
use halo2_ecc::{
    ecc::{ec_select, ec_select_from_bits, EcPoint},
    fields::{fp::FpChip, FieldChip, PrimeField, PrimeFieldChip, Selectable},
};
use std::marker::PhantomData;

use super::fixed_base;

// EcPoint and EccChip take in a generic `FieldChip` to implement generic elliptic curve operations on arbitrary field extensions (provided chip exists) for twisted Edwards curves
// i.e. a.x^2 + y^2 = 1 + d.x^2.y^2

// Implements:
//  Given P = (x_1, y_1) and Q = (x_2, y_2), ecc points over the twisted Edwards curve (Ed25519) in the field F_p
//  Find ec addition P + Q = (x_3, y_3)
// By solving:
//  x_3 = (x_1 * y_2 + y_1 * x_2) / (1 + d * x_1 * x_2 * y_1 * y_2)
//  y_3 = (y_1 * y_2 + x_1 * x_2) / (1 - d * x_1 * x_2 * y_1 * y_2)
// Where d is a constant specific to the twisted Edwards curve (Ed25519)
pub fn ec_add<F, FC, C>(
    chip: &FC,
    ctx: &mut Context<F>,
    P: &EcPoint<F, FC::FieldPoint>,
    Q: &EcPoint<F, FC::FieldPoint>,
) -> EcPoint<F, FC::FieldPoint>
where
    F: PrimeField,
    FC: FieldChip<F>,
    C: CurveAffine<Base = FC::FieldType>,
{
    let d = chip.load_constant(ctx, C::b());
    let one = chip.load_constant(ctx, FC::FieldType::one());

    // x3 = (x1 * y2 + y1 * x2) / (1 + d * x1 * x2 * y1 * y2)
    let x1_y2 = chip.mul(ctx, &P.x, &Q.y);
    let y1_x2 = chip.mul(ctx, &P.y, &Q.x);
    let x1_x2_y1_y2 = chip.mul(ctx, &x1_y2, &y1_x2);
    let d_x1_x2_y1_y2 = chip.mul(ctx, &d, &x1_x2_y1_y2);

    let denominator_x = chip.add_no_carry(ctx, &one, &d_x1_x2_y1_y2);
    let numerator_x = chip.add_no_carry(ctx, &x1_y2, &y1_x2);

    let x_3 = chip.divide_unsafe(ctx, &numerator_x, &denominator_x);

    // y3 = (y1 * y2 + x1 * x2) / (1 - d * x1 * x2 * y1 * y2)
    let y1_y2 = chip.mul(ctx, &P.y, &Q.y);
    let x1_x2 = chip.mul(ctx, &P.x, &Q.x);

    let numerator_y = chip.add_no_carry(ctx, &y1_y2, &x1_x2);
    let denominator_y = chip.sub_no_carry(ctx, &one, &d_x1_x2_y1_y2);

    let y_3 = chip.divide_unsafe(ctx, &numerator_y, &denominator_y);

    EcPoint::new(x_3, y_3)
}

// Implements:
//  Given P = (x_1, y_1) and Q = (x_2, y_2), ecc points over the twisted Edwards curve (Ed25519) in the field F_p
//  Find ec addition P - Q = (x_3, y_3)
// By solving:
//  x_3 = (x_1 * y_2 - y_1 * x_2) / (1 - d * x_1 * x_2 * y_1 * y_2)
//  y_3 = (y_1 * y_2 - x_1 * x_2) / (1 + d * x_1 * x_2 * y_1 * y_2)
// Where d is a constant specific to the twisted Edwards curve (Ed25519)
pub fn ec_sub<F, FC, C>(
    chip: &FC,
    ctx: &mut Context<F>,
    P: &EcPoint<F, FC::FieldPoint>,
    Q: &EcPoint<F, FC::FieldPoint>,
) -> EcPoint<F, FC::FieldPoint>
where
    F: PrimeField,
    FC: FieldChip<F>,
    C: CurveAffine<Base = FC::FieldType>,
{
    let d = chip.load_constant(ctx, C::b());
    let one = chip.load_constant(ctx, FC::FieldType::one());

    // x3 = (x1 * y2 + y1 * x2) / (1 + d * x1 * x2 * y1 * y2)
    let x1_y2 = chip.mul(ctx, &P.x, &Q.y);
    let y1_x2 = chip.mul(ctx, &P.y, &Q.x);
    let x1_x2_y1_y2 = chip.mul(ctx, &x1_y2, &y1_x2);
    let d_x1_x2_y1_y2 = chip.mul(ctx, &d, &x1_x2_y1_y2);

    let denominator_x = chip.sub_no_carry(ctx, &one, &d_x1_x2_y1_y2);
    let numerator_x = chip.sub_no_carry(ctx, &x1_y2, &y1_x2);

    let x_3 = chip.divide_unsafe(ctx, &numerator_x, &denominator_x);

    // y3 = (y1 * y2 + x1 * x2) / (1 - d * x1 * x2 * y1 * y2)
    let y1_y2 = chip.mul(ctx, &P.y, &Q.y);
    let x1_x2 = chip.mul(ctx, &P.x, &Q.x);

    let numerator_y = chip.sub_no_carry(ctx, &y1_y2, &x1_x2);
    let denominator_y = chip.add_no_carry(ctx, &one, &d_x1_x2_y1_y2);

    let y_3 = chip.divide_unsafe(ctx, &numerator_y, &denominator_y);

    EcPoint::new(x_3, y_3)
}

pub fn ec_double<F, FC, C>(
    chip: &FC,
    ctx: &mut Context<F>,
    P: &EcPoint<F, FC::FieldPoint>,
) -> EcPoint<F, FC::FieldPoint>
where
    F: PrimeField,
    FC: FieldChip<F>,
    C: CurveAffine<Base = FC::FieldType>,
{
    let d = chip.load_constant(ctx, C::b());
    let one = chip.load_constant(ctx, FC::FieldType::one());

    // x2 = (2 * x1 * y1) / (1 + d * x1^2 * y1^2)
    let x1_y1 = chip.mul(ctx, &P.x, &P.y);
    let x1_y1_2 = chip.mul(ctx, &x1_y1, &x1_y1);
    let d_x1_y1_2 = chip.mul(ctx, &d, &x1_y1_2);

    let denominator_x = chip.add_no_carry(ctx, &one, &d_x1_y1_2);
    let numerator_x = chip.scalar_mul_no_carry(ctx, &x1_y1, 2);

    let x_3 = chip.divide_unsafe(ctx, &numerator_x, &denominator_x);

    // y2 = (y1^2 + x1^2) / (1 - d * x1^2 * y1^2)
    let x1_2 = chip.mul(ctx, &P.x, &P.x);
    let y1_2 = chip.mul(ctx, &P.y, &P.y);

    let numerator_y = chip.add_no_carry(ctx, &y1_2, &x1_2);
    let denominator_y = chip.sub_no_carry(ctx, &one, &d_x1_y1_2);

    let y_3 = chip.divide_unsafe(ctx, &numerator_y, &denominator_y);

    EcPoint::new(x_3, y_3)
}

// computes [scalar] * P on twisted Edwards curve (Ed25519)
/// - `scalar` is represented as a reference array of `AssignedValue`s
/// - `scalar = sum_i scalar_i * 2^{max_bits * i}`
/// - an array of length > 1 is needed when `scalar` exceeds the modulus of scalar field `F`
///
/// # Assumptions
/// - `P` is not the point at infinity
/// - `scalar > 0`
/// - `scalar_i < 2^{max_bits} for all i`
/// - `max_bits <= modulus::<F>.bits()`, and equality only allowed when the order of `P` equals the modulus of `F`
pub fn scalar_multiply<F: PrimeField, FC, C>(
    chip: &FC,
    ctx: &mut Context<F>,
    P: EcPoint<F, FC::FieldPoint>,
    scalar: Vec<AssignedValue<F>>,
    max_bits: usize,
    window_bits: usize,
) -> EcPoint<F, FC::FieldPoint>
where
    FC: FieldChip<F> + Selectable<F, FC::FieldPoint>,
    C: CurveAffine<Base = FC::FieldType>,
{
    assert!(!scalar.is_empty());
    assert!((max_bits as u64) <= modulus::<F>().bits());

    let total_bits = max_bits * scalar.len();
    let num_windows = (total_bits + window_bits - 1) / window_bits;
    let rounded_bitlen = num_windows * window_bits;

    let mut bits = Vec::with_capacity(rounded_bitlen);
    for x in scalar {
        let mut new_bits = chip.gate().num_to_bits(ctx, x, max_bits);
        bits.append(&mut new_bits);
    }
    let mut rounded_bits = bits;
    let zero_cell = ctx.load_zero();
    rounded_bits.resize(rounded_bitlen, zero_cell);

    // is_started[idx] holds whether there is a 1 in bits with index at least (rounded_bitlen - idx)
    let mut is_started = Vec::with_capacity(rounded_bitlen);
    is_started.resize(rounded_bitlen - total_bits + 1, zero_cell);
    for idx in 1..total_bits {
        let or = chip.gate().or(
            ctx,
            *is_started.last().unwrap(),
            rounded_bits[total_bits - idx],
        );
        is_started.push(or);
    }

    // is_zero_window[idx] is 0/1 depending on whether bits [rounded_bitlen - window_bits * (idx + 1), rounded_bitlen - window_bits * idx) are all 0
    let mut is_zero_window = Vec::with_capacity(num_windows);
    for idx in 0..num_windows {
        let temp_bits = rounded_bits
            [rounded_bitlen - window_bits * (idx + 1)..rounded_bitlen - window_bits * idx]
            .iter()
            .copied();
        let bit_sum = chip.gate().sum(ctx, temp_bits);
        let is_zero = chip.gate().is_zero(ctx, bit_sum);
        is_zero_window.push(is_zero);
    }

    // cached_points[idx] stores idx * P, with cached_points[0] = P
    let cache_size = 1usize << window_bits;
    let mut cached_points = Vec::with_capacity(cache_size);
    cached_points.push(P.clone());
    cached_points.push(P.clone());
    for idx in 2..cache_size {
        if idx == 2 {
            let double = ec_double::<F, FC, C>(chip, ctx, &P);
            cached_points.push(double);
        } else {
            let new_point = ec_add::<F, FC, C>(chip, ctx, &cached_points[idx - 1], &P);
            cached_points.push(new_point);
        }
    }

    // if all the starting window bits are 0, get start_point = P
    let mut curr_point = ec_select_from_bits(
        chip,
        ctx,
        &cached_points,
        &rounded_bits[rounded_bitlen - window_bits..rounded_bitlen],
    );

    for idx in 1..num_windows {
        let mut mult_point = curr_point.clone();
        for _ in 0..window_bits {
            mult_point = ec_double::<F, FC, C>(chip, ctx, &mult_point);
        }
        let add_point = ec_select_from_bits(
            chip,
            ctx,
            &cached_points,
            &rounded_bits
                [rounded_bitlen - window_bits * (idx + 1)..rounded_bitlen - window_bits * idx],
        );
        let mult_and_add = ec_add::<F, FC, C>(chip, ctx, &mult_point, &add_point);
        let is_started_point = ec_select(chip, ctx, mult_point, mult_and_add, is_zero_window[idx]);

        curr_point = ec_select(
            chip,
            ctx,
            is_started_point,
            add_point,
            is_started[window_bits * idx],
        );
    }
    curr_point
}

/// Checks that `P` is indeed a point on the elliptic curve `C`.
// i.e. a.x^2 + y^2 = 1 + d.x^2.y^2
pub fn check_is_on_curve<F, FC, C>(chip: &FC, ctx: &mut Context<F>, P: &EcPoint<F, FC::FieldPoint>)
where
    F: PrimeField,
    FC: FieldChip<F>,
    C: CurveAffine<Base = FC::FieldType>,
{
    let x2 = chip.mul_no_carry(ctx, &P.x, &P.x);
    let y2 = chip.mul_no_carry(ctx, &P.y, &P.y);
    let lhs = chip.sub_no_carry(ctx, &y2, &x2);

    let d = chip.load_constant(ctx, C::b());

    let mut d_x2_y2 = chip.mul_no_carry(ctx, &x2, &y2);
    d_x2_y2 = chip.mul(ctx, &d, &d_x2_y2).into();
    let rhs = chip.add_constant_no_carry(ctx, d_x2_y2, FC::FieldType::one());

    let diff = chip.sub_no_carry(ctx, lhs, rhs);
    chip.check_carry_mod_to_zero(ctx, diff)
}

pub type BaseFieldEccChip<'chip, C> = EccChip<
    'chip,
    <C as CurveAffine>::ScalarExt,
    FpChip<'chip, <C as CurveAffine>::ScalarExt, <C as CurveAffine>::Base>,
>;

#[derive(Clone, Debug)]
pub struct EccChip<'chip, F: PrimeField, FC: FieldChip<F>> {
    pub field_chip: &'chip FC,
    _marker: PhantomData<F>,
}

impl<'chip, F: PrimeField, FC: FieldChip<F>> EccChip<'chip, F, FC> {
    pub fn new(field_chip: &'chip FC) -> Self {
        Self {
            field_chip,
            _marker: PhantomData,
        }
    }

    pub fn field_chip(&self) -> &FC {
        self.field_chip
    }

    /// Load affine point as private witness. Constrains witness to lie on curve. Does not allow (0, 0) point,
    pub fn load_private<C>(
        &self,
        ctx: &mut Context<F>,
        (x, y): (FC::FieldType, FC::FieldType),
    ) -> EcPoint<F, FC::FieldPoint>
    where
        C: CurveAffineExt<Base = FC::FieldType>,
    {
        let pt = self.load_private_unchecked(ctx, (x, y));
        self.assert_is_on_curve::<C>(ctx, &pt);
        pt
    }

    /// Does not constrain witness to lie on curve
    pub fn load_private_unchecked(
        &self,
        ctx: &mut Context<F>,
        (x, y): (FC::FieldType, FC::FieldType),
    ) -> EcPoint<F, FC::FieldPoint> {
        let x_assigned = self.field_chip.load_private(ctx, x);
        let y_assigned = self.field_chip.load_private(ctx, y);

        EcPoint::new(x_assigned, y_assigned)
    }

    pub fn assert_is_on_curve<C>(&self, ctx: &mut Context<F>, P: &EcPoint<F, FC::FieldPoint>)
    where
        C: CurveAffine<Base = FC::FieldType>,
    {
        check_is_on_curve::<F, FC, C>(self.field_chip, ctx, P)
    }

    pub fn add<C>(
        &self,
        ctx: &mut Context<F>,
        P: &EcPoint<F, FC::FieldPoint>,
        Q: &EcPoint<F, FC::FieldPoint>,
    ) -> EcPoint<F, FC::FieldPoint>
    where
        C: CurveAffineExt<Base = FC::FieldType>,
    {
        ec_add::<F, FC, C>(self.field_chip, ctx, &P, &Q)
    }

    pub fn double<C>(
        &self,
        ctx: &mut Context<F>,
        P: &EcPoint<F, FC::FieldPoint>,
    ) -> EcPoint<F, FC::FieldPoint>
    where
        C: CurveAffineExt<Base = FC::FieldType>,
    {
        ec_double::<F, FC, C>(self.field_chip, ctx, &P)
    }

    pub fn is_equal(
        &self,
        ctx: &mut Context<F>,
        P: EcPoint<F, FC::FieldPoint>,
        Q: EcPoint<F, FC::FieldPoint>,
    ) -> AssignedValue<F> {
        // TODO: optimize
        let x_is_equal = self.field_chip.is_equal(ctx, P.x, Q.x);
        let y_is_equal = self.field_chip.is_equal(ctx, P.y, Q.y);
        self.field_chip
            .range()
            .gate()
            .and(ctx, x_is_equal, y_is_equal)
    }
}

impl<'chip, F: PrimeField, FC: PrimeFieldChip<F>> EccChip<'chip, F, FC>
where
    FC::FieldType: PrimeField,
{
    // TODO: put a check in place that scalar is < modulus of C::Scalar
    pub fn fixed_base_scalar_mult<C>(
        &self,
        ctx: &mut Context<F>,
        point: &C,
        scalar: Vec<AssignedValue<F>>,
        max_bits: usize,
        window_bits: usize,
    ) -> EcPoint<F, FC::FieldPoint>
    where
        C: CurveAffineExt,
        FC: FieldChip<F, FieldType = C::Base> + Selectable<F, FC::FieldPoint>,
    {
        fixed_base::scalar_multiply::<F, _, _>(
            self.field_chip,
            ctx,
            point,
            scalar,
            max_bits,
            window_bits,
        )
    }
}
