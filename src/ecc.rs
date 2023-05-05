#![allow(non_snake_case)]
use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    halo2_proofs::arithmetic::CurveAffine,
    utils::{modulus, CurveAffineExt},
    AssignedValue, Context,
};
use halo2_ecc::{
    bigint::CRTInteger,
    ecc::EcPoint,
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
    let d = chip.load_constant(ctx, FC::fe_to_constant(C::b()));
    let one = chip.load_constant(ctx, FC::fe_to_constant(FC::FieldType::one()));

    // x3 = (x1 * y2 + y1 * x2) / (1 + d * x1 * x2 * y1 * y2)
    let x1_y2 = chip.mul(ctx, &P.x, &Q.y);
    let y1_x2 = chip.mul(ctx, &P.y, &Q.x);
    let x1_x2_y1_y2 = chip.mul(ctx, &x1_y2, &y1_x2);
    let d_x1_x2_y1_y2 = chip.mul(ctx, &d, &x1_x2_y1_y2);

    let denominator_x = chip.add_no_carry(ctx, &one, &d_x1_x2_y1_y2);
    let numerator_x = chip.add_no_carry(ctx, &x1_y2, &y1_x2);

    let x_3 = chip.divide(ctx, &numerator_x, &denominator_x);

    // y3 = (y1 * y2 + x1 * x2) / (1 - d * x1 * x2 * y1 * y2)
    let y1_y2 = chip.mul(ctx, &P.y, &Q.y);
    let x1_x2 = chip.mul(ctx, &P.x, &Q.x);

    let numerator_y = chip.add_no_carry(ctx, &y1_y2, &x1_x2);
    let denominator_y = chip.sub_no_carry(ctx, &one, &d_x1_x2_y1_y2);

    let y_3 = chip.divide(ctx, &numerator_y, &denominator_y);

    EcPoint::construct(x_3, y_3)
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
    let d = chip.load_constant(ctx, FC::fe_to_constant(C::b()));
    let one = chip.load_constant(ctx, FC::fe_to_constant(FC::FieldType::one()));

    // x2 = (2 * x1 * y1) / (1 + d * x1^2 * y1^2)
    let x1_y1 = chip.mul(ctx, &P.x, &P.y);
    let x1_y1_2 = chip.mul(ctx, &x1_y1, &x1_y1);
    let d_x1_y1_2 = chip.mul(ctx, &d, &x1_y1_2);

    let denominator_x = chip.add_no_carry(ctx, &one, &d_x1_y1_2);
    let numerator_x = chip.scalar_mul_no_carry(ctx, &x1_y1, 2);

    let x_3 = chip.divide(ctx, &numerator_x, &denominator_x);

    // y2 = (y1^2 + x1^2) / (1 - d * x1^2 * y1^2)
    let x1_2 = chip.mul(ctx, &P.x, &P.x);
    let y1_2 = chip.mul(ctx, &P.y, &P.y);

    let numerator_y = chip.add_no_carry(ctx, &y1_2, &x1_2);
    let denominator_y = chip.sub_no_carry(ctx, &one, &d_x1_y1_2);

    let y_3 = chip.divide(ctx, &numerator_y, &denominator_y);

    EcPoint::construct(x_3, y_3)
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
    let d = chip.load_constant(ctx, FC::fe_to_constant(C::b()));
    let one = chip.load_constant(ctx, FC::fe_to_constant(FC::FieldType::one()));

    // x3 = (x1 * y2 + y1 * x2) / (1 + d * x1 * x2 * y1 * y2)
    let x1_y2 = chip.mul(ctx, &P.x, &Q.y);
    let y1_x2 = chip.mul(ctx, &P.y, &Q.x);
    let x1_x2_y1_y2 = chip.mul(ctx, &x1_y2, &y1_x2);
    let d_x1_x2_y1_y2 = chip.mul(ctx, &d, &x1_x2_y1_y2);

    let denominator_x = chip.sub_no_carry(ctx, &one, &d_x1_x2_y1_y2);
    let numerator_x = chip.sub_no_carry(ctx, &x1_y2, &y1_x2);

    let x_3 = chip.divide(ctx, &numerator_x, &denominator_x);

    // y3 = (y1 * y2 + x1 * x2) / (1 - d * x1 * x2 * y1 * y2)
    let y1_y2 = chip.mul(ctx, &P.y, &Q.y);
    let x1_x2 = chip.mul(ctx, &P.x, &Q.x);

    let numerator_y = chip.sub_no_carry(ctx, &y1_y2, &x1_x2);
    let denominator_y = chip.add_no_carry(ctx, &one, &d_x1_x2_y1_y2);

    let y_3 = chip.divide(ctx, &numerator_y, &denominator_y);

    EcPoint::construct(x_3, y_3)
}

pub fn ec_select<F: PrimeField, FC>(
    chip: &FC,
    ctx: &mut Context<F>,
    P: &EcPoint<F, FC::FieldPoint>,
    Q: &EcPoint<F, FC::FieldPoint>,
    sel: AssignedValue<F>,
) -> EcPoint<F, FC::FieldPoint>
where
    FC: FieldChip<F> + Selectable<F, Point = FC::FieldPoint>,
{
    let Rx = chip.select(ctx, &P.x, &Q.x, sel);
    let Ry = chip.select(ctx, &P.y, &Q.y, sel);
    EcPoint::construct(Rx, Ry)
}

// takes the dot product of points with sel, where each is intepreted as
// a _vector_
pub fn ec_select_by_indicator<F: PrimeField, FC>(
    chip: &FC,
    ctx: &mut Context<F>,
    points: &[EcPoint<F, FC::FieldPoint>],
    coeffs: &[AssignedValue<F>],
) -> EcPoint<F, FC::FieldPoint>
where
    FC: FieldChip<F> + Selectable<F, Point = FC::FieldPoint>,
{
    let x_coords = points.iter().map(|P| P.x.clone()).collect::<Vec<_>>();
    let y_coords = points.iter().map(|P| P.y.clone()).collect::<Vec<_>>();
    let Rx = chip.select_by_indicator(ctx, &x_coords, coeffs);
    let Ry = chip.select_by_indicator(ctx, &y_coords, coeffs);
    EcPoint::construct(Rx, Ry)
}

// `sel` is little-endian binary
pub fn ec_select_from_bits<F: PrimeField, FC>(
    chip: &FC,
    ctx: &mut Context<F>,
    points: &[EcPoint<F, FC::FieldPoint>],
    sel: &[AssignedValue<F>],
) -> EcPoint<F, FC::FieldPoint>
where
    FC: FieldChip<F> + Selectable<F, Point = FC::FieldPoint>,
{
    let w = sel.len();
    let num_points = points.len();
    assert_eq!(1 << w, num_points);
    let coeffs = chip.range().gate().bits_to_indicator(ctx, sel);
    ec_select_by_indicator(chip, ctx, points, &coeffs)
}

// computes [scalar] * P on twisted Edwards curve (Ed25519)
// - `scalar` is represented as a reference array of `AssignedCell`s
// - `scalar = sum_i scalar_i * 2^{max_bits * i}`
// - an array of length > 1 is needed when `scalar` exceeds the modulus of scalar field `F`
// assumes:
// - `scalar_i < 2^{max_bits} for all i` (constrained by num_to_bits)
// - `max_bits <= modulus::<F>.bits()`
//   * P has order given by the scalar field modulus
pub fn scalar_multiply<F: PrimeField, FC, C>(
    chip: &FC,
    ctx: &mut Context<F>,
    P: &EcPoint<F, FC::FieldPoint>,
    scalar: Vec<AssignedValue<F>>,
    max_bits: usize,
    window_bits: usize,
) -> EcPoint<F, FC::FieldPoint>
where
    FC: FieldChip<F> + Selectable<F, Point = FC::FieldPoint>,
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
            let double = ec_double::<F, FC, C>(chip, ctx, P /*, b*/);
            cached_points.push(double);
        } else {
            let new_point = ec_add::<F, FC, C>(chip, ctx, &cached_points[idx - 1], P);
            cached_points.push(new_point);
        }
    }

    // if all the starting window bits are 0, get start_point = P
    let mut curr_point = ec_select_from_bits::<F, FC>(
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
        let add_point = ec_select_from_bits::<F, FC>(
            chip,
            ctx,
            &cached_points,
            &rounded_bits
                [rounded_bitlen - window_bits * (idx + 1)..rounded_bitlen - window_bits * idx],
        );
        let mult_and_add = ec_add::<F, FC, C>(chip, ctx, &mult_point, &add_point);
        let is_started_point =
            ec_select(chip, ctx, &mult_point, &mult_and_add, is_zero_window[idx]);

        curr_point = ec_select(
            chip,
            ctx,
            &is_started_point,
            &add_point,
            is_started[window_bits * idx],
        );
    }
    curr_point
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

    pub fn load_private(
        &self,
        ctx: &mut Context<F>,
        point: (FC::FieldType, FC::FieldType),
    ) -> EcPoint<F, FC::FieldPoint> {
        let (x, y) = (FC::fe_to_witness(&point.0), FC::fe_to_witness(&point.1));

        let x_assigned = self.field_chip.load_private(ctx, x);
        let y_assigned = self.field_chip.load_private(ctx, y);

        EcPoint::construct(x_assigned, y_assigned)
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
        ec_add::<F, FC, C>(self.field_chip, ctx, P, Q)
    }

    pub fn double<C>(
        &self,
        ctx: &mut Context<F>,
        P: &EcPoint<F, FC::FieldPoint>,
    ) -> EcPoint<F, FC::FieldPoint>
    where
        C: CurveAffineExt<Base = FC::FieldType>,
    {
        ec_double::<F, FC, C>(self.field_chip, ctx, P)
    }

    pub fn is_equal(
        &self,
        ctx: &mut Context<F>,
        P: &EcPoint<F, FC::FieldPoint>,
        Q: &EcPoint<F, FC::FieldPoint>,
    ) -> AssignedValue<F> {
        // TODO: optimize
        let x_is_equal = self.field_chip.is_equal(ctx, &P.x, &Q.x);
        let y_is_equal = self.field_chip.is_equal(ctx, &P.y, &Q.y);
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
        FC: PrimeFieldChip<F, FieldType = C::Base, FieldPoint = CRTInteger<F>>
            + Selectable<F, Point = FC::FieldPoint>,
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
