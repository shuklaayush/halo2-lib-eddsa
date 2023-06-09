#![allow(non_snake_case)]
use ark_std::{end_timer, start_timer};
use halo2_base::gates::builder::{
    CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints, RangeCircuitBuilder,
};
use halo2_base::gates::RangeChip;
use halo2_base::halo2_proofs::{
    halo2curves::bn256::Fr,
    halo2curves::ed25519::{Ed25519Affine, Fq as Fp, Fr as Fq},
};
use halo2_base::Context;
use halo2_ecc::ecc::EcPoint;
use halo2_ecc::fields::{FieldChip, FpStrategy, PrimeField};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::ed25519::{FpChip, FqChip};
use crate::{ecc::EccChip, eddsa::eddsa_verify};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct CircuitParams {
    pub strategy: FpStrategy,
    pub degree: u32,
    pub num_advice: usize,
    pub num_lookup_advice: usize,
    pub num_fixed: usize,
    pub lookup_bits: usize,
    pub limb_bits: usize,
    pub num_limbs: usize,
}

pub fn eddsa_circuit_synthesize<F: PrimeField>(
    ctx: &mut Context<F>,
    params: CircuitParams,
    R: Ed25519Affine,
    s: Fq,
    msghash: Fq,
    pubkey: Ed25519Affine,
) {
    std::env::set_var("LOOKUP_BITS", params.lookup_bits.to_string());
    let range = RangeChip::<F>::default(params.lookup_bits);
    let fp_chip = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let fq_chip = FqChip::<F>::new(&range, params.limb_bits, params.num_limbs);

    let [m, s] = [msghash, s].map(|x| fq_chip.load_private(ctx, x));
    let [Rx, Ry] = [R.x, R.y].map(|x| fp_chip.load_private(ctx, x));
    let R = EcPoint::new(Rx, Ry);

    let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);
    let pubkey = ecc_chip.load_private_unchecked(ctx, (pubkey.x, pubkey.y));
    // test EdDSA
    let res = eddsa_verify::<F, Fp, Fq, Ed25519Affine>(&ecc_chip, ctx, pubkey, R, s, m, 4, 4);
    assert_eq!(res.value(), &F::one());
}

pub fn hash_to_fe(hash: Sha512) -> Fq {
    let output: [u8; 64] = hash.finalize().as_slice().try_into().unwrap();
    Fq::from_bytes_wide(&output)
}

pub fn eddsa_circuit(
    params: CircuitParams,
    stage: CircuitBuilderStage,
    break_points: Option<MultiPhaseThreadBreakPoints>,
    sig: &[u8; 64],
    A_bytes: &[u8; 32],
    msg: &[u8],
) -> RangeCircuitBuilder<Fr> {
    let mut builder = match stage {
        CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
        CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
        CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
    };

    let R_bytes: [u8; 32] = sig[..32].try_into().unwrap();
    let s_bytes: [u8; 32] = sig[32..].try_into().unwrap();

    // TODO: Rename
    let msg_hash = hash_to_fe(
        Sha512::default()
            .chain(&R_bytes[..])
            .chain(&A_bytes[..])
            .chain(msg),
    );

    let R = Ed25519Affine::from_bytes(R_bytes).unwrap();
    let s = Fq::from_bytes(&s_bytes).unwrap();
    let A = Ed25519Affine::from_bytes(*A_bytes).unwrap();

    let start0 = start_timer!(|| format!("Witness generation for circuit in {stage:?} stage"));
    eddsa_circuit_synthesize(builder.main(0), params, R, s, msg_hash, A);

    let circuit = match stage {
        CircuitBuilderStage::Mock => {
            builder.config(params.degree as usize, Some(20));
            RangeCircuitBuilder::mock(builder)
        }
        CircuitBuilderStage::Keygen => {
            builder.config(params.degree as usize, Some(20));
            RangeCircuitBuilder::keygen(builder)
        }
        CircuitBuilderStage::Prover => RangeCircuitBuilder::prover(builder, break_points.unwrap()),
    };
    end_timer!(start0);
    circuit
}
