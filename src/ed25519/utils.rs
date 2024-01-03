#![allow(non_snake_case)]
use halo2_base::gates::RangeChip;
use halo2_base::halo2_proofs::halo2curves::ed25519::{Ed25519Affine, Fq as Fp, Fr as Fq};
use halo2_base::utils::BigPrimeField;
use halo2_base::{halo2_proofs::halo2curves::ff::FromUniformBytes, Context};
use halo2_ecc::ecc::EcPoint;
use halo2_ecc::fields::{FieldChip, FpStrategy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::ecc::EccChip;
use crate::ed25519::{FpChip, FqChip};
use crate::eddsa::eddsa_verify;

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

pub fn hash_to_fe(hash: Sha512) -> Fq {
    let output: [u8; 64] = hash.finalize().as_slice().try_into().unwrap();
    Fq::from_uniform_bytes(&output)
}

#[derive(Clone, Copy, Debug)]
pub struct EdDSAInput {
    pub R: Ed25519Affine,
    pub s: Fq,
    pub msghash: Fq,
    pub pubkey: Ed25519Affine,
}

impl EdDSAInput {
    pub fn from_bytes(sig: &[u8; 64], A_bytes: &[u8; 32], msg: &[u8]) -> Self {
        let R_bytes: [u8; 32] = sig[..32].try_into().unwrap();
        let s_bytes: [u8; 32] = sig[32..].try_into().unwrap();

        let msghash = hash_to_fe(
            Sha512::default()
                .chain(&R_bytes[..])
                .chain(&A_bytes[..])
                .chain(msg),
        );

        let R = Ed25519Affine::from_bytes(R_bytes).unwrap();
        let s = Fq::from_bytes(&s_bytes).unwrap();
        let A = Ed25519Affine::from_bytes(*A_bytes).unwrap();

        EdDSAInput {
            R,
            s,
            msghash,
            pubkey: A,
        }
    }
}

pub fn eddsa_circuit<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    params: CircuitParams,
    input: EdDSAInput,
) -> F {
    let fp_chip = FpChip::<F>::new(range, params.limb_bits, params.num_limbs);
    let fq_chip = FqChip::<F>::new(range, params.limb_bits, params.num_limbs);

    let [m, s] = [input.msghash, input.s].map(|x| fq_chip.load_private(ctx, x));
    let [Rx, Ry] = [input.R.x, input.R.y].map(|x| fp_chip.load_private(ctx, x));
    let R = EcPoint::new(Rx, Ry);

    let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);
    let pubkey = ecc_chip.load_private_unchecked(ctx, (input.pubkey.x, input.pubkey.y));
    // test EdDSA
    let res = eddsa_verify::<F, Fp, Fq, Ed25519Affine>(&ecc_chip, ctx, pubkey, R, s, m, 4, 4);
    *res.value()
}
