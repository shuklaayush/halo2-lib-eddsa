#![allow(non_snake_case)]
use halo2_base::gates::RangeChip;
use halo2_base::halo2_proofs::arithmetic::Field;
use halo2_base::halo2_proofs::{
    halo2curves::bn256::Fr,
    halo2curves::ed25519::{Ed25519Affine, Fq as Fp, Fr as Fq},
};
use halo2_base::utils::testing::base_test;
use halo2_base::utils::BigPrimeField;
use halo2_base::{halo2_proofs::halo2curves::ff::FromUniformBytes, Context};
use halo2_ecc::ecc::EcPoint;
use halo2_ecc::fields::{FieldChip, FpStrategy};
use rand::RngCore;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::fs::File;
use std::io::BufReader;
use std::io::Write;
use std::{fs, io::BufRead};

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

fn hash_to_fe(hash: Sha512) -> Fq {
    let output: [u8; 64] = hash.finalize().as_slice().try_into().unwrap();
    Fq::from_uniform_bytes(&output)
}

fn seed_to_key(seed: [u8; 32]) -> (Fq, [u8; 32], [u8; 32]) {
    // Expand the seed to a 64-byte array with SHA512.
    let h = Sha512::digest(&seed[..]);

    // Convert the low half to a scalar with Ed25519 "clamping"
    let s = {
        let mut scalar_bytes: [u8; 32] = h.as_slice()[0..32].try_into().unwrap();
        // Clear the lowest three bits to make the scalar a multiple of 8
        scalar_bytes[0] &= 248;
        // Clear highest bit
        scalar_bytes[31] &= 127;
        // Set second highest bit to 1
        scalar_bytes[31] |= 64;

        let mut scalar_bytes_wide = [0u8; 64];
        scalar_bytes_wide[0..32].copy_from_slice(&scalar_bytes);

        Fq::from_uniform_bytes(&scalar_bytes_wide)
    };

    // Extract and cache the high half.
    let prefix = h.as_slice()[32..64].try_into().unwrap();

    // Compute the public key as A = [s]B.
    let A = Ed25519Affine::from(Ed25519Affine::generator() * s);
    let A_bytes = A.to_bytes();

    (s, prefix, A_bytes)
}

fn sign(s: Fq, prefix: [u8; 32], A_bytes: [u8; 32], msg: &[u8]) -> [u8; 64] {
    let r = hash_to_fe(Sha512::default().chain(&prefix[..]).chain(msg));

    let R_bytes = Ed25519Affine::from(Ed25519Affine::generator() * r).to_bytes();

    let k = hash_to_fe(
        Sha512::default()
            .chain(&R_bytes[..])
            .chain(&A_bytes[..])
            .chain(msg),
    );

    let s_bytes = (r + s * k).to_bytes();

    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&R_bytes[..]);
    signature[32..].copy_from_slice(&s_bytes[..]);

    signature
}

fn random_eddsa_input() -> EdDSAInput {
    // Generate a key pair
    let mut seed = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut seed[..]);

    let (s, prefix, A_bytes) = seed_to_key(seed);

    // Generate a valid signature
    let msg = b"test message";
    let sig = sign(s, prefix, A_bytes, msg);

    EdDSAInput::from_bytes(&sig, &A_bytes, msg)
}

pub fn eddsa_test<F: BigPrimeField>(
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

pub fn run_test(input: EdDSAInput) {
    let path = "configs/ed25519/eddsa_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let res = base_test()
        .k(params.degree)
        .lookup_bits(params.lookup_bits)
        .run(|ctx, range| eddsa_test(ctx, range, params, input));
    assert_eq!(res, Fr::ONE);
}

#[test]
fn test_ed25519_eddsa() {
    let input = random_eddsa_input();
    run_test(input);
}

#[test]
fn test_ssh_ed25519() {
    use ssh_key::SshSig;

    let ed25519_sig = "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg2jSEHYIEAcIfwZ2P9gnNUL7L1g\nqjkP1XG35XMGVvT+8AAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5\nAAAAQGOlq7vRfb6sd2m1V+lQEKj1/IKwck8p+Xcuu5/j4pZEDLICcEWcbKSz76XrddeUnY\nCvY/+F+UevG1iOUleRXww=\n-----END SSH SIGNATURE-----";
    let payload = "tree cb00595c68ae966d5a0319f44a07aae75e17118f\nparent bb588e3edd556583426e7f47856ca70a130f3b09\nauthor Ayush Shukla <shuklaayush247@gmail.com> 1686598553 +0200\ncommitter Ayush Shukla <shuklaayush247@gmail.com> 1686598626 +0200\n\nfix: produce concatenated signature\n";

    let sshsig = ed25519_sig.parse::<SshSig>().unwrap();
    let msg: &[u8] =
        &SshSig::signed_data(sshsig.namespace(), sshsig.hash_alg(), payload.as_bytes()).unwrap();

    let A_bytes: &[u8; 32] = sshsig.public_key().ed25519().unwrap().as_ref();
    let sig: &[u8; 64] = sshsig.signature().as_bytes().try_into().unwrap();

    let input = EdDSAInput::from_bytes(sig, A_bytes, msg);

    run_test(input);
}

#[test]
fn bench_ssh_ed25519() {
    use ssh_key::SshSig;

    let ed25519_sig = "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg2jSEHYIEAcIfwZ2P9gnNUL7L1g\nqjkP1XG35XMGVvT+8AAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5\nAAAAQGOlq7vRfb6sd2m1V+lQEKj1/IKwck8p+Xcuu5/j4pZEDLICcEWcbKSz76XrddeUnY\nCvY/+F+UevG1iOUleRXww=\n-----END SSH SIGNATURE-----";
    let payload = "tree cb00595c68ae966d5a0319f44a07aae75e17118f\nparent bb588e3edd556583426e7f47856ca70a130f3b09\nauthor Ayush Shukla <shuklaayush247@gmail.com> 1686598553 +0200\ncommitter Ayush Shukla <shuklaayush247@gmail.com> 1686598626 +0200\n\nfix: produce concatenated signature\n";

    let sshsig = ed25519_sig.parse::<SshSig>().unwrap();
    let msg: &[u8] =
        &SshSig::signed_data(sshsig.namespace(), sshsig.hash_alg(), payload.as_bytes()).unwrap();

    let A_bytes: &[u8; 32] = sshsig.public_key().ed25519().unwrap().as_ref();
    let sig: &[u8; 64] = sshsig.signature().as_bytes().try_into().unwrap();

    let input = EdDSAInput::from_bytes(sig, A_bytes, msg);

    let path = "configs/ed25519/eddsa_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    base_test()
        .k(params.degree)
        .lookup_bits(params.lookup_bits)
        .unusable_rows(20)
        .bench_builder(input, input, |pool, range, input| {
            eddsa_test(pool.main(), range, params, input);
        });
}

#[test]
fn bench_ed25519_eddsa() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = "configs/ed25519/bench_eddsa.config";
    let bench_params_file =
        File::open(config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/ed25519").unwrap();
    fs::create_dir_all("data").unwrap();
    let results_path = "results/ed25519/eddsa_bench.csv";
    let mut fs_results = File::create(results_path).unwrap();
    writeln!(fs_results, "degree,num_advice,num_lookup,num_fixed,lookup_bits,limb_bits,num_limbs,proof_time,proof_size,verify_time")?;

    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: CircuitParams = serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        println!("---------------------- degree = {k} ------------------------------",);

        let stats = base_test()
            .k(k)
            .lookup_bits(bench_params.lookup_bits)
            .unusable_rows(20)
            .bench_builder(
                random_eddsa_input(),
                random_eddsa_input(),
                |pool, range, input| {
                    eddsa_test(pool.main(), range, bench_params, input);
                },
            );

        writeln!(
            fs_results,
            "{},{},{},{},{},{},{},{:?},{},{:?}",
            bench_params.degree,
            bench_params.num_advice,
            bench_params.num_lookup_advice,
            bench_params.num_fixed,
            bench_params.lookup_bits,
            bench_params.limb_bits,
            bench_params.num_limbs,
            stats.proof_time.time.elapsed(),
            stats.proof_size,
            stats.verify_time.time.elapsed()
        )?;
    }
    Ok(())
}
