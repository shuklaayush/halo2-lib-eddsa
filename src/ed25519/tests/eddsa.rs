#![allow(non_snake_case)]
use ark_std::{end_timer, start_timer};
use halo2_base::halo2_proofs::{
    halo2curves::ff::FromUniformBytes,
    poly::kzg::{
        commitment::KZGCommitmentScheme,
        multiopen::{ProverSHPLONK, VerifierSHPLONK},
        strategy::SingleStrategy,
    },
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use halo2_base::utils::fs::gen_srs;
use halo2_base::{
    gates::{
        circuit::{builder::BaseCircuitBuilder, CircuitBuilderStage},
        flex_gate::MultiPhaseThreadBreakPoints,
    },
    halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        halo2curves::ed25519::{Ed25519Affine, Fr as Fq},
        plonk::*,
        poly::commitment::ParamsProver,
        transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    },
};
use rand::RngCore;
use rand_core::OsRng;
use sha2::{Digest, Sha512};
use std::fs::File;
use std::io::BufReader;
use std::io::Write;
use std::{fs, io::BufRead};

use super::super::utils::{eddsa_circuit, CircuitParams};

fn hash_to_fe(hash: Sha512) -> Fq {
    let output: [u8; 64] = hash.finalize().as_slice().try_into().unwrap();
    Fq::from_uniform_bytes(&output)
}

fn random_eddsa_circuit(
    params: CircuitParams,
    stage: CircuitBuilderStage,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> BaseCircuitBuilder<Fr> {
    // TODO: generate eddsa sig and verify in circuit
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
        let A = Ed25519Affine::from(Ed25519Affine::generator() * &s);
        let A_bytes = A.to_bytes();

        (s, prefix, A_bytes)
    }

    fn sign(s: Fq, prefix: [u8; 32], A_bytes: [u8; 32], msg: &[u8]) -> [u8; 64] {
        let r = hash_to_fe(Sha512::default().chain(&prefix[..]).chain(msg));

        let R_bytes = Ed25519Affine::from(Ed25519Affine::generator() * &r).to_bytes();

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

    // Generate a key pair
    let mut seed = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut seed[..]);

    let (s, prefix, A_bytes) = seed_to_key(seed);

    // Generate a valid signature
    let msg = b"test message";
    let sig = sign(s, prefix, A_bytes, msg);

    eddsa_circuit(params, stage, break_points, &sig, &A_bytes, msg)
}

#[test]
fn test_ed25519_eddsa() {
    let path = "configs/ed25519/eddsa_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let circuit = random_eddsa_circuit(params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![])
        .unwrap()
        .assert_satisfied();
}

#[cfg(feature = "dev-graph")]
#[test]
fn test_ed25519_eddsa_plot() {
    use plotters::prelude::*;

    let root = BitMapBackend::new("layout.png", (1920, 1080)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root.titled("Ed25519 Layout", ("sans-serif", 60)).unwrap();

    let path = "configs/ed25519/eddsa_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let circuit = random_eddsa_circuit(params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![])
        .unwrap()
        .assert_satisfied();

    halo2_base::halo2_proofs::dev::CircuitLayout::default()
        .render(params.degree as u32, &circuit, &root)
        .unwrap();
}

#[test]
fn test_ssh_ed25519() {
    use ssh_key::SshSig;

    let path = "configs/ed25519/eddsa_circuit.config";
    let circuit_params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let ed25519_sig = "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg2jSEHYIEAcIfwZ2P9gnNUL7L1g\nqjkP1XG35XMGVvT+8AAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5\nAAAAQGOlq7vRfb6sd2m1V+lQEKj1/IKwck8p+Xcuu5/j4pZEDLICcEWcbKSz76XrddeUnY\nCvY/+F+UevG1iOUleRXww=\n-----END SSH SIGNATURE-----";
    let payload = "tree cb00595c68ae966d5a0319f44a07aae75e17118f\nparent bb588e3edd556583426e7f47856ca70a130f3b09\nauthor Ayush Shukla <shuklaayush247@gmail.com> 1686598553 +0200\ncommitter Ayush Shukla <shuklaayush247@gmail.com> 1686598626 +0200\n\nfix: produce concatenated signature\n";

    let sshsig = ed25519_sig.parse::<SshSig>().unwrap();
    let msg: &[u8] =
        &SshSig::signed_data(sshsig.namespace(), sshsig.hash_alg(), payload.as_bytes()).unwrap();

    let A_bytes: &[u8; 32] = sshsig.public_key().ed25519().unwrap().as_ref();
    let sig: &[u8; 64] = sshsig.signature().as_bytes().try_into().unwrap();

    // let circuit = eddsa_circuit(circuit_params, CircuitBuilderStage::Mock, None, &sig, &A_bytes, msg);
    // MockProver::run(circuit_params.degree, &circuit, vec![])
    //     .unwrap()
    //     .assert_satisfied();

    let k = circuit_params.degree;
    let srs_params = gen_srs(k);
    let mut rng = OsRng;

    let circuit = eddsa_circuit(
        circuit_params,
        CircuitBuilderStage::Keygen,
        None,
        &sig,
        &A_bytes,
        msg,
    );

    let vk_time = start_timer!(|| "Generating vkey");
    let vk = keygen_vk(&srs_params, &circuit).unwrap();
    end_timer!(vk_time);

    let pk_time = start_timer!(|| "Generating pkey");
    let pk = keygen_pk(&srs_params, vk, &circuit).unwrap();
    end_timer!(pk_time);

    let break_points = circuit.break_points();
    drop(circuit);
    // create a proof
    let proof_time = start_timer!(|| "Proving time");
    let circuit = eddsa_circuit(
        circuit_params,
        CircuitBuilderStage::Prover,
        Some(break_points),
        &sig,
        &A_bytes,
        msg,
    );
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        _,
    >(
        &srs_params,
        &pk,
        &[circuit],
        &[&[]],
        &mut rng,
        &mut transcript,
    )
    .unwrap();
    let proof = transcript.finalize();
    end_timer!(proof_time);

    let proof_size = proof.len();

    let verify_time = start_timer!(|| "Verify time");
    let verifier_params = srs_params.verifier_params();
    let strategy = SingleStrategy::new(&srs_params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(
        verifier_params,
        pk.get_vk(),
        strategy,
        &[&[]],
        &mut transcript,
    )
    .unwrap();
    end_timer!(verify_time);

    println!("\nCircuit Parameters:");
    println!("  Degree                   : {}", circuit_params.degree);
    println!("  Number of advice columns : {}", circuit_params.num_advice);
    println!(
        "  Number of lookup columns : {}",
        circuit_params.num_lookup_advice
    );
    println!("  Number of fixed columns  : {}", circuit_params.num_fixed);
    println!(
        "  Lookup bits              : {}",
        circuit_params.lookup_bits
    );
    println!("  Limb bits                : {}", circuit_params.limb_bits);
    println!("  Number of limbs          : {}", circuit_params.num_limbs);

    println!("\nBenchmarks:");
    println!(
        "  Proving time             : {:?}",
        proof_time.time.elapsed()
    );
    println!("  Proof size               : {} bytes", proof_size);
    println!(
        "  Verification time        : {:?}",
        verify_time.time.elapsed()
    );
}

#[test]
fn bench_ed25519_eddsa() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;
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

        let params = gen_srs(k);
        println!("{bench_params:?}");

        let circuit = random_eddsa_circuit(bench_params, CircuitBuilderStage::Keygen, None);

        let vk_time = start_timer!(|| "Generating vkey");
        let vk = keygen_vk(&params, &circuit)?;
        end_timer!(vk_time);

        let pk_time = start_timer!(|| "Generating pkey");
        let pk = keygen_pk(&params, vk, &circuit)?;
        end_timer!(pk_time);

        let break_points = circuit.break_points();
        drop(circuit);
        // create a proof
        let proof_time = start_timer!(|| "Proving time");
        let circuit = random_eddsa_circuit(
            bench_params,
            CircuitBuilderStage::Prover,
            Some(break_points),
        );
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            _,
        >(&params, &pk, &[circuit], &[&[]], &mut rng, &mut transcript)?;
        let proof = transcript.finalize();
        end_timer!(proof_time);

        let proof_size = {
            let path = format!(
                "data/eddsa_circuit_proof_{}_{}_{}_{}_{}_{}_{}.data",
                bench_params.degree,
                bench_params.num_advice,
                bench_params.num_lookup_advice,
                bench_params.num_fixed,
                bench_params.lookup_bits,
                bench_params.limb_bits,
                bench_params.num_limbs
            );
            let mut fd = File::create(&path)?;
            fd.write_all(&proof)?;
            let size = fd.metadata().unwrap().len();
            fs::remove_file(path)?;
            size
        };

        let verify_time = start_timer!(|| "Verify time");
        let verifier_params = params.verifier_params();
        let strategy = SingleStrategy::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(
            verifier_params,
            pk.get_vk(),
            strategy,
            &[&[]],
            &mut transcript,
        )
        .unwrap();
        end_timer!(verify_time);

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
            proof_time.time.elapsed(),
            proof_size,
            verify_time.time.elapsed()
        )?;
    }
    Ok(())
}
