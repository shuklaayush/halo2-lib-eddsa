#![allow(non_snake_case)]
#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use]
extern crate rocket;

use ark_std::{end_timer, start_timer};
use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use halo2_base::gates::builder::{CircuitBuilderStage, MultiPhaseThreadBreakPoints};
use halo2_base::halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey,
};
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    poly::commitment::ParamsProver,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    SerdeFormat,
};
use halo2_base::halo2_proofs::{
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::{ProverSHPLONK, VerifierSHPLONK},
        strategy::SingleStrategy,
    },
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use halo2_base::utils::fs::gen_srs;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use ssh_key::SshSig;
use std::fs::File;
use std::path::PathBuf;

use rocket::http::Method;
use rocket_contrib::json::Json;
use rocket_cors::{AllowedHeaders, AllowedOrigins, Cors, CorsOptions};

use halo2_lib_eddsa::ed25519::utils::{eddsa_circuit, CircuitParams};

struct ServerState {
    circuit_params: CircuitParams,
    break_points: MultiPhaseThreadBreakPoints,
    srs_params: ParamsKZG<Bn256>,
    pk: ProvingKey<G1Affine>,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct GenerateProofTask {
    pub ssh_sig: String,
    pub raw_msg: String,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifyProofTask {
    pub proof: String,
}

#[post("/generate-proof", format = "json", data = "<task>")]
fn serve_generate_proof(
    state: rocket::State<ServerState>,
    task: Json<GenerateProofTask>,
) -> Result<Json<String>, String> {
    let circuit_params = state.circuit_params;
    let break_points = &state.break_points;
    let srs_params = &state.srs_params;
    let pk = &state.pk;

    let task = task.into_inner();
    let sshsig = task.ssh_sig.parse::<SshSig>().unwrap();
    let msg: &[u8] = &SshSig::signed_data(
        sshsig.namespace(),
        sshsig.hash_alg(),
        task.raw_msg.as_bytes(),
    )
    .unwrap();

    let A_bytes: &[u8; 32] = sshsig.public_key().ed25519().unwrap().as_ref();
    let sig: &[u8; 64] = sshsig.signature().as_bytes().try_into().unwrap();

    // let circuit = eddsa_circuit(circuit_params, CircuitBuilderStage::Mock, None, &sig, &A_bytes, msg);
    // MockProver::run(circuit_params.degree, &circuit, vec![])
    //     .unwrap()
    //     .assert_satisfied();

    // create a proof
    let proof_time = start_timer!(|| "Proving time");
    let circuit = eddsa_circuit(
        circuit_params,
        CircuitBuilderStage::Prover,
        Some(break_points.clone()),
        &sig,
        &A_bytes,
        msg,
    );
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    let mut rng = OsRng;
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

    println!("\nBenchmarks:");
    println!(
        "  Proving time             : {:?}",
        proof_time.time.elapsed()
    );
    println!("  Proof size               : {} bytes", proof.len());

    Ok(Json(general_purpose::STANDARD.encode(&proof)))
}

#[post("/verify-proof", format = "json", data = "<task>")]
fn serve_verify_proof(
    state: rocket::State<ServerState>,
    task: Json<VerifyProofTask>,
) -> Result<Json<bool>, String> {
    let srs_params = &state.srs_params;
    let pk = &state.pk;

    let task = task.into_inner();
    let proof = general_purpose::STANDARD.decode(&task.proof).unwrap();

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

    println!("\nBenchmarks:");
    println!(
        "  Verification time        : {:?}",
        verify_time.time.elapsed()
    );

    Ok(Json(true))
}

fn make_cors() -> Cors {
    // let allowed_origins = AllowedOrigins::some_exact(&[
    //     "http://localhost:3000",
    // ]);
    let allowed_origins = AllowedOrigins::all();

    CorsOptions {
        allowed_origins,
        allowed_methods: vec![Method::Post].into_iter().map(From::from).collect(),
        allowed_headers: AllowedHeaders::some(&[
            "Authorization",
            "Accept",
            "Access-Control-Allow-Origin",
            "Content-Type",
        ]),
        allow_credentials: true,
        ..Default::default()
    }
    .to_cors()
    .unwrap()
}

#[derive(Parser, Debug)]
struct Cli {
    #[arg(short, long = "config-path")]
    config_path: Option<PathBuf>,
}

fn init_server_state(config_path: &PathBuf) -> ServerState {
    let circuit_params: CircuitParams = serde_json::from_reader(
        File::open(config_path).unwrap_or_else(|e| panic!("{config_path:?} does not exist: {e:?}")),
    )
    .unwrap();

    let k = circuit_params.degree;
    let srs_params = gen_srs(k);

    let circuit = eddsa_circuit(
        circuit_params,
        CircuitBuilderStage::Keygen,
        None,
        &[0u8; 64],
        &[0u8; 32],
        &[0u8],
    );

    let vk_time = start_timer!(|| "Generating vkey");
    let vk = keygen_vk(&srs_params, &circuit).unwrap();
    end_timer!(vk_time);

    let pk_time = start_timer!(|| "Generating pkey");
    let pk = keygen_pk(&srs_params, vk, &circuit).unwrap();
    end_timer!(pk_time);

    let break_points = circuit.0.break_points.take();
    drop(circuit);

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
    println!("  Vkey generation time     : {:?}", vk_time.time.elapsed());
    println!(
        "  Vkey size                : {} bytes",
        pk.get_vk().to_bytes(SerdeFormat::Processed).len()
    );
    println!("  Pkey generation time     : {:?}", pk_time.time.elapsed());
    println!(
        "  Pkey size                : {} bytes",
        pk.to_bytes(SerdeFormat::Processed).len()
    );

    ServerState {
        circuit_params,
        break_points,
        srs_params,
        pk,
    }
}

fn main() {
    let args = Cli::parse();
    let config_path = &args
        .config_path
        .unwrap_or_else(|| PathBuf::from("configs/ed25519/eddsa_circuit.config"));

    let server_state = init_server_state(config_path);

    rocket::ignite()
        .mount("/", routes![serve_generate_proof, serve_verify_proof])
        .attach(make_cors())
        .manage(server_state)
        .launch();
}
