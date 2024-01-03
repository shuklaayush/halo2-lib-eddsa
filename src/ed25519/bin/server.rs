#![allow(non_snake_case)]
#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use]
extern crate rocket;

use ark_std::{end_timer, start_timer};
use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use halo2_base::gates::circuit::builder::RangeCircuitBuilder;
use halo2_base::gates::circuit::{BaseCircuitParams, CircuitBuilderStage};
use halo2_base::gates::flex_gate::MultiPhaseThreadBreakPoints;
use halo2_base::gates::RangeChip;
use halo2_base::halo2_proofs::plonk::{keygen_pk, keygen_vk, ProvingKey};
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    SerdeFormat,
};
use halo2_base::utils::fs::gen_srs;
use halo2_base::utils::testing::{check_proof, gen_proof};
use serde::{Deserialize, Serialize};
use ssh_key::SshSig;
use std::fs::File;
use std::path::PathBuf;

use rocket::http::Method;
use rocket_contrib::json::Json;
use rocket_cors::{AllowedHeaders, AllowedOrigins, Cors, CorsOptions};

use halo2_lib_eddsa::ed25519::utils::{eddsa_circuit, CircuitParams, EdDSAInput};

struct ServerState {
    circuit_params: CircuitParams,
    config_params: BaseCircuitParams,
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
    let config_params = state.config_params.clone();
    let break_points = &state.break_points;
    let srs_params = &state.srs_params;
    let pk = &state.pk;

    let task = task.into_inner();
    let sshsig = task.ssh_sig.parse::<SshSig>().unwrap();
    println!("ssh_sig: {:?}", sshsig);

    let msg: &[u8] = &SshSig::signed_data(
        sshsig.namespace(),
        sshsig.hash_alg(),
        task.raw_msg.as_bytes(),
    )
    .unwrap();

    let A_bytes: &[u8; 32] = sshsig.public_key().ed25519().unwrap().as_ref();
    let sig: &[u8; 64] = sshsig.signature().as_bytes().try_into().unwrap();

    let input = EdDSAInput::from_bytes(sig, A_bytes, msg);

    // create real proof
    let proof_time = start_timer!(|| "Proving time");
    let mut builder = RangeCircuitBuilder::prover(config_params.clone(), break_points.clone());
    let range = RangeChip::new(circuit_params.lookup_bits, builder.lookup_manager().clone());
    eddsa_circuit(builder.pool(0).main(), &range, circuit_params, input);
    let proof = gen_proof(&srs_params, &pk, builder);
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
    check_proof(&srs_params, pk.get_vk(), &proof, true);
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

    let input = EdDSAInput::from_bytes(&[0u8; 64], &[0u8; 32], &[0u8]);

    let mut builder = RangeCircuitBuilder::from_stage(CircuitBuilderStage::Keygen)
        .use_k(circuit_params.degree as usize);
    builder.set_lookup_bits(circuit_params.lookup_bits);
    let range = RangeChip::new(circuit_params.lookup_bits, builder.lookup_manager().clone());
    eddsa_circuit(builder.pool(0).main(), &range, circuit_params, input);

    // configure the circuit shape, 9 blinding rows seems enough
    let config_params = builder.calculate_params(None);

    let srs_params = gen_srs(circuit_params.degree);
    let vk_time = start_timer!(|| "Generating vkey");
    let vk = keygen_vk(&srs_params, &builder).unwrap();
    end_timer!(vk_time);
    let pk_time = start_timer!(|| "Generating pkey");
    let pk = keygen_pk(&srs_params, vk, &builder).unwrap();
    end_timer!(pk_time);

    let break_points = builder.break_points();
    drop(builder);

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
        config_params,
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
