#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use ciborium::de::from_reader;
use linked_list_allocator::LockedHeap;
use risc0_groth16::{ProofJson, PublicInputsJson, Verifier, VerifyingKeyJson};
use riscv_rt::entry;

mod cmio;
mod panic_handler;
mod utils;

use crate::cmio::{CMIODriver, HTIF_DEVICE_YIELD, HTIF_YIELD_CMD_MANUAL, pack_yield, sbi_yield};

const HEAP_START: usize = 0x8100_0000;
const HEAP_SIZE: usize = 512 * 1024;

const PERMISSION_GRANTED_TRUE: &str = r#"{"Exit": {"code": 0}}"#;
const PERMISSION_GRANTED_FALSE: &str = r#"{"Exit": {"code": 1}}"#;
const READ_EXTRA_DATA: &str = r#"{"ReadExtraData": {}}"#;
const QUERY_COMMAND_TYPE: &str = r#"{"QueryCommandType": {}}"#;

const VERIFYING_KEY_INDEX: usize = 0;
const PROOF_INDEX: usize = 1;
const PUBLIC_INPUTS_INDEX: usize = 2;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

fn verify_proof(
    verifying_key: VerifyingKeyJson,
    proof: ProofJson,
    public_inputs: PublicInputsJson,
) -> Result<(), anyhow::Error> {
    let verifier = Verifier::from_json(proof, public_inputs, verifying_key)?;
    verifier.verify()
}

fn send_message_and_yield(device: &CMIODriver, message: &str) -> Result<usize, anyhow::Error> {
    let bytes_written = device.tx_write(message.as_bytes());
    let yield_request = pack_yield(
        HTIF_DEVICE_YIELD,
        HTIF_YIELD_CMD_MANUAL,
        0,
        bytes_written as u32,
    );
    Ok(sbi_yield(yield_request))
}

fn send_message_and_read_response(
    device: &CMIODriver,
    message: &str,
) -> Result<Vec<u8>, anyhow::Error> {
    let bytes_written = device.tx_write(message.as_bytes());
    let yield_request = pack_yield(
        HTIF_DEVICE_YIELD,
        HTIF_YIELD_CMD_MANUAL,
        0,
        bytes_written as u32,
    );
    let response_length = sbi_yield(yield_request);
    Ok(device.rx_read(response_length))
}

#[entry]
fn main() -> ! {
    unsafe {
        ALLOCATOR.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }

    let device = CMIODriver::new();

    let command_type = get_current_command_type(&device);

    match command_type.as_str() {
        "LockIntentForSolving" | "CancelIntent" | "CancelIntentLock" => {
            send_message_and_yield(&device, PERMISSION_GRANTED_TRUE).unwrap();
        }
        "SolveIntent" => {
            let extra_data_response = match send_message_and_read_response(&device, READ_EXTRA_DATA)
            {
                Ok(response) => response,
                Err(e) => {
                    println!("Failed to read extra data: {:?}", e);
                    utils::shutdown();
                }
            };

            let blob_hashes = parse_blob_hashes_from_response(&extra_data_response);

            let verifying_key_json = read_blob_by_hash(&device, &blob_hashes[VERIFYING_KEY_INDEX]);
            let proof_json = read_blob_by_hash(&device, &blob_hashes[PROOF_INDEX]);
            let public_inputs_json = read_blob_by_hash(&device, &blob_hashes[PUBLIC_INPUTS_INDEX]);

            let verifying_key: VerifyingKeyJson = serde_json::from_str(&verifying_key_json)
                .expect("Failed to parse verifying key JSON");
            let proof: ProofJson =
                serde_json::from_str(&proof_json).expect("Failed to parse proof JSON");
            let public_values: Vec<String> = serde_json::from_str(&public_inputs_json)
                .expect("Failed to parse public inputs JSON");
            let public_inputs = PublicInputsJson {
                values: public_values,
            };

            if let Err(e) = verify_proof(verifying_key, proof, public_inputs) {
                println!("Proof verification failed: {:?}", e);
                send_message_and_yield(&device, PERMISSION_GRANTED_FALSE).unwrap();
                utils::shutdown();
            }

            send_message_and_yield(&device, PERMISSION_GRANTED_TRUE).unwrap();
        }
        _ => {
            send_message_and_yield(&device, PERMISSION_GRANTED_FALSE).unwrap();
        }
    }
    utils::shutdown();
}

fn parse_blob_hashes_from_response(response: &[u8]) -> Vec<String> {
    let json_value: serde_json::Value =
        serde_json::from_slice(response).expect("Failed to parse extra data response JSON");

    let extra_data_array = &json_value["ExtraDataResponse"]["extra_data"];
    let cbor_bytes: Vec<u8> = extra_data_array
        .as_array()
        .expect("Extra data is not an array")
        .iter()
        .map(|v| v.as_u64().expect("Invalid array element") as u8)
        .collect();

    from_reader(cbor_bytes.as_slice()).expect("Failed to decode CBOR blob hashes")
}

fn get_current_command_type(device: &CMIODriver) -> String {
    let response = send_message_and_read_response(device, QUERY_COMMAND_TYPE)
        .expect("Failed to query command type");

    println!("get_current_command_type response: {:?}", response);

    let json_value: serde_json::Value =
        serde_json::from_slice(&response).expect("Failed to parse command type response");

    json_value["CommandTypeResponse"]["command_type"]
        .as_str()
        .unwrap_or("Unknown")
        .to_string()
}

fn read_blob_by_hash(device: &CMIODriver, hash_hex: &str) -> String {
    let message = alloc::format!(r#"{{"ReadBlob": {{"blob_hash_hex": "{}"}}}}"#, hash_hex);
    let response = send_message_and_read_response(device, &message).expect("Failed to read blob");

    let json_value: serde_json::Value =
        serde_json::from_slice(&response).expect("Failed to parse blob response");

    let data_hex = json_value["BlobResponse"]["data_hex"]
        .as_str()
        .expect("Missing data_hex field")
        .trim_start_matches("0x");

    let bytes = hex::decode(data_hex).expect("Failed to decode hex data");

    String::from_utf8(bytes).expect("Invalid UTF-8 in blob data")
}
