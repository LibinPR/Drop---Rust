use ed25519_dalek::{
    Signature,
    Signer,
    SigningKey,
    Verifier,
    VerifyingKey,
};
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use std::net::TcpListener;
use std::thread;

use crate::protocol::{
    receive_message,
    send_message,
};
use crate::trusted;

const PAIRING_PORT: u16 = 9002;

const MESSAGE_PAIR_REQUEST: u8 = 1;
const MESSAGE_PC_PUBLIC_KEY: u8 = 2;
const MESSAGE_PC_CHALLENGE: u8 = 3;
const MESSAGE_PC_SIGNATURE: u8 = 4;
const MESSAGE_PHONE_PUBLIC_KEY: u8 = 5;
const MESSAGE_PHONE_CHALLENGE: u8 = 6;
const MESSAGE_PHONE_SIGNATURE: u8 = 7;
const MESSAGE_TRUSTED: u8 = 8;
const MESSAGE_REJECTED: u8 = 9;

pub fn generate_pairing_code() -> String {
    let mut rng = rand::thread_rng();

    let code: u32 =
        rng.gen_range(100000..1000000);

    format!("{:06}", code)
}

pub fn run_server(
    pairing_code: String,
    signing_key: SigningKey,
) {
    let listener =
        TcpListener::bind(
            ("0.0.0.0", PAIRING_PORT),
        )
        .unwrap();

    println!(
        "Pairing server listening on TCP port {}",
        PAIRING_PORT
    );

    println!(
        "Pairing code: {}",
        pairing_code
    );

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,

            Err(error) => {
                println!(
                    "Pairing connection failed: {}",
                    error
                );

                continue;
            }
        };

        let expected_code =
            pairing_code.clone();

        let signing_key =
            signing_key.clone();

        thread::spawn(move || {
            handle_pairing(
                stream,
                expected_code,
                signing_key,
            );
        });
    }
}

fn handle_pairing(
    mut stream: std::net::TcpStream,
    expected_code: String,
    signing_key: SigningKey,
) {
    /*
     * --------------------------------------------------
     * 1. Receive pairing request
     * --------------------------------------------------
     */

    let (
        message_type,
        payload,
    ) = match receive_message(&mut stream) {
        Ok(message) => message,

        Err(error) => {
            println!(
                "Failed to receive pairing request: {}",
                error
            );

            return;
        }
    };

    if message_type != MESSAGE_PAIR_REQUEST {
        println!(
            "Invalid pairing message type."
        );

        let _ = send_message(
            &mut stream,
            MESSAGE_REJECTED,
            b"Invalid pairing request",
        );

        return;
    }

    let request =
        String::from_utf8_lossy(
            &payload,
        );

    let parts: Vec<&str> =
        request.split('|').collect();

    if parts.len() != 2 {
        println!(
            "Invalid pairing request format."
        );

        let _ = send_message(
            &mut stream,
            MESSAGE_REJECTED,
            b"Invalid pairing request",
        );

        return;
    }

    let device_id =
        parts[0];

    let received_code =
        parts[1];

    println!(
        "Device ID: {}",
        device_id
    );

    println!(
        "Pairing code: {}",
        received_code
    );

    if received_code != expected_code {
        println!(
            "Pairing rejected."
        );

        let _ = send_message(
            &mut stream,
            MESSAGE_REJECTED,
            b"Wrong pairing code",
        );

        return;
    }

    println!(
        "Pairing code accepted."
    );

    /*
     * --------------------------------------------------
     * 2. Send PC public key
     * --------------------------------------------------
     */

    let pc_public_key =
        signing_key
            .verifying_key()
            .to_bytes();

    if send_message(
        &mut stream,
        MESSAGE_PC_PUBLIC_KEY,
        &pc_public_key,
    )
    .is_err()
    {
        println!(
            "Failed to send PC public key."
        );

        return;
    }

    println!(
        "Public key sent."
    );

    /*
     * --------------------------------------------------
     * 3. Generate random PC challenge
     * --------------------------------------------------
     */

    let mut pc_challenge =
        [0u8; 32];

    let mut rng = OsRng;

    rng.fill_bytes(
        &mut pc_challenge,
    );

    /*
     * --------------------------------------------------
     * 4. Send PC challenge
     * --------------------------------------------------
     */

    if send_message(
        &mut stream,
        MESSAGE_PC_CHALLENGE,
        &pc_challenge,
    )
    .is_err()
    {
        println!(
            "Failed to send PC challenge."
        );

        return;
    }

    /*
     * --------------------------------------------------
     * 5. Sign PC challenge
     * --------------------------------------------------
     */

    let pc_signature =
        signing_key.sign(
            &pc_challenge,
        );

    if send_message(
        &mut stream,
        MESSAGE_PC_SIGNATURE,
        pc_signature
            .to_bytes()
            .as_ref(),
    )
    .is_err()
    {
        println!(
            "Failed to send PC signature."
        );

        return;
    }

    println!(
        "PC random challenge signed and sent."
    );

    /*
     * --------------------------------------------------
     * 6. Receive phone public key
     * --------------------------------------------------
     */

    let (
        message_type,
        phone_public_key,
    ) = match receive_message(
        &mut stream,
    ) {
        Ok(message) => message,

        Err(error) => {
            println!(
                "Failed to receive phone public key: {}",
                error
            );

            return;
        }
    };

    if message_type != MESSAGE_PHONE_PUBLIC_KEY
        || phone_public_key.len() != 32
    {
        println!(
            "Invalid phone public key."
        );

        return;
    }

    println!(
        "Phone public key received."
    );

    /*
     * --------------------------------------------------
     * 7. Verify phone device ID
     * --------------------------------------------------
     */

    let calculated_device_id =
        phone_public_key
            .iter()
            .map(
                |byte| format!("{:02x}", byte),
            )
            .collect::<String>();

    if calculated_device_id != device_id {
        println!(
            "Phone device ID does not match public key."
        );

        let _ = send_message(
            &mut stream,
            MESSAGE_REJECTED,
            b"Device ID mismatch",
        );

        return;
    }

    let phone_public_key_array:
        [u8; 32] =
        match phone_public_key
            .as_slice()
            .try_into()
        {
            Ok(bytes) => bytes,

            Err(_) => {
                return;
            }
        };

    let phone_verifying_key =
        match VerifyingKey::from_bytes(
            &phone_public_key_array,
        ) {
            Ok(key) => key,

            Err(error) => {
                println!(
                    "Invalid phone public key: {}",
                    error
                );

                return;
            }
        };

    /*
     * --------------------------------------------------
     * 8. Generate phone challenge
     * --------------------------------------------------
     */

    let mut phone_challenge =
        [0u8; 32];

    rng.fill_bytes(
        &mut phone_challenge,
    );

    /*
     * --------------------------------------------------
     * 9. Send phone challenge
     * --------------------------------------------------
     */

    if send_message(
        &mut stream,
        MESSAGE_PHONE_CHALLENGE,
        &phone_challenge,
    )
    .is_err()
    {
        println!(
            "Failed to send phone challenge."
        );

        return;
    }

    println!(
        "Phone random challenge sent."
    );

    /*
     * --------------------------------------------------
     * 10. Receive phone signature
     * --------------------------------------------------
     */

    let (
        message_type,
        phone_signature,
    ) = match receive_message(
        &mut stream,
    ) {
        Ok(message) => message,

        Err(error) => {
            println!(
                "Failed to receive phone signature: {}",
                error
            );

            return;
        }
    };

    if message_type != MESSAGE_PHONE_SIGNATURE
        || phone_signature.len() != 64
    {
        println!(
            "Invalid phone signature."
        );

        return;
    }

    let phone_signature_array:
        [u8; 64] =
        match phone_signature
            .as_slice()
            .try_into()
        {
            Ok(bytes) => bytes,

            Err(_) => {
                return;
            }
        };

    let phone_signature =
        Signature::from_bytes(
            &phone_signature_array,
        );

    /*
     * --------------------------------------------------
     * 11. Verify phone signature
     * --------------------------------------------------
     */

    if phone_verifying_key
        .verify(
            &phone_challenge,
            &phone_signature,
        )
        .is_err()
    {
        println!(
            "Phone cryptographic proof FAILED."
        );

        let _ = send_message(
            &mut stream,
            MESSAGE_REJECTED,
            b"Phone verification failed",
        );

        return;
    }

    println!(
        "Phone cryptographic proof verified."
    );

    /*
     * --------------------------------------------------
     * 12. Trust device
     * --------------------------------------------------
     */

    trusted::add_trusted_device(
        device_id,
    );

    send_message(
        &mut stream,
        MESSAGE_TRUSTED,
        b"Pairing completed",
    )
    .ok();

    println!(
        "Mutual authentication successful."
    );

    println!(
        "Pairing completed successfully."
    );
}