use ed25519_dalek::{
    Signature,
    Signer,
    SigningKey,
    Verifier,
    VerifyingKey,
};
use rand::rngs::OsRng;
use std::fs;
use std::io;
use std::net::TcpStream;
use std::path::Path;

use drop::protocol::{
    receive_message,
    send_message,
};

const DEVICE_KEY_FILE: &str =
    "phone_device_key.bin";

const MESSAGE_PAIR_REQUEST: u8 = 1;
const MESSAGE_PC_PUBLIC_KEY: u8 = 2;
const MESSAGE_PC_CHALLENGE: u8 = 3;
const MESSAGE_PC_SIGNATURE: u8 = 4;
const MESSAGE_PHONE_PUBLIC_KEY: u8 = 5;
const MESSAGE_PHONE_CHALLENGE: u8 = 6;
const MESSAGE_PHONE_SIGNATURE: u8 = 7;
const MESSAGE_TRUSTED: u8 = 8;
const MESSAGE_REJECTED: u8 = 9;

fn main() {
    let signing_key =
        load_or_create_device_key();

    let device_id =
        public_key_hex(&signing_key);

    println!(
        "Phone device ID: {}",
        device_id
    );

    println!(
        "Enter the PC pairing code:"
    );

    let mut code = String::new();

    io::stdin()
        .read_line(&mut code)
        .unwrap();

    let code = code.trim();

    println!(
        "Connecting to pairing service..."
    );

    let mut stream =
        match TcpStream::connect(
            "127.0.0.1:9002",
        ) {
            Ok(stream) => stream,

            Err(error) => {
                println!(
                    "Connection failed: {}",
                    error
                );

                return;
            }
        };

    /*
     * 1. Send pairing request.
     *
     * Payload:
     *
     * phone_device_id|pairing_code
     */
    let request =
        format!(
            "{}|{}",
            device_id,
            code
        );

    if let Err(error) =
        send_message(
            &mut stream,
            MESSAGE_PAIR_REQUEST,
            request.as_bytes(),
        )
    {
        println!(
            "Failed to send pairing request: {}",
            error
        );

        return;
    }

    /*
     * 2. Receive PC public key.
     */
    let (
        message_type,
        pc_public_key,
    ) = match receive_message(
        &mut stream,
    ) {
        Ok(message) => message,

        Err(error) => {
            println!(
                "Failed to receive PC public key: {}",
                error
            );

            return;
        }
    };

    if message_type == MESSAGE_REJECTED {
        println!(
            "PC rejected pairing: {}",
            String::from_utf8_lossy(
                &pc_public_key,
            )
        );

        return;
    }

    if message_type != MESSAGE_PC_PUBLIC_KEY
        || pc_public_key.len() != 32
    {
        println!(
            "Invalid PC public key."
        );

        return;
    }

    let pc_public_key_array:
        [u8; 32] =
        match pc_public_key
            .as_slice()
            .try_into()
        {
            Ok(bytes) => bytes,

            Err(_) => {
                println!(
                    "Invalid PC public key size."
                );

                return;
            }
        };

    let pc_verifying_key =
        match VerifyingKey::from_bytes(
            &pc_public_key_array,
        ) {
            Ok(key) => key,

            Err(error) => {
                println!(
                    "Invalid PC public key: {}",
                    error
                );

                return;
            }
        };

    println!(
        "Received PC public key."
    );

    /*
     * 3. Receive random PC challenge.
     */
    let (
        message_type,
        pc_challenge,
    ) = match receive_message(
        &mut stream,
    ) {
        Ok(message) => message,

        Err(error) => {
            println!(
                "Failed to receive PC challenge: {}",
                error
            );

            return;
        }
    };

    if message_type != MESSAGE_PC_CHALLENGE
        || pc_challenge.len() != 32
    {
        println!(
            "Invalid PC challenge."
        );

        return;
    }

    println!(
        "Received PC random challenge."
    );

    /*
     * 4. Receive PC signature.
     */
    let (
        message_type,
        pc_signature,
    ) = match receive_message(
        &mut stream,
    ) {
        Ok(message) => message,

        Err(error) => {
            println!(
                "Failed to receive PC signature: {}",
                error
            );

            return;
        }
    };

    if message_type != MESSAGE_PC_SIGNATURE
        || pc_signature.len() != 64
    {
        println!(
            "Invalid PC signature."
        );

        return;
    }

    let pc_signature_array:
        [u8; 64] =
        match pc_signature
            .as_slice()
            .try_into()
        {
            Ok(bytes) => bytes,

            Err(_) => {
                println!(
                    "Invalid PC signature size."
                );

                return;
            }
        };

    let pc_signature =
        Signature::from_bytes(
            &pc_signature_array,
        );

    /*
     * 5. Verify that the PC signed
     *    the exact random challenge.
     */
    if pc_verifying_key
        .verify(
            &pc_challenge,
            &pc_signature,
        )
        .is_err()
    {
        println!(
            "PC cryptographic proof FAILED."
        );

        return;
    }

    println!(
        "PC random challenge verified!"
    );

    /*
     * 6. Send phone public key.
     */
    if let Err(error) =
        send_message(
            &mut stream,
            MESSAGE_PHONE_PUBLIC_KEY,
            signing_key
                .verifying_key()
                .as_bytes(),
        )
    {
        println!(
            "Failed to send phone public key: {}",
            error
        );

        return;
    }

    println!(
        "Phone public key sent."
    );

    /*
     * 7. Receive random phone challenge.
     */
    let (
        message_type,
        phone_challenge,
    ) = match receive_message(
        &mut stream,
    ) {
        Ok(message) => message,

        Err(error) => {
            println!(
                "Failed to receive phone challenge: {}",
                error
            );

            return;
        }
    };

    if message_type != MESSAGE_PHONE_CHALLENGE
        || phone_challenge.len() != 32
    {
        println!(
            "Invalid phone challenge."
        );

        return;
    }

    println!(
        "Received phone random challenge."
    );

    /*
     * 8. Sign the phone challenge.
     */
    let phone_signature =
        signing_key.sign(
            &phone_challenge,
        );

    if let Err(error) =
        send_message(
            &mut stream,
            MESSAGE_PHONE_SIGNATURE,
            phone_signature
                .to_bytes()
                .as_ref(),
        )
    {
        println!(
            "Failed to send phone signature: {}",
            error
        );

        return;
    }

    println!(
        "Phone random challenge signed and sent."
    );

    /*
     * 9. Receive final trust confirmation.
     */
    let (
        message_type,
        payload,
    ) = match receive_message(
        &mut stream,
    ) {
        Ok(message) => message,

        Err(error) => {
            println!(
                "Failed to receive final confirmation: {}",
                error
            );

            return;
        }
    };

    if message_type == MESSAGE_TRUSTED {
        println!(
            "PC verified the phone identity."
        );

        println!(
            "Mutual authentication successful!"
        );

        println!(
            "Pairing completed successfully!"
        );
    } else {
        println!(
            "PC did not trust the phone: {}",
            String::from_utf8_lossy(
                &payload,
            )
        );
    }
}

fn load_or_create_device_key()
    -> SigningKey
{
    if Path::new(DEVICE_KEY_FILE).exists() {
        println!(
            "Loading existing phone device key."
        );

        let key_bytes =
            fs::read(
                DEVICE_KEY_FILE,
            )
            .expect(
                "Failed to read phone device key",
            );

        let key_array: [u8; 32] =
            key_bytes
                .try_into()
                .expect(
                    "Phone device key must contain exactly 32 bytes",
                );

        return SigningKey::from_bytes(
            &key_array,
        );
    }

    println!(
        "Creating new phone device key."
    );

    let mut rng = OsRng;

    let signing_key =
        SigningKey::generate(
            &mut rng,
        );

    fs::write(
        DEVICE_KEY_FILE,
        signing_key.to_bytes(),
    )
    .expect(
        "Failed to save phone device key",
    );

    signing_key
}

fn public_key_hex(
    signing_key: &SigningKey,
) -> String {
    signing_key
        .verifying_key()
        .as_bytes()
        .iter()
        .map(
            |byte| format!("{:02x}", byte),
        )
        .collect()
}