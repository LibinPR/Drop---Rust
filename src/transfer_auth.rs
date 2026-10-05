use ed25519_dalek::{
    Signature,
    Signer,
    Verifier,
    SigningKey,
    VerifyingKey,
};
use rand::rngs::OsRng;
use rand::RngCore;
use std::io::{Read, Write};

use crate::trusted;

const AUTH_VERSION: u8 = 1;

const MESSAGE_TRANSFER_REQUEST: u8 = 1;
const MESSAGE_TRANSFER_CHALLENGE: u8 = 2;
const MESSAGE_TRANSFER_SIGNATURE: u8 = 3;
const MESSAGE_TRANSFER_ACCEPTED: u8 = 4;
const MESSAGE_TRANSFER_REJECTED: u8 = 5;

pub fn authenticate_client(
    stream: &mut std::net::TcpStream,
) -> bool {
    /*
     * Receive:
     *
     * [version]
     * [message type]
     * [device ID length]
     * [device ID]
     */

    let mut header = [0u8; 4];

      if stream
          .read_exact(&mut header)
          .is_err()
      {
          println!(
              "Failed to receive transfer authentication request."
          );

          return false;
      }

      if header[0] != AUTH_VERSION {
          println!(
              "Unsupported transfer authentication version."
          );

          return false;
      }

      if header[1] != MESSAGE_TRANSFER_REQUEST {
          println!(
              "Invalid transfer authentication message."
          );

          return false;
      }

      let device_id_length =
          u16::from_be_bytes([
              header[2],
              header[3],
          ]);

    let mut device_id_buffer =
        vec![0u8; device_id_length as usize];

    if stream
        .read_exact(&mut device_id_buffer)
        .is_err()
    {
        println!(
            "Failed to receive device ID."
        );

        return false;
    }

    let device_id =
        String::from_utf8_lossy(
            &device_id_buffer,
        );

    println!(
        "Transfer authentication request from {}",
        device_id
    );

    /*
     * The device must already be trusted.
     */
    if !trusted::is_trusted(&device_id) {
        println!(
            "Transfer rejected: device is not trusted."
        );

        let _ =
            stream.write_all(&[
                AUTH_VERSION,
                MESSAGE_TRANSFER_REJECTED,
            ]);

        return false;
    }

    /*
     * Convert the device ID back into
     * the public key.
     */
    let public_key_bytes =
        match hex_to_bytes(&device_id) {
            Some(bytes) => bytes,

            None => {
                println!(
                    "Transfer rejected: invalid device ID."
                );

                return false;
            }
        };

    if public_key_bytes.len() != 32 {
        println!(
            "Transfer rejected: invalid public key length."
        );

        return false;
    }

    let public_key_array:
        [u8; 32] =
        match public_key_bytes
            .try_into()
        {
            Ok(bytes) => bytes,

            Err(_) => {
                return false;
            }
        };

    let verifying_key =
        match VerifyingKey::from_bytes(
            &public_key_array,
        ) {
            Ok(key) => key,

            Err(_) => {
                println!(
                    "Transfer rejected: invalid public key."
                );

                return false;
            }
        };

    /*
     * Generate a fresh challenge.
     */
    let mut challenge =
        [0u8; 32];

    let mut rng = OsRng;

    rng.fill_bytes(
        &mut challenge,
    );

    /*
     * Send challenge.
     */
    if stream
        .write_all(&[
            AUTH_VERSION,
            MESSAGE_TRANSFER_CHALLENGE,
        ])
        .is_err()
    {
        return false;
    }

    if stream
        .write_all(&challenge)
        .is_err()
    {
        return false;
    }

    /*
     * Receive signature.
     */
    let mut signature_header =
        [0u8; 2];

    if stream
        .read_exact(&mut signature_header)
        .is_err()
    {
        println!(
            "Failed to receive transfer signature."
        );

        return false;
    }

    if signature_header[0] != AUTH_VERSION
        || signature_header[1]
            != MESSAGE_TRANSFER_SIGNATURE
    {
        println!(
            "Invalid transfer signature message."
        );

        return false;
    }

    let mut signature_bytes =
        [0u8; 64];

    if stream
        .read_exact(&mut signature_bytes)
        .is_err()
    {
        println!(
            "Failed to receive transfer signature."
        );

        return false;
    }

    let signature =
        Signature::from_bytes(
            &signature_bytes,
        );

    /*
     * Verify signature.
     */
    if verifying_key
        .verify(
            &challenge,
            &signature,
        )
        .is_err()
    {
        println!(
            "Transfer authentication FAILED."
        );

        let _ =
            stream.write_all(&[
                AUTH_VERSION,
                MESSAGE_TRANSFER_REJECTED,
            ]);

        return false;
    }

    /*
     * Authentication succeeded.
     */
    println!(
        "Transfer authentication successful."
    );

    if stream
        .write_all(&[
            AUTH_VERSION,
            MESSAGE_TRANSFER_ACCEPTED,
        ])
        .is_err()
    {
        return false;
    }

    true
}

pub fn send_authentication_request(
    stream: &mut std::net::TcpStream,
    signing_key: &SigningKey,
) -> bool {
    let device_id =
        signing_key
            .verifying_key()
            .as_bytes()
            .iter()
            .map(
                |byte| format!("{:02x}", byte),
            )
            .collect::<String>();

    let device_id_bytes =
        device_id.as_bytes();

    if device_id_bytes.len()
        > u16::MAX as usize
    {
        return false;
    }

    /*
     * Send:
     *
     * [version]
     * [request type]
     * [device ID length: 2 bytes]
     * [device ID]
     */
    if stream
        .write_all(&[
            AUTH_VERSION,
            MESSAGE_TRANSFER_REQUEST,
        ])
        .is_err()
    {
        return false;
    }

    let length =
        device_id_bytes.len() as u16;

    if stream
        .write_all(
            &length.to_be_bytes(),
        )
        .is_err()
    {
        return false;
    }

    if stream
        .write_all(device_id_bytes)
        .is_err()
    {
        return false;
    }

    /*
     * Receive challenge.
     */
    let mut challenge_header =
        [0u8; 2];

    if stream
        .read_exact(&mut challenge_header)
        .is_err()
    {
        return false;
    }

    if challenge_header[0] != AUTH_VERSION
        || challenge_header[1]
            != MESSAGE_TRANSFER_CHALLENGE
    {
        return false;
    }

    let mut challenge =
        [0u8; 32];

    if stream
        .read_exact(&mut challenge)
        .is_err()
    {
        return false;
    }

    /*
     * Sign challenge.
     */
    let signature =
        signing_key.sign(
            &challenge,
        );

    if stream
        .write_all(&[
            AUTH_VERSION,
            MESSAGE_TRANSFER_SIGNATURE,
        ])
        .is_err()
    {
        return false;
    }

    if stream
        .write_all(
            signature.to_bytes().as_ref(),
        )
        .is_err()
    {
        return false;
    }

    /*
     * Receive result.
     */
    let mut result =
        [0u8; 2];

    if stream
        .read_exact(&mut result)
        .is_err()
    {
        return false;
    }

    if result[0] != AUTH_VERSION {
        return false;
    }

    if result[1]
        == MESSAGE_TRANSFER_ACCEPTED
    {
        println!(
            "Transfer authentication successful."
        );

        return true;
    }

    println!(
        "Transfer authentication rejected."
    );

    false
}

fn hex_to_bytes(
    hex: &str,
) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }

    let mut bytes = Vec::new();

    let chars =
        hex.as_bytes();

    for index in
        (0..hex.len()).step_by(2)
    {
        let high =
            hex_value(chars[index])?;

        let low =
            hex_value(chars[index + 1])?;

        bytes.push(
            (high << 4) | low,
        );
    }

    Some(bytes)
}

fn hex_value(
    byte: u8,
) -> Option<u8> {
    match byte {
        b'0'..=b'9' =>
            Some(byte - b'0'),

        b'a'..=b'f' =>
            Some(byte - b'a' + 10),

        b'A'..=b'F' =>
            Some(byte - b'A' + 10),

        _ => None,
    }
}