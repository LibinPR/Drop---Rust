use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use snow::{TransportState, params::NoiseParams};
use std::io::{self, Read, Write};
use std::net::TcpStream;

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const MAX_FRAME_SIZE: usize = 64 * 1024;
const MAX_PLAINTEXT_SIZE: usize = MAX_FRAME_SIZE - 16;
const IDENTITY_DOMAIN: &[u8] = b"DROP-IDENTITY-PROOF-V1";

pub struct SecureChannel {
    stream: TcpStream,
    transport: TransportState,
}

fn io_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn noise_params() -> Result<NoiseParams, String> {
    NOISE_PATTERN
        .parse()
        .map_err(|e| format!("Invalid Noise protocol: {e}"))
}

fn write_frame(stream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    if data.is_empty() || data.len() > MAX_FRAME_SIZE {
        return Err(io_error("Invalid frame size"));
    }

    let length = u32::try_from(data.len()).map_err(|_| io_error("Frame is too large"))?;

    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(data)?;
    stream.flush()?;
    Ok(())
}

fn read_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut length_bytes = [0u8; 4];
    stream.read_exact(&mut length_bytes)?;

    let length = u32::from_be_bytes(length_bytes) as usize;

    if length == 0 || length > MAX_FRAME_SIZE {
        return Err(io_error("Invalid incoming frame size"));
    }

    let mut data = vec![0u8; length];
    stream.read_exact(&mut data)?;
    Ok(data)
}

fn public_key_id(public_key: &[u8; 32]) -> String {
    public_key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn parse_device_id(device_id: &str) -> Result<[u8; 32], String> {
    if device_id.len() != 64 {
        return Err("Device ID must contain 64 hexadecimal characters".into());
    }

    let mut public_key = [0u8; 32];

    for (index, byte) in public_key.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&device_id[start..start + 2], 16)
            .map_err(|_| "Device ID contains invalid hexadecimal characters")?;
    }

    Ok(public_key)
}

fn identity_proof_message(
    own_noise_static: &[u8],
    peer_noise_static: &[u8],
    handshake_hash: &[u8],
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(IDENTITY_DOMAIN);
    message.extend_from_slice(&(handshake_hash.len() as u32).to_be_bytes());
    message.extend_from_slice(handshake_hash);
    message.extend_from_slice(&(own_noise_static.len() as u32).to_be_bytes());
    message.extend_from_slice(own_noise_static);
    message.extend_from_slice(&(peer_noise_static.len() as u32).to_be_bytes());
    message.extend_from_slice(peer_noise_static);
    message
}

fn send_encrypted(
    stream: &mut TcpStream,
    transport: &mut TransportState,
    plaintext: &[u8],
) -> io::Result<()> {
    if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT_SIZE {
        return Err(io_error("Invalid plaintext message size"));
    }

    let mut ciphertext = vec![0u8; plaintext.len() + 128];

    let written = transport
        .write_message(plaintext, &mut ciphertext)
        .map_err(|e| io_error(format!("Encryption failed: {e}")))?;

    ciphertext.truncate(written);
    write_frame(stream, &ciphertext)
}

fn receive_encrypted(
    stream: &mut TcpStream,
    transport: &mut TransportState,
) -> io::Result<Vec<u8>> {
    let ciphertext = read_frame(stream)?;
    let mut plaintext = vec![0u8; ciphertext.len()];

    let written = transport
        .read_message(&ciphertext, &mut plaintext)
        .map_err(|e| io_error(format!("Decryption or authentication failed: {e}")))?;

    plaintext.truncate(written);

    if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT_SIZE {
        return Err(io_error("Invalid decrypted message size"));
    }

    Ok(plaintext)
}

fn build_proof(
    signing_key: &SigningKey,
    own_noise_static: &[u8],
    peer_noise_static: &[u8],
    handshake_hash: &[u8],
) -> Vec<u8> {
    let message = identity_proof_message(own_noise_static, peer_noise_static, handshake_hash);

    let signature = signing_key.sign(&message);

    let mut proof = Vec::with_capacity(96);
    proof.extend_from_slice(&signing_key.verifying_key().to_bytes());
    proof.extend_from_slice(&signature.to_bytes());
    proof
}

fn verify_proof(
    proof: &[u8],
    expected_device_id: &str,
    own_noise_static: &[u8],
    peer_noise_static: &[u8],
    handshake_hash: &[u8],
) -> Result<(), String> {
    if proof.len() != 96 {
        return Err("Invalid identity proof length".into());
    }

    let public_bytes: [u8; 32] = proof[..32]
        .try_into()
        .map_err(|_| "Invalid identity public key")?;

    if public_key_id(&public_bytes) != expected_device_id {
        return Err("Device identity does not match the expected device".into());
    }

    let verifying_key = VerifyingKey::from_bytes(&public_bytes)
        .map_err(|e| format!("Invalid identity public key: {e}"))?;

    let signature = Signature::from_slice(&proof[32..])
        .map_err(|e| format!("Invalid identity signature: {e}"))?;

    let message = identity_proof_message(own_noise_static, peer_noise_static, handshake_hash);

    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| "Device identity signature verification failed".into())
}

fn send_device_id(stream: &mut TcpStream, device_id: &str) -> Result<(), String> {
    let bytes = device_id.as_bytes();

    if bytes.len() != 64 {
        return Err("Invalid device ID length".into());
    }

    write_frame(stream, bytes).map_err(|e| e.to_string())
}

fn receive_device_id(stream: &mut TcpStream) -> Result<String, String> {
    let bytes = read_frame(stream).map_err(|e| e.to_string())?;

    if bytes.len() != 64 {
        return Err("Invalid device ID length".into());
    }

    let id = String::from_utf8(bytes).map_err(|_| "Device ID is not valid UTF-8")?;

    parse_device_id(&id)?;
    Ok(id)
}

impl SecureChannel {
    pub fn send(&mut self, plaintext: &[u8]) -> io::Result<()> {
        send_encrypted(&mut self.stream, &mut self.transport, plaintext)
    }

    pub fn receive(&mut self) -> io::Result<Vec<u8>> {
        receive_encrypted(&mut self.stream, &mut self.transport)
    }

    /// Shut down the TCP connection to stop an ongoing transfer.
    pub fn shutdown(&self) -> io::Result<()> {
        self.stream.shutdown(std::net::Shutdown::Both)
    }
}

/// Client side: verifies that the remote server owns the expected PC identity.
pub fn connect_client(
    mut stream: TcpStream,
    signing_key: &SigningKey,
    expected_server_id: &str,
) -> Result<SecureChannel, String> {
    parse_device_id(expected_server_id)?;

    // Identify the client so the server can check its trusted-device list.
    let client_id = public_key_id(&signing_key.verifying_key().to_bytes());
    send_device_id(&mut stream, &client_id)?;

    let params = noise_params()?;
    let keypair = snow::Builder::new(params.clone())
        .generate_keypair()
        .map_err(|e| format!("Could not generate Noise keypair: {e}"))?;

    let builder = snow::Builder::new(params)
        .local_private_key(&keypair.private)
        .map_err(|e| format!("Could not set client Noise key: {e}"))?;

    let mut handshake = builder
        .build_initiator()
        .map_err(|e| format!("Could not start Noise handshake: {e}"))?;
    // Noise XX message 1: client -> server.
    let mut message = vec![0u8; MAX_FRAME_SIZE];
    let length = handshake
        .write_message(&[], &mut message)
        .map_err(|e| format!("Noise message 1 failed: {e}"))?;
    message.truncate(length);
    write_frame(&mut stream, &message).map_err(|e| e.to_string())?;

    // Noise XX message 2: server -> client.
    let incoming = read_frame(&mut stream).map_err(|e| e.to_string())?;
    let mut plaintext = vec![0u8; MAX_FRAME_SIZE];
    handshake
        .read_message(&incoming, &mut plaintext)
        .map_err(|e| format!("Noise message 2 failed: {e}"))?;

    // Noise XX message 3: client -> server.
    let mut message = vec![0u8; MAX_FRAME_SIZE];
    let length = handshake
        .write_message(&[], &mut message)
        .map_err(|e| format!("Noise message 3 failed: {e}"))?;
    message.truncate(length);
    write_frame(&mut stream, &message).map_err(|e| e.to_string())?;

    let peer_static = handshake
        .get_remote_static()
        .ok_or("Server did not provide a Noise static key")?
        .to_vec();

    let handshake_hash = handshake.get_handshake_hash().to_vec();
    let own_static = keypair.public.clone();

    let mut transport = handshake
        .into_transport_mode()
        .map_err(|e| format!("Could not establish encrypted transport: {e}"))?;

    // The client proves its persistent Ed25519 identity inside encryption.
    let proof = build_proof(signing_key, &own_static, &peer_static, &handshake_hash);

    send_encrypted(&mut stream, &mut transport, &proof)
        .map_err(|e| format!("Could not send client identity proof: {e}"))?;

    // Verify the PC's persistent Ed25519 identity and its binding to this session.
    let server_proof = receive_encrypted(&mut stream, &mut transport)
        .map_err(|e| format!("Could not receive server identity proof: {e}"))?;

    verify_proof(
        &server_proof,
        expected_server_id,
        &peer_static,
        &own_static,
        &handshake_hash,
    )?;

    Ok(SecureChannel { stream, transport })
}

/// Server side: rejects untrusted clients and proves the server's identity.
pub fn accept_server(
    mut stream: TcpStream,
    signing_key: &SigningKey,
) -> Result<SecureChannel, String> {
    let client_id = receive_device_id(&mut stream)?;

    if !crate::trusted::is_trusted(&client_id) {
        return Err("Client device is not trusted".into());
    }

    let client_public = parse_device_id(&client_id)?;
    VerifyingKey::from_bytes(&client_public)
        .map_err(|e| format!("Invalid client public key: {e}"))?;

    let params = noise_params()?;
    let keypair = snow::Builder::new(params.clone())
        .generate_keypair()
        .map_err(|e| format!("Could not generate Noise keypair: {e}"))?;

    let builder = snow::Builder::new(params)
        .local_private_key(&keypair.private)
        .map_err(|e| format!("Could not set server Noise key: {e}"))?;

    let mut handshake = builder
        .build_responder()
        .map_err(|e| format!("Could not start Noise handshake: {e}"))?;

    // Noise XX message 1: client -> server.
    let incoming = read_frame(&mut stream).map_err(|e| e.to_string())?;
    let mut plaintext = vec![0u8; MAX_FRAME_SIZE];
    handshake
        .read_message(&incoming, &mut plaintext)
        .map_err(|e| format!("Noise message 1 failed: {e}"))?;

    // Noise XX message 2: server -> client.
    let mut message = vec![0u8; MAX_FRAME_SIZE];
    let length = handshake
        .write_message(&[], &mut message)
        .map_err(|e| format!("Noise message 2 failed: {e}"))?;
    message.truncate(length);
    write_frame(&mut stream, &message).map_err(|e| e.to_string())?;

    // Noise XX message 3: client -> server.
    let incoming = read_frame(&mut stream).map_err(|e| e.to_string())?;
    handshake
        .read_message(&incoming, &mut plaintext)
        .map_err(|e| format!("Noise message 3 failed: {e}"))?;

    let peer_static = handshake
        .get_remote_static()
        .ok_or("Client did not provide a Noise static key")?
        .to_vec();

    let handshake_hash = handshake.get_handshake_hash().to_vec();
    let own_static = keypair.public.clone();

    let mut transport = handshake
        .into_transport_mode()
        .map_err(|e| format!("Could not establish encrypted transport: {e}"))?;

    // Verify the trusted client's persistent identity.
    let client_proof = receive_encrypted(&mut stream, &mut transport)
        .map_err(|e| format!("Could not receive client identity proof: {e}"))?;

    verify_proof(
        &client_proof,
        &client_id,
        &peer_static,
        &own_static,
        &handshake_hash,
    )?;

    // Prove the PC's persistent identity to the client.
    let proof = build_proof(signing_key, &own_static, &peer_static, &handshake_hash);

    send_encrypted(&mut stream, &mut transport, &proof)
        .map_err(|e| format!("Could not send server identity proof: {e}"))?;

    Ok(SecureChannel { stream, transport })
}
