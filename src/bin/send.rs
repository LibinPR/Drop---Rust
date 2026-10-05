use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::net::UdpSocket;
use std::time::{
    Duration,
    SystemTime,
    UNIX_EPOCH,
};

use drop::protocol::{
    send_header,
    TransferHeader,
};
use drop::transfer_auth;

const DISCOVERY_PORT: u16 = 9001;
const DISCOVERY_MESSAGE: &[u8] =
    b"DROP_DISCOVER";

fn main() {
    /*
     * Discover a Drop device.
     */
    let socket =
        UdpSocket::bind(
            "0.0.0.0:0",
        )
        .unwrap();

    socket
        .set_broadcast(true)
        .unwrap();

    socket
        .set_read_timeout(
            Some(Duration::from_secs(3)),
        )
        .unwrap();

    socket
        .send_to(
            DISCOVERY_MESSAGE,
            format!(
                "255.255.255.255:{}",
                DISCOVERY_PORT
            ),
        )
        .unwrap();

    println!(
        "Searching for Drop devices..."
    );

    let mut buffer =
        [0u8; 1024];

    let (
        device_ip,
        device_port,
        device_id,
        device_name,
    ) = loop {
        match socket.recv_from(
            &mut buffer,
        ) {
            Ok((
                bytes_received,
                sender_address,
            )) => {
                let message =
                    String::from_utf8_lossy(
                        &buffer[..bytes_received],
                    );

                let parts:
                    Vec<&str> =
                    message
                        .split('|')
                        .collect();

                if parts.len() == 4
                    && parts[0]
                        == "DROP_HERE"
                {
                    let device_id =
                        parts[1];

                    let device_name =
                        parts[2];

                    let port =
                        match parts[3]
                            .parse::<u16>()
                        {
                            Ok(port) =>
                                port,

                            Err(_) => {
                                continue;
                            }
                        };

                    break (
                        sender_address.ip(),
                        port,
                        device_id.to_string(),
                        device_name.to_string(),
                    );
                }
            }

            Err(error) => {
                println!(
                    "Discovery failed: {}",
                    error
                );

                return;
            }
        }
    };

    println!(
        "Found device: {}",
        device_name
    );

    println!(
        "Device ID: {}",
        device_id
    );

    println!(
        "Connecting to {}:{}...",
        device_ip,
        device_port
    );

    let mut stream =
        match std::net::TcpStream::connect(
            (
                device_ip,
                device_port,
            ),
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

    println!(
        "Connected!"
    );

    /*
     * Authenticate before sending
     * any file-transfer data.
     *
     * IMPORTANT:
     *
     * This is currently the phone/test
     * device's private key.
     */
    let signing_key =
        load_phone_signing_key();

    if !transfer_auth::send_authentication_request(
        &mut stream,
        &signing_key,
    ) {
        println!(
            "Transfer authentication failed."
        );

        return;
    }

    /*
     * Open the file.
     */
    let filename =
        "big.txt";

    let mut file =
        match File::open(filename) {
            Ok(file) => file,

            Err(error) => {
                println!(
                    "Failed to open {}: {}",
                    filename,
                    error
                );

                return;
            }
        };

    let file_size =
        match file.metadata() {
            Ok(metadata) =>
                metadata.len(),

            Err(error) => {
                println!(
                    "Failed to read file metadata: {}",
                    error
                );

                return;
            }
        };

    println!(
        "File: {}",
        filename
    );

    println!(
        "File size: {} bytes",
        file_size
    );

    /*
     * Calculate SHA-256.
     */
    let mut hasher =
        Sha256::new();

    let mut buffer =
        [0u8; 1024];

    loop {
        let bytes_read =
            match file.read(
                &mut buffer,
            ) {
                Ok(0) => break,

                Ok(bytes) => bytes,

                Err(error) => {
                    println!(
                        "Failed to read file: {}",
                        error
                    );

                    return;
                }
            };

        hasher.update(
            &buffer[..bytes_read],
        );
    }

    let checksum =
        hasher.finalize();

    /*
     * Rewind file so we can send it.
     */
    if let Err(error) =
        file.rewind()
    {
        println!(
            "Failed to rewind file: {}",
            error
        );

        return;
    }

    let transfer_id =
        SystemTime::now()
            .duration_since(
                UNIX_EPOCH,
            )
            .unwrap()
            .as_nanos() as u64;

    let header =
        TransferHeader {
            transfer_id,
            filename:
                filename.to_string(),
            file_size,
            checksum:
                checksum.into(),
        };

    if let Err(error) =
        send_header(
            &mut stream,
            &header,
        )
    {
        println!(
            "Failed to send file header: {}",
            error
        );

        return;
    }

    println!(
        "Header sent!"
    );

    let mut sent =
        0u64;

    loop {
        let bytes_read =
            match file.read(
                &mut buffer,
            ) {
                Ok(0) => break,

                Ok(bytes) => bytes,

                Err(error) => {
                    println!(
                        "Failed to read file: {}",
                        error
                    );

                    return;
                }
            };

        if let Err(error) =
            stream.write_all(
                &buffer[..bytes_read],
            )
        {
            println!(
                "Failed to send file: {}",
                error
            );

            return;
        }

        sent +=
            bytes_read as u64;

        println!(
            "Sent {} / {} bytes",
            sent,
            file_size
        );
    }

    println!(
        "Transfer complete!"
    );
}

fn load_phone_signing_key()
    -> ed25519_dalek::SigningKey
{
    let key_bytes =
        std::fs::read(
            "phone_device_key.bin",
        )
        .expect(
            "Failed to read phone device key",
        );

    let key_array:
        [u8; 32] =
        key_bytes
            .try_into()
            .expect(
                "Phone device key must contain exactly 32 bytes",
            );

    ed25519_dalek::SigningKey::from_bytes(
        &key_array,
    )
}