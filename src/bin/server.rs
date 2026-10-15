use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Cursor, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use drop::discovery;
use drop::pairing;
use drop::protocol::receive_header;
use drop::secure_channel::SecureChannel;

fn main() {
    let identity = discovery::load_or_create_device_identity();

    println!("Starting Drop...");
    println!("Device name: {}", identity.device_name);
    println!("Device ID: {}", identity.device_id);

    let server_signing_key = identity.signing_key.clone();

    let pairing_code = pairing::generate_pairing_code();
    let pairing_signing_key = server_signing_key.clone();

    thread::spawn(move || {
        pairing::run_server(pairing_code, pairing_signing_key);
    });

    thread::spawn(move || {
        discovery::run_server(identity);
    });

    let listener = TcpListener::bind("0.0.0.0:9000")
        .expect("Failed to bind file-transfer port 9000");

    println!("Encrypted file server listening on port 9000");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let signing_key = server_signing_key.clone();

                thread::spawn(move || {
                    handle_client(stream, signing_key);
                });
            }
            Err(error) => {
                println!("Connection failed: {error}");
            }
        }
    }
}

fn handle_client(stream: TcpStream, signing_key: ed25519_dalek::SigningKey) {
    let mut channel = match drop::secure_channel::accept_server(stream, &signing_key) {
        Ok(channel) => channel,
        Err(error) => {
            println!("Secure connection rejected: {error}");
            return;
        }
    };

    println!("Trusted device connected through an encrypted channel.");

    let header_bytes = match channel.receive() {
        Ok(bytes) => bytes,
        Err(error) => {
            println!("Failed to receive encrypted header: {error}");
            return;
        }
    };

    let header = match receive_header(&mut Cursor::new(header_bytes)) {
        Ok(header) => header,
        Err(error) => {
            reject_transfer(&mut channel, "Invalid transfer header");
            println!("Invalid transfer header: {error}");
            return;
        }
    };

    if !is_safe_filename(&header.filename) {
        reject_transfer(&mut channel, "Unsafe filename");
        println!("Rejected unsafe filename: {}", header.filename);
        return;
    }

    println!("Incoming file: {}", header.filename);
    println!("Expected size: {} bytes", header.file_size);

    if let Err(error) = fs::create_dir_all("received") {
        reject_transfer(&mut channel, "Could not create received directory");
        println!("Failed to create received directory: {error}");
        return;
    }

    let temporary_path = format!(
        "received/{}_{}.part",
        header.transfer_id, header.filename
    );
    let final_path = format!(
        "received/{}_{}",
        header.transfer_id, header.filename
    );

    let mut file = match File::create(&temporary_path) {
        Ok(file) => file,
        Err(error) => {
            reject_transfer(&mut channel, "Could not create destination file");
            println!("Failed to create temporary file: {error}");
            return;
        }
    };

    let mut hasher = Sha256::new();
    let mut received = 0u64;

    while received < header.file_size {
        let chunk = match channel.receive() {
            Ok(chunk) => chunk,
            Err(error) => {
                println!("Encrypted transfer failed: {error}");
                drop(file);
                let _ = fs::remove_file(&temporary_path);
                // The connection may be broken, so an acknowledgement may fail.
                reject_transfer(&mut channel, "Transfer interrupted");
                return;
            }
        };

        let remaining = header.file_size - received;

        if chunk.len() as u64 > remaining {
            reject_transfer(&mut channel, "Received more data than expected");
            println!("Rejected data exceeding the declared file size.");
            drop(file);
            let _ = fs::remove_file(&temporary_path);
            return;
        }

        if let Err(error) = file.write_all(&chunk) {
            reject_transfer(&mut channel, "Could not write received file");
            println!("Failed to write file: {error}");
            drop(file);
            let _ = fs::remove_file(&temporary_path);
            return;
        }

        hasher.update(&chunk);
        received += chunk.len() as u64;

        println!("Received {} / {} bytes", received, header.file_size);
    }

    if let Err(error) = file.flush() {
        reject_transfer(&mut channel, "Could not finish writing the file");
        println!("Failed to flush file: {error}");
        drop(file);
        let _ = fs::remove_file(&temporary_path);
        return;
    }

    let calculated_checksum = hasher.finalize();

    if calculated_checksum.as_slice() != header.checksum {
        reject_transfer(&mut channel, "SHA-256 checksum mismatch");
        println!("Checksum mismatch; deleting corrupt file.");
        drop(file);
        let _ = fs::remove_file(&temporary_path);
        return;
    }

    drop(file);

    if let Err(error) = fs::rename(&temporary_path, &final_path) {
        reject_transfer(&mut channel, "Could not finalize the received file");
        println!("Failed to finalize file: {error}");
        let _ = fs::remove_file(&temporary_path);
        return;
    }

    // Send success only after checksum verification and final file rename.
    match channel.send(b"OK") {
        Ok(()) => {
            println!("Transfer complete! Checksum verified.");
            println!("Saved to: {final_path}");
            println!("Success acknowledgement sent to sender.");
        }
        Err(error) => {
            println!("File saved, but acknowledgement failed: {error}");
            println!("Saved to: {final_path}");
        }
    }
}

fn reject_transfer(channel: &mut SecureChannel, reason: &str) {
    let message = format!("ERR:{reason}");

    if let Err(error) = channel.send(message.as_bytes()) {
        println!("Could not send failure acknowledgement: {error}");
    }
}

fn is_safe_filename(filename: &str) -> bool {
    !filename.is_empty()
        && filename.len() <= 255
        && filename != "."
        && filename != ".."
        && !filename.contains('/')
        && !filename.contains('\\')
        && !filename.contains(':')
        && !filename.chars().any(char::is_control)
}