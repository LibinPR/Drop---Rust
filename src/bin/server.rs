use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use drop::discovery;
use drop::protocol::receive_header;

fn main() {
    // Start UDP device discovery in its own thread.
    thread::spawn(|| {
        discovery::run_server();
    });

    // Start the TCP file-transfer server.
    let listener = TcpListener::bind("0.0.0.0:9000").unwrap();

    println!("File server listening on 0.0.0.0:9000");

    for stream in listener.incoming() {
        let stream = stream.unwrap();

        thread::spawn(|| {
            handle_client(stream);
        });
    }
}

fn handle_client(mut stream: std::net::TcpStream) {
    // Receive the transfer header.
    let header = match receive_header(&mut stream) {
        Ok(header) => header,
        Err(error) => {
            println!("Failed to receive header: {}", error);
            return;
        }
    };

    println!("Transfer ID: {}", header.transfer_id);
    println!("Filename: {}", header.filename);
    println!("File size: {} bytes", header.file_size);

    // Validate the filename.
    if !is_safe_filename(&header.filename) {
        println!("Rejected unsafe filename: {}", header.filename);
        return;
    }

    let temp_path = format!(
        "received/{}_{}.part",
        header.transfer_id,
        header.filename
    );

    let final_path = format!(
        "received/{}_{}",
        header.transfer_id,
        header.filename
    );

    let mut file = match File::create(&temp_path) {
        Ok(file) => file,
        Err(error) => {
            println!("Failed to create file: {}", error);
            return;
        }
    };

    let mut hasher = Sha256::new();

    let mut buffer = [0u8; 1024];

    let mut received = 0u64;

    while received < header.file_size {
        let bytes_read = match stream.read(&mut buffer) {
            Ok(bytes) => bytes,

            Err(error) => {
                println!(
                    "Connection error during transfer: {}",
                    error
                );

                break;
            }
        };

        if bytes_read == 0 {
            println!("Connection closed before transfer completed.");
            break;
        }

        file.write_all(&buffer[..bytes_read]).unwrap();

        hasher.update(&buffer[..bytes_read]);

        received += bytes_read as u64;

        println!(
            "Received {} / {} bytes",
            received,
            header.file_size
        );
    }

    file.flush().unwrap();

    if received != header.file_size {
        drop(file);

        fs::remove_file(&temp_path).unwrap();

        println!(
            "Transfer incomplete: received {} / {} bytes",
            received,
            header.file_size
        );

        println!("Incomplete file deleted.");

        return;
    }

    let received_checksum = hasher.finalize();

    if received_checksum[..] != header.checksum[..] {
        drop(file);

        fs::remove_file(&temp_path).unwrap();

        println!("Checksum verification failed.");
        println!("File was deleted.");

        return;
    }

    drop(file);

    fs::rename(&temp_path, &final_path).unwrap();

    println!("Checksum verified.");
    println!("File saved as {}", final_path);
}

fn is_safe_filename(filename: &str) -> bool {
    if filename.is_empty() {
        return false;
    }

    if filename.len() > 255 {
        return false;
    }

    if filename.contains('/') {
        return false;
    }

    if filename.contains('\\') {
        return false;
    }

    if filename == ".." {
        return false;
    }

    true
}