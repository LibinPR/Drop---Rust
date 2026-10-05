use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use drop::discovery;
use drop::pairing;
use drop::protocol::receive_header;
use drop::transfer_auth;

fn main() {
    let identity =
        discovery::load_or_create_device_identity();

    println!("Starting Drop...");
    println!(
        "Device name: {}",
        identity.device_name
    );
    println!(
        "Device ID: {}",
        identity.device_id
    );

    let pairing_code =
        pairing::generate_pairing_code();

    let signing_key =
        identity.signing_key.clone();

    thread::spawn(move || {
        pairing::run_server(
            pairing_code,
            signing_key,
        );
    });

    thread::spawn(move || {
        discovery::run_server(identity);
    });

    let listener =
        TcpListener::bind(
            "0.0.0.0:9000",
        )
        .unwrap();

    println!(
        "File server listening on 0.0.0.0:9000"
    );

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,

            Err(error) => {
                println!(
                    "Connection failed: {}",
                    error
                );

                continue;
            }
        };

        thread::spawn(|| {
            handle_client(stream);
        });
    }
}

fn handle_client(
    mut stream: std::net::TcpStream,
) {
    /*
     * Authenticate the device BEFORE
     * accepting any file-transfer data.
     */
    if !transfer_auth::authenticate_client(
        &mut stream,
    ) {
        println!(
            "Unauthenticated transfer connection closed."
        );

        return;
    }

    println!(
        "Authenticated transfer connection accepted."
    );

    /*
     * Only now do we read the file header.
     */
    let header =
        match receive_header(&mut stream) {
            Ok(header) => header,

            Err(error) => {
                println!(
                    "Failed to receive header: {}",
                    error
                );

                return;
            }
        };

    println!(
        "Incoming file: {}",
        header.filename
    );

    println!(
        "Expected size: {} bytes",
        header.file_size
    );

    println!(
        "Transfer ID: {}",
        header.transfer_id
    );

    if !is_safe_filename(
        &header.filename,
    ) {
        println!(
            "Rejected unsafe filename: {}",
            header.filename
        );

        return;
    }

    fs::create_dir_all("received")
        .expect(
            "Failed to create received directory",
        );

    let temporary_path =
        format!(
            "received/{}_{}.part",
            header.transfer_id,
            header.filename
        );

    let final_path =
        format!(
            "received/{}_{}",
            header.transfer_id,
            header.filename
        );

    let mut file =
        match File::create(
            &temporary_path,
        ) {
            Ok(file) => file,

            Err(error) => {
                println!(
                    "Failed to create temporary file: {}",
                    error
                );

                return;
            }
        };

    let mut hasher =
        Sha256::new();

    let mut buffer =
        [0u8; 1024];

    let mut received =
        0u64;

    while received <
        header.file_size
    {
        let remaining =
            header.file_size - received;

        let buffer_size =
            remaining.min(
                buffer.len() as u64
            ) as usize;

        let bytes_read =
            match stream.read(
                &mut buffer[..buffer_size],
            ) {
                Ok(0) => {
                    println!(
                        "Connection closed before transfer completed."
                    );

                    break;
                }

                Ok(bytes) => bytes,

                Err(error) => {
                    println!(
                        "Connection error during transfer: {}",
                        error
                    );

                    break;
                }
            };

        if let Err(error) =
            file.write_all(
                &buffer[..bytes_read],
            )
        {
            println!(
                "Failed to write file: {}",
                error
            );

            break;
        }

        hasher.update(
            &buffer[..bytes_read],
        );

        received +=
            bytes_read as u64;

        println!(
            "Received {} / {} bytes",
            received,
            header.file_size
        );
    }

    /*
     * Make sure the temporary file is
     * flushed before verification.
     */
    if let Err(error) =
        file.flush()
    {
        println!(
            "Failed to flush file: {}",
            error
        );

        let _ =
            fs::remove_file(
                &temporary_path,
            );

        return;
    }

    /*
     * The transfer must contain exactly
     * the expected number of bytes.
     */
    if received != header.file_size {
        println!(
            "Transfer incomplete: received {} / {} bytes",
            received,
            header.file_size
        );

        drop(file);

        let _ =
            fs::remove_file(
                &temporary_path,
            );

        println!(
            "Incomplete file deleted."
        );

        return;
    }

    let calculated_checksum =
        hasher.finalize();

    if calculated_checksum.as_slice()
        != header.checksum
    {
        println!(
            "Checksum mismatch!"
        );

        drop(file);

        let _ =
            fs::remove_file(
                &temporary_path,
            );

        println!(
            "Corrupt file deleted."
        );

        return;
    }

    drop(file);

    if let Err(error) =
        fs::rename(
            &temporary_path,
            &final_path,
        )
    {
        println!(
            "Failed to finalize file: {}",
            error
        );

        let _ =
            fs::remove_file(
                &temporary_path,
            );

        return;
    }

    println!(
        "Transfer complete!"
    );

    println!(
        "Saved to: {}",
        final_path
    );
}

fn is_safe_filename(
    filename: &str,
) -> bool {
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