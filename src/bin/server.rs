use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;

use drop::discovery;
use drop::pairing;
use drop::protocol::receive_header;
use drop::secure_channel::SecureChannel;

const RECEIVED_DIR: &str = "received";
const TEMP_DIR: &str = "received/.drop-temp";

fn main() {
    if let Err(error) = cleanup_abandoned_transfers() {
        eprintln!("Could not clean up temporary transfers: {error}");
        eprintln!("Drop will not start until this is resolved.");
        return;
    }

    let identity = discovery::load_or_create_device_identity();

    println!("Starting Drop...");
    println!("Device name: {}", identity.device_name);
    println!("Device ID: {}", identity.device_id);
    println!("Abandoned temporary transfers cleaned up.");

    let server_signing_key = identity.signing_key.clone();

    let pairing_code = pairing::generate_pairing_code();
    let pairing_signing_key = server_signing_key.clone();

    thread::spawn(move || {
        pairing::run_server(pairing_code, pairing_signing_key);
    });

    thread::spawn(move || {
        discovery::run_server(identity);
    });

    let listener =
        TcpListener::bind("0.0.0.0:9000").expect("Failed to bind file-transfer port 9000");

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

// Temporary files are isolated from completed downloads.
// At startup there cannot be any active transfers from a previous process.
fn cleanup_abandoned_transfers() -> io::Result<()> {
    fs::create_dir_all(RECEIVED_DIR)?;
    fs::create_dir_all(TEMP_DIR)?;

    for entry in fs::read_dir(TEMP_DIR)? {
        let entry = entry?;
        let file_type = entry.file_type()?;

       if file_type.is_file()
            && entry.path().extension().and_then(|ext| ext.to_str()) != Some("part")
        {
            match fs::remove_file(entry.path()) {
                Ok(()) => {
                    println!("Removed abandoned temporary file: {}", entry.path().display());
                }
                Err(error) => {
                    return Err(error);
                }
            }
        }
    }

    Ok(())
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

    if let Err(error) = fs::create_dir_all(TEMP_DIR) {
        reject_transfer(&mut channel, "Could not create temporary directory");
        println!("Failed to create temporary directory: {error}");
        return;
    }

    
    let checksum_name: String = header
        .checksum
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    let temporary_path = Path::new(TEMP_DIR)
        .join(format!("{}_{}.part", checksum_name, header.filename));

    
    let mut file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&temporary_path)
    {
        Ok(file) => file,
        Err(error) => {
            reject_transfer(&mut channel, "Could not open temporary file");
            println!("Failed to open temporary file: {error}");
            return;
        }
    };

    let mut received = match file.metadata() {
        Ok(metadata) => metadata.len(),
        Err(error) => {
            reject_transfer(&mut channel, "Could not inspect temporary file");
            println!("Failed to inspect temporary file: {error}");
            return;
        }
    };

    if received > header.file_size {
        if let Err(error) = file.set_len(0) {
            reject_transfer(&mut channel, "Could not reset temporary file");
            println!("Failed to reset temporary file: {error}");
            return;
        }
        received = 0;
    }

    let mut hasher = Sha256::new();
    let mut prefix_remaining = received;
    let mut buffer = [0u8; 32 * 1024];

    if let Err(error) = file.seek(SeekFrom::Start(0)) {
        reject_transfer(&mut channel, "Could not read temporary file");
        println!("Failed to seek temporary file: {error}");
        return;
    }

    while prefix_remaining > 0 {
        let amount = prefix_remaining.min(buffer.len() as u64) as usize;
        let bytes_read = match file.read(&mut buffer[..amount]) {
            Ok(0) => {
                reject_transfer(&mut channel, "Temporary file ended unexpectedly");
                println!("Temporary file was shorter than expected.");
                return;
            }
            Ok(count) => count,
            Err(error) => {
                reject_transfer(&mut channel, "Could not read temporary file");
                println!("Failed to read temporary file: {error}");
                return;
            }
        };

        hasher.update(&buffer[..bytes_read]);
        prefix_remaining -= bytes_read as u64;
    }

    if let Err(error) = file.seek(SeekFrom::End(0)) {
        reject_transfer(&mut channel, "Could not seek temporary file");
        println!("Failed to seek to end of temporary file: {error}");
        return;
    }

    if let Err(error) = channel.send(&received.to_be_bytes()) {
        println!("Could not send resume position: {error}");
        return;
    }

    println!("Resuming at byte {received}.");

    while received < header.file_size {
        let chunk = match channel.receive() {
            Ok(chunk) => chunk,
            Err(_) => {
                println!(
                    "Transfer interrupted; keeping partial file for resume: {}",
                    header.filename
                );
                drop(file);
                return;
            }
        };

        let remaining = header.file_size - received;

        if chunk.is_empty() || chunk.len() as u64 > remaining {
            reject_transfer(&mut channel, "Invalid chunk size");
            println!("Rejected empty or oversized data chunk.");
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

    // Reserve a unique final name without overwriting an existing file.
    let (final_path, mut destination) =
        match reserve_destination(Path::new(RECEIVED_DIR), &header.filename) {
            Ok(result) => result,
            Err(error) => {
                reject_transfer(&mut channel, "Could not choose a destination filename");
                println!("Failed to reserve destination filename: {error}");
                let _ = fs::remove_file(&temporary_path);
                return;
            }
        };

    // Only finalize the file after its checksum has been verified.
    let copy_result = (|| -> io::Result<()> {
        let mut source = File::open(&temporary_path)?;
        io::copy(&mut source, &mut destination)?;
        destination.flush()?;
        Ok(())
    })();

    if let Err(error) = copy_result {
        println!("Failed to finalize received file: {error}");
        drop(destination);
        let _ = fs::remove_file(&final_path);
        let _ = fs::remove_file(&temporary_path);
        reject_transfer(&mut channel, "Could not finalize the received file");
        return;
    }

    drop(destination);

    if let Err(error) = fs::remove_file(&temporary_path) {
        println!("Warning: could not remove temporary file: {error}");
    }

    match channel.send(b"OK") {
        Ok(()) => {
            println!("Transfer complete! Checksum verified.");
            println!("Saved to: {}", final_path.display());
            println!("Success acknowledgement sent to sender.");
        }
        Err(error) => {
            println!("File saved, but acknowledgement failed: {error}");
            println!("Saved to: {}", final_path.display());
        }
    }
}

fn reserve_destination(directory: &Path, filename: &str) -> io::Result<(PathBuf, File)> {
    let original_path = Path::new(filename);
    let stem = original_path
        .file_stem()
        .and_then(|part| part.to_str())
        .unwrap_or("received-file");
    let extension = original_path.extension().and_then(|part| part.to_str());

    for index in 0u32.. {
        let candidate_name = if index == 0 {
            filename.to_string()
        } else {
            match extension {
                Some(extension) => format!("{stem} ({index}).{extension}"),
                None => format!("{stem} ({index})"),
            }
        };

        let candidate_path = directory.join(candidate_name);

        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate_path)
        {
            Ok(file) => return Ok((candidate_path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }

    unreachable!("The filename search range is finite")
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
