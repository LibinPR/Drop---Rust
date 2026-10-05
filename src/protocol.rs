use std::io::{Read, Write};

const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

pub struct TransferHeader {
    pub transfer_id: u64,
    pub filename: String,
    pub file_size: u64,
    pub checksum: [u8; 32],
}

pub fn send_header<W: Write>(
    writer: &mut W,
    header: &TransferHeader,
) -> std::io::Result<()> {
    writer.write_all(
        &header.transfer_id.to_be_bytes(),
    )?;

    let filename_bytes =
        header.filename.as_bytes();

    let filename_length =
        filename_bytes.len() as u16;

    writer.write_all(
        &filename_length.to_be_bytes(),
    )?;

    writer.write_all(filename_bytes)?;

    writer.write_all(
        &header.file_size.to_be_bytes(),
    )?;

    writer.write_all(&header.checksum)?;

    Ok(())
}

pub fn receive_header<R: Read>(
    reader: &mut R,
) -> std::io::Result<TransferHeader> {
    let mut id_buffer = [0u8; 8];

    reader.read_exact(&mut id_buffer)?;

    let transfer_id =
        u64::from_be_bytes(id_buffer);

    let mut length_buffer = [0u8; 2];

    reader.read_exact(
        &mut length_buffer,
    )?;

    let filename_length =
        u16::from_be_bytes(length_buffer);

    let mut filename_buffer =
        vec![0u8; filename_length as usize];

    reader.read_exact(
        &mut filename_buffer,
    )?;

    let filename =
        String::from_utf8(filename_buffer)
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid UTF-8 filename",
                )
            })?;

    let mut size_buffer = [0u8; 8];

    reader.read_exact(
        &mut size_buffer,
    )?;

    let file_size =
        u64::from_be_bytes(size_buffer);

    let mut checksum = [0u8; 32];

    reader.read_exact(&mut checksum)?;

    Ok(TransferHeader {
        transfer_id,
        filename,
        file_size,
        checksum,
    })
}

/*
 * Generic protocol message framing.
 *
 * Message format:
 *
 * [1 byte type]
 * [4 bytes payload length]
 * [payload]
 */

pub fn send_message<W: Write>(
    writer: &mut W,
    message_type: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    let payload_length =
        u32::try_from(payload.len())
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Message is too large",
                )
            })?;

    if payload_length > MAX_MESSAGE_SIZE {
        return Err(
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Message exceeds maximum size",
            ),
        );
    }

    writer.write_all(
        &[message_type],
    )?;

    writer.write_all(
        &payload_length.to_be_bytes(),
    )?;

    writer.write_all(payload)?;

    Ok(())
}

pub fn receive_message<R: Read>(
    reader: &mut R,
) -> std::io::Result<(u8, Vec<u8>)> {
    let mut type_buffer = [0u8; 1];

    reader.read_exact(
        &mut type_buffer,
    )?;

    let message_type =
        type_buffer[0];

    let mut length_buffer = [0u8; 4];

    reader.read_exact(
        &mut length_buffer,
    )?;

    let payload_length =
        u32::from_be_bytes(length_buffer);

    if payload_length > MAX_MESSAGE_SIZE {
        return Err(
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Message exceeds maximum size",
            ),
        );
    }

    let mut payload =
        vec![0u8; payload_length as usize];

    reader.read_exact(&mut payload)?;

    Ok((
        message_type,
        payload,
    ))
}