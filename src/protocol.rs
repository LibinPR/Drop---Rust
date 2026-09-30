use std::io::{Read, Write};

pub struct TransferHeader {
    pub transfer_id: u64,
    pub filename: String,
    pub file_size: u64,
}

pub fn send_header<W: Write>(
    writer: &mut W,
    header: &TransferHeader,
) -> std::io::Result<()> {
    // Send transfer ID
    writer.write_all(&header.transfer_id.to_be_bytes())?;

    // Send filename length
    let filename_bytes = header.filename.as_bytes();
    let filename_length = filename_bytes.len() as u16;

    writer.write_all(&filename_length.to_be_bytes())?;

    // Send filename
    writer.write_all(filename_bytes)?;

    // Send file size
    writer.write_all(&header.file_size.to_be_bytes())?;

    Ok(())
}

pub fn receive_header<R: Read>(
    reader: &mut R,
) -> std::io::Result<TransferHeader> {
    // Read transfer ID
    let mut id_buffer = [0u8; 8];

    reader.read_exact(&mut id_buffer)?;

    let transfer_id = u64::from_be_bytes(id_buffer);

    // Read filename length
    let mut length_buffer = [0u8; 2];

    reader.read_exact(&mut length_buffer)?;

    let filename_length = u16::from_be_bytes(length_buffer);

    // Read filename
    let mut filename_buffer = vec![0u8; filename_length as usize];

    reader.read_exact(&mut filename_buffer)?;

    let filename = String::from_utf8(filename_buffer)
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid UTF-8 filename",
            )
        })?;

    // Read file size
    let mut size_buffer = [0u8; 8];

    reader.read_exact(&mut size_buffer)?;

    let file_size = u64::from_be_bytes(size_buffer);

    Ok(TransferHeader {
        transfer_id,
        filename,
        file_size,
    })
}