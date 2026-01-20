use anyhow::{Result, anyhow};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use serde_json::Value;

pub async fn read_message<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Value>> {
    let mut buffer = Vec::new();
    let mut content_length: Option<usize> = None;

    // Read headers
    loop {
        let mut byte = [0; 1];
        if reader.read(&mut byte).await? == 0 {
            return Ok(None); // EOF
        }
        buffer.push(byte[0]);

        if buffer.ends_with(b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&buffer);
            for line in headers.lines() {
                if line.to_lowercase().starts_with("content-length:") {
                    if let Some(val) = line.split(':').nth(1) {
                        content_length = Some(val.trim().parse()?);
                    }
                }
            }
            break;
        }
    }

    if let Some(len) = content_length {
        let mut body = vec![0; len];
        reader.read_exact(&mut body).await?;
        let val: Value = serde_json::from_slice(&body)?;
        return Ok(Some(val));
    }

    Ok(None)
}

pub async fn write_message<W: AsyncWrite + Unpin>(writer: &mut W, msg: &Value) -> Result<()> {
    let body = serde_json::to_string(msg)?;
    let content_length = body.len();
    let header = format!("Content-Length: {}\r\n\r\n", content_length);
    writer.write_all(header.as_bytes()).await?;
    writer.write_all(body.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}
