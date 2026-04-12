//! Core proxy logic: pipe bytes between client and Telegram DC with
//! AES-CTR encryption/decryption applied on the fly.

use crate::crypto::AesCtr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const BUF: usize = 16 * 1024;

/// Bidirectional pipe between an already-handshaked client stream and the
/// upstream Telegram DC stream.
///
/// `client_dec` decrypts bytes arriving FROM the client.
/// `client_enc` encrypts bytes going TO the client.
///
/// The Telegram side is plain (no extra encryption).
pub async fn pipe(
    client: TcpStream,
    tg: TcpStream,
    mut client_dec: AesCtr,
    mut client_enc: AesCtr,
) -> anyhow::Result<()> {
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut tr, mut tw) = tokio::io::split(tg);

    let client_to_tg = async {
        let mut buf = vec![0u8; BUF];
        loop {
            let n = cr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            client_dec.apply(&mut buf[..n]);
            tw.write_all(&buf[..n]).await?;
        }
        tw.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };

    let tg_to_client = async {
        let mut buf = vec![0u8; BUF];
        loop {
            let n = tr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            client_enc.apply(&mut buf[..n]);
            cw.write_all(&buf[..n]).await?;
        }
        cw.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };

    tokio::try_join!(client_to_tg, tg_to_client)?;
    Ok(())
}

/// Same as `pipe` but the client side is wrapped in TLS ApplicationData records.
/// Each direction reads/writes `TLS_APP_DATA` framing.
pub async fn pipe_faketls(
    client: TcpStream,
    tg: TcpStream,
    mut client_dec: AesCtr,
    mut client_enc: AesCtr,
) -> anyhow::Result<()> {
    use crate::fake_tls::{read_app_data, wrap_app_data};

    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut tr, mut tw) = tokio::io::split(tg);

    let client_to_tg = async {
        loop {
            let mut payload = read_app_data(&mut cr).await?;
            client_dec.apply(&mut payload);
            tw.write_all(&payload).await?;
        }
        #[allow(unreachable_code)]
        tw.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };

    let tg_to_client = async {
        let mut buf = vec![0u8; BUF];
        loop {
            let n = tr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            client_enc.apply(&mut buf[..n]);
            let frame = wrap_app_data(&buf[..n]);
            cw.write_all(&frame).await?;
        }
        cw.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };

    tokio::try_join!(client_to_tg, tg_to_client)?;
    Ok(())
}
