mod config;
mod crypto;
mod fake_tls;
mod handshake;
mod proxy;
mod replay;
mod telegram;

use anyhow::{bail, Context, Result};
use clap::Parser;
use config::{Config, SecretMode};
use crypto::{derive_keys, AesCtr};
use replay::ReplayCache;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};
use tracing::{debug, info};

#[derive(Parser)]
#[command(name = "mtproxy", about = "MTProto proxy server (obfuscation v2)")]
struct Cli {
    /// Path to TOML config file
    #[arg(short, long, default_value = "config.toml")]
    config: String,
}

struct State {
    secrets: HashMap<String, SecretMode>,
    replay: ReplayCache,
    prefer_ipv6: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("mtproxy=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();
    let raw = std::fs::read_to_string(&cli.config)
        .with_context(|| format!("reading config {}", cli.config))?;
    let cfg = Config::from_toml_str(&raw)?;
    let secrets = cfg.parsed_secrets()?;

    info!(
        listen = %cfg.listen,
        users = secrets.len(),
        "MTProxy starting"
    );

    let state = Arc::new(State {
        secrets,
        replay: ReplayCache::new(65536),
        prefer_ipv6: false,
    });

    let listener = TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;

    info!("Listening on {}", cfg.listen);

    loop {
        let (stream, peer) = listener.accept().await?;
        let state = Arc::clone(&state);
        let mask_host = cfg.mask_host.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, peer, state, mask_host).await {
                debug!(%peer, "connection closed: {e}");
            }
        });
    }
}

async fn handle(
    stream: TcpStream,
    peer: SocketAddr,
    state: Arc<State>,
    mask_host: String,
) -> Result<()> {
    stream.set_nodelay(true)?;

    // Peek at first byte to detect TLS ClientHello vs raw obfuscated data
    let mut first = [0u8; 1];
    stream.peek(&mut first).await?;

    if first[0] == 0x16 {
        handle_faketls(stream, peer, state).await
    } else {
        handle_obfuscated(stream, peer, state, mask_host).await
    }
}

/// Handle a raw obfuscated (non-TLS) connection.
async fn handle_obfuscated(
    mut stream: TcpStream,
    peer: SocketAddr,
    state: Arc<State>,
    _mask_host: String,
) -> Result<()> {
    let mut init = [0u8; 64];
    stream.read_exact(&mut init).await.context("read init")?;

    let (dec_key, dec_iv, enc_key, enc_iv, dc_id, _protocol) =
        try_secrets_obfuscated(&init, &state.secrets)?;

    // Replay check on pre_key[0..8]
    let token: [u8; 8] = init[8..16].try_into().unwrap();
    if state.replay.check_and_insert(token) {
        bail!("replay attack detected from {peer}");
    }

    info!(%peer, dc_id, "new obfuscated connection");

    let mut client_dec = AesCtr::new(&dec_key, &dec_iv);
    let client_enc = AesCtr::new(&enc_key, &enc_iv);

    // Advance decrypt keystream past the 64-byte init (already consumed from socket)
    let mut dummy = init;
    client_dec.apply(&mut dummy);

    let (tg_host, tg_port) = telegram::dc_addr(dc_id, state.prefer_ipv6);
    let tg = TcpStream::connect((tg_host, tg_port))
        .await
        .with_context(|| format!("connect to DC{dc_id} {tg_host}:{tg_port}"))?;
    tg.set_nodelay(true)?;

    proxy::pipe(stream, tg, client_dec, client_enc).await
}

/// Handle a FakeTLS connection.
async fn handle_faketls(
    mut stream: TcpStream,
    peer: SocketAddr,
    state: Arc<State>,
) -> Result<()> {
    let hello = fake_tls::read_client_hello(&mut stream)
        .await
        .context("read ClientHello")?;

    let (secret, domain, dc_id) = try_secrets_faketls(&hello, &state.secrets)?;

    // Replay check on random[0..8] inside the hello
    let token: [u8; 8] = hello[11..19].try_into().unwrap();
    if state.replay.check_and_insert(token) {
        bail!("replay attack detected from {peer}");
    }

    info!(%peer, dc_id, "new FakeTLS connection");

    fake_tls::send_server_hello(&mut stream, &domain).await?;

    let header = fake_tls::extract_obfuscation_header(&hello)?;
    let (dec_key, dec_iv, enc_key, enc_iv) = derive_keys(&header, &secret);
    let client_dec = AesCtr::new(&dec_key, &dec_iv);
    let client_enc = AesCtr::new(&enc_key, &enc_iv);

    let (tg_host, tg_port) = telegram::dc_addr(dc_id, state.prefer_ipv6);
    let tg = TcpStream::connect((tg_host, tg_port))
        .await
        .with_context(|| format!("connect to DC{dc_id} {tg_host}:{tg_port}"))?;
    tg.set_nodelay(true)?;

    proxy::pipe_faketls(stream, tg, client_dec, client_enc).await
}

// ---------------------------------------------------------------------------
// Secret matching helpers
// ---------------------------------------------------------------------------

fn try_secrets_obfuscated(
    init: &[u8; 64],
    secrets: &HashMap<String, SecretMode>,
) -> Result<([u8; 32], [u8; 16], [u8; 32], [u8; 16], i16, handshake::Protocol)> {
    for (_name, mode) in secrets {
        if let SecretMode::FakeTls { .. } = mode {
            continue;
        }

        let raw = mode.raw_secret();
        let (dec_key, dec_iv, enc_key, enc_iv) = derive_keys(init, raw);
        let mut buf = *init;
        let mut dec = AesCtr::new(&dec_key, &dec_iv);
        dec.apply(&mut buf);

        if let Ok(info) = handshake::parse_handshake(&buf) {
            if let SecretMode::Secure(_) = mode {
                if info.protocol != handshake::Protocol::Secure {
                    continue;
                }
            }
            return Ok((dec_key, dec_iv, enc_key, enc_iv, info.dc_id, info.protocol));
        }
    }
    bail!("no matching secret for obfuscated connection")
}

fn try_secrets_faketls(
    hello: &[u8],
    secrets: &HashMap<String, SecretMode>,
) -> Result<(Vec<u8>, String, i16)> {
    for (_name, mode) in secrets {
        if let SecretMode::FakeTls { secret, domain } = mode {
            if fake_tls::validate_hello_hmac(hello, secret).is_ok() {
                // Extract 64-byte header and parse DC id
                let dc_id = extract_faketls_dc_id(hello, secret).unwrap_or(1);
                return Ok((secret.clone(), domain.clone(), dc_id));
            }
        }
    }
    bail!("no matching FakeTLS secret")
}

fn extract_faketls_dc_id(hello: &[u8], secret: &[u8]) -> Result<i16> {
    if hello.len() < 76 {
        bail!("hello too short");
    }
    // Build 64-byte header: random(32) at hello[11..43] + session_id(32) at hello[44..76]
    let mut header = [0u8; 64];
    header[..32].copy_from_slice(&hello[11..43]);
    header[32..].copy_from_slice(&hello[44..76]);

    let (dec_key, dec_iv, _, _) = derive_keys(&header, secret);
    let mut buf = header;
    let mut dec = AesCtr::new(&dec_key, &dec_iv);
    dec.apply(&mut buf);

    let info = handshake::parse_handshake(&buf)?;
    Ok(info.dc_id)
}
