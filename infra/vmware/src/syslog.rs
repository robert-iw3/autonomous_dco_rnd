// Minimal syslog ingestion for VMware sources.
//
// Transports:
//   * TCP, non-transparent (LF-delimited) framing -- the common mode for
//     NSX-T / vCenter forwarding to a collector. A leading RFC6587
//     octet-count prefix ("<len> ") is tolerated and stripped.
//   * UDP (optional) -- one datagram per message; typical for ESXi.

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc::Sender;

pub async fn serve_tcp(bind: String, tx: Sender<String>) -> std::io::Result<()> {
    let listener = TcpListener::bind(&bind).await?;
    tracing::info!("Syslog TCP listener bound on {}", bind);

    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!("TCP accept failed: {}", e);
                continue;
            }
        };
        let tx = tx.clone();
        tokio::spawn(async move {
            tracing::debug!("Syslog connection from {}", peer);
            let reader = BufReader::new(socket);
            let mut lines = reader.lines();
            loop {
                match lines.next_line().await {
                    Ok(Some(line)) => {
                        let msg = strip_octet_count(line.trim_end_matches('\r'));
                        if !msg.is_empty() && tx.send(msg).await.is_err() {
                            return; // batcher gone
                        }
                    }
                    Ok(None) => return, // peer closed
                    Err(e) => {
                        tracing::warn!("Read error from {}: {}", peer, e);
                        return;
                    }
                }
            }
        });
    }
}

pub async fn serve_udp(bind: String, tx: Sender<String>) -> std::io::Result<()> {
    let socket = UdpSocket::bind(&bind).await?;
    tracing::info!("Syslog UDP listener bound on {}", bind);
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, _peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("UDP recv failed: {}", e);
                continue;
            }
        };
        let line = String::from_utf8_lossy(&buf[..n]).trim().to_string();
        let msg = strip_octet_count(&line);
        if !msg.is_empty() && tx.send(msg).await.is_err() {
            return Ok(());
        }
    }
}

fn strip_octet_count(line: &str) -> String {
    if let Some(sp) = line.find(' ') {
        let (head, rest) = line.split_at(sp);
        if !head.is_empty() && head.bytes().all(|b| b.is_ascii_digit()) {
            return rest.trim_start().to_string();
        }
    }
    line.to_string()
}