use clap::{Parser, Subcommand};
use iroh::{endpoint::presets, Endpoint, EndpointId};
use tracing::{info, warn};
use std::time::Duration;

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Run,
    Connect {
        endpoint_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let endpoint = Endpoint::builder(presets::N0)
        .bind()
        .await
        .map_err(|e| format!("Failed to bind: {}", e))?;

    let my_id = endpoint.id();

    info!(" Muspell Daemon started");
    info!("   My EndpointID : {}", my_id);

    match args.command {
        Commands::Run => {
            info!(" Listening mode - Share this ID:");
            info!("{}", my_id);

            // Simple accept loop using Iroh's recommended pattern
            loop {
                tokio::select! {
                    Some(incoming) = endpoint.accept() => {
                        tokio::spawn(async move {
                            let connecting = match incoming.accept() {
                                Ok(c) => c,
                                Err(e) => {
                                    warn!("Accept failed: {}", e);
                                    return;
                                }
                            };

                            match connecting.await {
                                Ok(conn) => {
                                    info!(" Connected from {}", conn.remote_id());
                                    // Just close for now - we'll add echo later
                                    conn.close(0u32.into(), b"ok");
                                }
                                Err(e) => warn!("Connection failed: {}", e),
                            }
                        });
                    }
                    _ = tokio::signal::ctrl_c() => {
                        info!("Shutting down...");
                        break;
                    }
                }
            }
        }

        Commands::Connect { endpoint_id } => {
            let peer_id: EndpointId = match endpoint_id.parse() {
                Ok(id) => id,
                Err(_) => {
                    warn!("Invalid EndpointID");
                    return Ok(());
                }
            };

            info!(" Connecting to {}", peer_id);

            let peer_addr = iroh::EndpointAddr::from(peer_id);

            // Use a very standard Iroh ALPN that should be accepted
            const ALPN: &[u8] = b"/iroh/0.1";

            match tokio::time::timeout(Duration::from_secs(45), endpoint.connect(peer_addr, ALPN)).await {
                Ok(Ok(conn)) => {
                    info!(" Connected successfully!");

                    let (mut send, mut recv) = match conn.open_bi().await {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("Failed to open stream: {}", e);
                            return Ok(());
                        }
                    };

                    let _ = send.write_all(b"Hi from the other side").await;
                    let _ = send.finish();

                    let mut buf = vec![0; 256];
                    if let Ok(Some(n)) = recv.read(&mut buf).await {
                        if n > 0 {
                            info!("Received: {}", String::from_utf8_lossy(&buf[0..n]));
                        }
                    }
                }
                Ok(Err(e)) => warn!("Connection failed: {}", e),
                Err(_) => warn!("Timed out trying to connect"),
            }
        }
    }

    Ok(())
}
