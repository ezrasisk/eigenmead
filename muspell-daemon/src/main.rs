use clap::{Parser, Subcommand};
use iroh::{endpoint::presets, Endpoint, EndpointId, EndpointAddr};
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
    /// Start the daemon (listens for incoming connections)
    Run,

    /// Connect to another node by EndpointId (z32 format)
    Connect {
        /// EndpointId of the peer
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
        .map_err(|e| format!("Failed to bind endpoint: {}", e))?;

    let my_id = endpoint.id();

    info!(" Muspell Daemon started");
    info!("   My EndpointID : {}", my_id);

    let addr = endpoint.addr();
    info!("   Relay URLs    : {:?}", addr.relay_urls().collect::<Vec<_>>());
    info!("   Direct IPs    : {:?}", addr.ip_addrs().collect::<Vec<_>>());

    match args.command {
        Commands::Run => {
            info!(" Listening for incoming connections...");
            info!("   Share this command with the other machine:");
            info!("   cargo run -p muspell-daemon -- connect {}", my_id);

            // Simple accept loop - no custom ALPN
            while let Some(incoming) = endpoint.accept().await {
                let connecting = match incoming.accept() {
                    Ok(connecting) => connecting,
                    Err(e) => {
                        warn!("Failed to accept incoming: {}", e);
                        continue;
                    }
                };

                tokio::spawn(async move {
                    match connecting.await {
                        Ok(conn) => {
                            info!(" New connection from {}", conn.remote_id());
                            // Gracefully close
                            conn.close(0u32.into(), b"closed");
                        }
                        Err(e) => warn!("Failed to establish connection: {}", e),
                    }
                });
            }
        }

        Commands::Connect { endpoint_id } => {
            let peer_id: EndpointId = match endpoint_id.parse() {
                Ok(id) => id,
                Err(_) => {
                    warn!("Invalid EndpointID format");
                    return Ok(());
                }
            };

            info!(" Attempting to connect to {}", peer_id);

            let peer_addr = EndpointAddr::from(peer_id);

            // Use a standard Iroh ALPN (this is what most examples use)
            const DEFAULT_ALPN: &[u8] = b"/iroh/0.1";

            match tokio::time::timeout(
                Duration::from_secs(60),
                endpoint.connect(peer_addr, DEFAULT_ALPN),
            ).await {
                Ok(Ok(connection)) => {
                    info!(" Successfully connected to {}", peer_id);

                    let (mut send, mut recv) = match connection.open_bi().await {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("Failed to open stream: {}", e);
                            return Ok(());
                        }
                    };

                    if let Err(e) = send.write_all(b"Hello from the other machine!").await {
                        warn!("Failed to send message: {}", e);
                    }
                    let _ = send.finish();

                    info!(" Sent greeting");

                    let mut buf = vec![0u8; 512];
                    if let Ok(Some(n)) = recv.read(&mut buf).await {
                        if n > 0 {
                            info!(" Received: {}", String::from_utf8_lossy(&buf[0..n]));
                        }
                    }
                }
                Ok(Err(e)) => warn!(" Connection failed: {}", e),
                Err(_) => warn!(" Connection timed out after 60 seconds"),
            }
        }
    }

    Ok(())
}
