use clap::{Parser, Subcommand};
use iroh::{endpoint::presets, Endpoint, EndpointId, EndpointAddr};
use tracing::{info, warn};

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
        /// EndpointId of the peer (z32 string)
        endpoint_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    // Create endpoint with the standard N0 preset (includes relay + discovery)
    let endpoint = Endpoint::builder(presets::N0)
        .bind()
        .await
        .map_err(|e| format!("Failed to bind Iroh endpoint: {}", e))?;

    let my_id = endpoint.id();

    info!(" Muspell Daemon started");
    info!("   My EndpointID : {}", my_id);

    // Show addressing info (without Debug issues)
    let addr = endpoint.addr();
    info!("   Relay URLs    : {:?}", addr.relay_urls().collect::<Vec<_>>());
    info!("   Direct IPs    : {:?}", addr.ip_addrs().collect::<Vec<_>>());

    match args.command {
        Commands::Run => {
            info!("Running in daemon mode — waiting for incoming connections...");
            info!("Share your EndpointID with others so they can connect.");

            // Keep the program alive
            tokio::signal::ctrl_c().await?;
            info!("Shutting down...");
        }

        Commands::Connect { endpoint_id } => {
            let peer_id: EndpointId = endpoint_id.parse()
                .map_err(|_| "Invalid EndpointID format. Must be a valid z32 string.")?;

            info!("Attempting to connect to {}", peer_id);

            // Convert EndpointId to EndpointAddr (required in 0.97+)
            let peer_addr = EndpointAddr::from(peer_id);

            // Connect requires an ALPN protocol (byte slice) to identify the application
            // We'll use a simple custom ALPN for this minimal example
            const ALPN: &[u8] = b"muspell/0.1";

            match endpoint.connect(peer_addr, ALPN).await {
                Ok(connection) => {
                    info!("Successfully connected to {}", peer_id);

                    // Open a bidirectional stream
                    let (mut send, mut recv) = connection.open_bi().await?;

                    // Send a simple greeting
                    send.write_all(b"Hello from Muspell Daemon!").await?;
                    send.finish()?;

                    info!("Sent greeting message");

                    // Optional: read any response
                    let mut buf = vec![0u8; 1024];
                    if let Ok(Some(n)) = recv.read(&mut buf).await {
                        if n > 0 {
                            info!("Received: {}", String::from_utf8_lossy(&buf[..n]));
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to connect: {}", e);
                }
            }
        }
    }

    Ok(())
}
