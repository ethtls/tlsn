use axum::{
    routing::{get, post},
    Router,
};
use tokio::signal;
use tracing_subscriber;
use http_body_util::{BodyExt, Empty};
use hyper::{body::Body, Method, Request, StatusCode};
use hyper::http::header::{CONTENT_TYPE, CONNECTION, USER_AGENT};
use hyper_util::rt::TokioIo;
use std::{env, ops::Range, str, net::SocketAddr};
use tlsn_core::proof::TlsProof;
use tlsn_examples::request_notarization;
use tokio::io::AsyncWriteExt as _;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;
use serde_json::json;

use tlsn_prover::tls::{Prover, ProverConfig};

// Setting of the application server
const SERVER_DOMAIN: &str = "127.0.0.1";

// Setting of the notary server — make sure these are the same with those in ../../../notary-server
const NOTARY_HOST: &str = "127.0.0.1";
const NOTARY_PORT: u16 = 7047;

// Configuration of notarization
const NOTARY_MAX_TRANSCRIPT_SIZE: usize = 16384;
// ---

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Define your application routes
    let app = Router::new()
        .route("/", get(root_handler))
        .route("/notarize", post(notarize_handler));

    // Set up the server address
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("listening on {}", addr);

    // Run the server and gracefully handle shutdown
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

async fn root_handler() -> &'static str {
    "Hello, Notary!"
}

async fn notarize_handler() -> String {
    notarize().await
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("failed to listen for event");
    };

    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    println!("signal received, starting graceful shutdown");
}

async fn notarize() -> String {

    dotenv::dotenv().ok();
    let avs_contract = env::var("AVSCONTRACT").unwrap();
    let avs_contract_topic = env::var("AVSCONTRACTTOPIC").unwrap();
    let user_agent = env::var("USER_AGENT").unwrap();

    let (notary_tls_socket, session_id) =
        request_notarization(NOTARY_HOST, NOTARY_PORT, Some(NOTARY_MAX_TRANSCRIPT_SIZE)).await;

    // Basic default prover config using the session_id returned from /session endpoint just now
    let config = ProverConfig::builder()
        .id(session_id)
        .server_dns(SERVER_DOMAIN)
        .build()
        .unwrap();

    // Create a new prover and set up the MPC backend.
    let prover = Prover::new(config)
        .setup(notary_tls_socket.compat())
        .await
        .unwrap();

    let client_socket = tokio::net::TcpStream::connect((SERVER_DOMAIN, 443))
        .await
        .unwrap();

    // Bind the Prover to server connection
    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();

    // Spawn the Prover to be run concurrently
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the TLS connection
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_connection.compat()))
            .await
            .unwrap();

    // Spawn the HTTP task to be run concurrently
    tokio::spawn(connection);

    // Build the HTTP request to fetch the lates event
    let data = json!({
        "jsonrpc": "2.0",
        "method": "eth_getLogs",
        "params": [{
            "fromBlock": "latest",
            "toBlock": "latest",
            "address": avs_contract.to_string(),
            "topics": [avs_contract_topic.to_string()]
        }],
        "id": 1
    }).to_string();

    let request: hyper::Request<String> = Request::builder()
        .method(Method::POST)
        // .version(hyper::Version::HTTP_2)
        .uri(format!(
            "https://{SERVER_DOMAIN}:8545/"
        ))
        .header("Host", SERVER_DOMAIN)
        .header("Accept", "*/*")
        .header(USER_AGENT, user_agent)
        .header(CONTENT_TYPE, "application/json")
        .header(CONNECTION, "keep-alive")
        .body(data.into())
        .unwrap();

    debug!("Sending request");

    let response = request_sender.send_request(request).await.unwrap();

    debug!("Sent request");

    assert!(response.status() == StatusCode::OK, "{}", response.status());

    debug!("Request OK");

    // The Prover task should be done now, so we can grab it.
    let prover = prover_task.await.unwrap().unwrap();

    // Prepare for notarization
    let mut prover = prover.start_notarize();

    // Identify the ranges in the transcript that contain secrets
    let (public_ranges, private_ranges) =
        find_ranges(prover.sent_transcript().data(), &[SERVER_DOMAIN.as_bytes()]);

    let recv_len = prover.recv_transcript().data().len();

    let builder = prover.commitment_builder();

    // Collect commitment ids for the outbound transcript
    let mut commitment_ids = public_ranges
        .iter()
        .chain(private_ranges.iter())
        .map(|range| builder.commit_sent(range).unwrap())
        .collect::<Vec<_>>();

    // Commit to the full received transcript in one shot, as we don't need to redact anything
    commitment_ids.push(builder.commit_recv(&(0..recv_len)).unwrap());

    // Finalize, returning the notarized session
    let notarized_session = prover.finalize().await.unwrap();

    debug!("Notarization complete!");

    let session_proof = notarized_session.session_proof();

    let mut proof_builder = notarized_session.data().build_substrings_proof();

    // Reveal everything but the auth token (which was assigned commitment id 2)
    proof_builder.reveal_by_id(commitment_ids[0]).unwrap();
    proof_builder.reveal_by_id(commitment_ids[1]).unwrap();
    proof_builder.reveal_by_id(commitment_ids[3]).unwrap();

    let substrings_proof = proof_builder.build().unwrap();

    let proof = TlsProof {
        session: session_proof,
        substrings: substrings_proof,
    };

    let signature = proof.session.signature;
    
    // serde_json::to_string_pretty(&proof).unwrap()
    serde_json::to_string_pretty(&signature).unwrap()
}

fn find_ranges(seq: &[u8], sub_seq: &[&[u8]]) -> (Vec<Range<usize>>, Vec<Range<usize>>) {
    let mut private_ranges = Vec::new();
    for s in sub_seq {
        for (idx, w) in seq.windows(s.len()).enumerate() {
            if w == *s {
                private_ranges.push(idx..(idx + w.len()));
            }
        }
    }

    let mut sorted_ranges = private_ranges.clone();
    sorted_ranges.sort_by_key(|r| r.start);

    let mut public_ranges = Vec::new();
    let mut last_end = 0;
    for r in sorted_ranges {
        if r.start > last_end {
            public_ranges.push(last_end..r.start);
        }
        last_end = r.end;
    }

    if last_end < seq.len() {
        public_ranges.push(last_end..seq.len());
    }

    (public_ranges, private_ranges)
}
