use async_nats::jetstream;
use bytes::Bytes;
use futures::StreamExt;
use metrics::{counter, histogram};
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{error, info, warn};

pub trait ParquetWorker: Send + Sync {
    fn batch_size(&self) -> usize;

    fn transmit_batch(
        &self,
        payloads: Vec<(Bytes, Option<async_nats::HeaderMap>)>,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send;
}

/// Authenticated NATS connect — the central NATS cluster runs default-deny
/// authorization. Credentials come from NATS_USER / NATS_PASS (middleware_node
/// user provisioned via the middleware Quadlet env). Anonymous fallback for dev.
pub async fn nats_connect(url: &str) -> Result<async_nats::Client, async_nats::ConnectError> {
    let user = std::env::var("NATS_USER").unwrap_or_default();
    let pass = std::env::var("NATS_PASS").unwrap_or_default();
    if !user.is_empty() && !pass.is_empty() {
        async_nats::ConnectOptions::with_user_and_password(user, pass)
            .connect(url)
            .await
    } else {
        async_nats::connect(url).await
    }
}

pub async fn start_worker<W: ParquetWorker + 'static>(
    worker: W,
    nats_url: &str,
    stream_name: &str,
    subject_filter: &str,
    consumer_name: &str,
    dlq_prefix: &str,
) {
    let client = nats_connect(nats_url).await
        .unwrap_or_else(|e| { error!("NATS connect failed: {}", e); std::process::exit(1); });
    let js = jetstream::new(client.clone());

    let stream = js.get_or_create_stream(jetstream::stream::Config {
        name: stream_name.to_string(),
        subjects: vec![subject_filter.to_string()],
        ..Default::default()
    }).await.unwrap_or_else(|e| { error!("Stream bind failed: {}", e); std::process::exit(1); });

    let dlq_wildcard = format!("{}.>", dlq_prefix);
    let dlq_stream = format!("{}_DLQ", stream_name);
    if let Err(e) = js.get_or_create_stream(jetstream::stream::Config {
        name: dlq_stream, subjects: vec![dlq_wildcard], ..Default::default()
    }).await {
        warn!("DLQ stream creation failed (non-fatal): {}", e);
    }

    let consumer = stream.get_or_create_consumer(consumer_name,
        jetstream::consumer::pull::Config {
            durable_name: Some(consumer_name.to_string()),
            filter_subject: subject_filter.to_string(),
            ack_wait: Duration::from_secs(90),
            max_deliver: 5,
            ..Default::default()
        }).await.unwrap_or_else(|e| { error!("Consumer bind failed: {}", e); std::process::exit(1); });

    info!("Worker '{}' online on stream '{}'", consumer_name, stream_name);

    let js_dlq = jetstream::new(client);
    let batch_limit = worker.batch_size();
    let dlq_subject = format!("{}.{}", dlq_prefix, consumer_name.to_lowercase());
    let mut circuit_open = false;

    // Signal channel: background task forwards SIGTERM/SIGINT.
    // The tokio::select! biased+sleep(Duration::ZERO) pattern can stall in
    // containers; a watch channel guarantees the signal is delivered and the
    // fetch loop receives messages without blocking indefinitely.
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let mut st = signal(SignalKind::terminate()).expect("sigterm");
        let mut si = signal(SignalKind::interrupt()).expect("sigint");
        tokio::select! { _ = st.recv() => {}, _ = si.recv() => {} }
        let _ = shutdown_tx.send(true);
    });

    loop {
        if *shutdown_rx.borrow() {
            info!("Shutdown signal received. Draining."); break;
        }

        if circuit_open {
            warn!("Circuit breaker: pausing 30s");
            counter!("middleware_worker_circuit_breaker_trips_total").increment(1);
            tokio::time::sleep(Duration::from_secs(30)).await;
            circuit_open = false;
        }

        let mut batch_payloads: Vec<(Bytes, Option<async_nats::HeaderMap>)> = Vec::with_capacity(batch_limit);
        let mut raw_messages = Vec::with_capacity(batch_limit);
        let pull_start = std::time::Instant::now();

        // fetch() with explicit expiry -- avoids consumer.messages() expires:None
        // which holds the server-side fetch open until max_messages arrive and
        // starves low-volume workers indefinitely.
        let fetched = match consumer
            .fetch()
            .max_messages(batch_limit)
            .expires(Duration::from_secs(5))
            .messages()
            .await
        {
            Ok(m) => m,
            Err(e) => { warn!("Fetch failed: {}", e); tokio::time::sleep(Duration::from_millis(500)).await; continue; }
        };

        let mut msgs = fetched;
        loop {
            if *shutdown_rx.borrow() { break; }
            tokio::select! {
                msg = msgs.next() => {
                    match msg {
                        Some(Ok(msg)) => {
                            counter!("middleware_worker_messages_pulled_total").increment(1);
                            batch_payloads.push((msg.payload.clone(), msg.headers.clone()));
                            raw_messages.push(msg);
                            if raw_messages.len() >= batch_limit { break; }
                        }
                        Some(Err(e)) => { warn!("Stream error: {}", e); break; }
                        None => { break; } // fetch exhausted (timeout or max_messages)
                    }
                }
            }
        }

        if raw_messages.is_empty() { continue; }
        histogram!("middleware_worker_batch_accumulation_seconds").record(pull_start.elapsed().as_secs_f64());

        let mut success = false;
        let max_attempts: u32 = 5;

        for attempt in 1..=max_attempts {
            let tx_start = std::time::Instant::now();
            match worker.transmit_batch(batch_payloads.clone()).await {
                Ok(_) => {
                    histogram!("middleware_worker_transmission_latency_seconds").record(tx_start.elapsed().as_secs_f64());
                    success = true;
                    for msg in &raw_messages { let _ = msg.ack().await; }
                    counter!("middleware_worker_messages_acked_total").increment(raw_messages.len() as u64);
                    info!("Flushed {} payloads", raw_messages.len());
                    break;
                }
                Err(e) => {
                    counter!("middleware_worker_transmission_retries_total").increment(1);
                    warn!("Attempt {}/{}: {}", attempt, max_attempts, e);
                    if attempt < max_attempts {
                        tokio::time::sleep(Duration::from_secs(2u64.pow(attempt))).await;
                    }
                }
            }
        }

        if !success {
            counter!("middleware_worker_transmission_failures_total").increment(1);
            error!("Batch failed {} attempts. DLQ routing.", max_attempts);
            for msg in &raw_messages {
                if let Err(e) = js_dlq.publish(dlq_subject.clone(), msg.payload.clone()).await {
                    error!("DLQ publish failed: {}", e);
                } else {
                    let _ = msg.ack().await;
                }
            }
            counter!("middleware_worker_dlq_routed_total").increment(1);
            circuit_open = true;
        }
    }
    info!("Worker shutdown complete.");
}
