//! Load generator for the /v1/sign endpoint.
//!
//! Produces throughput + latency percentiles (p50/p95/p99) using HDR
//! histograms with a fixed number of concurrent "virtual users" each
//! firing requests back-to-back for the configured duration.

mod alloc_counter;

#[global_allocator]
static ALLOC: alloc_counter::CountingAllocator = alloc_counter::CountingAllocator;

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::Parser;
use futures::future::join_all;
use hdrhistogram::Histogram;
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

#[derive(Parser, Debug)]
#[command(version, about = "Signing service load generator")]
struct Args {
    /// Target URL for POST /v1/sign.
    #[arg(long, default_value = "http://127.0.0.1:8080/v1/sign")]
    url: String,
    /// Concurrency levels to test (comma-separated).
    #[arg(long, default_value = "1,10,100,500")]
    concurrencies: String,
    /// Duration (seconds) per level.
    #[arg(long, default_value_t = 15)]
    duration_secs: u64,
    /// Warmup (seconds) per level.
    #[arg(long, default_value_t = 2)]
    warmup_secs: u64,
    /// Key id to sign under.
    #[arg(long, default_value = "demo-ecdsa")]
    key_id: String,
    /// Payload size in bytes.
    #[arg(long, default_value_t = 128)]
    payload_bytes: usize,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let args = Args::parse();

    let levels: Vec<usize> = args
        .concurrencies
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    println!("# target        : {}", args.url);
    println!(
        "# duration/lvl  : {}s (warmup {}s)",
        args.duration_secs, args.warmup_secs
    );
    println!("# payload bytes : {}", args.payload_bytes);
    println!();
    println!(
        "{:>7} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>12}",
        "conc", "rps", "p50_ms", "p95_ms", "p99_ms", "max_ms", "err%", "allocs/op", "bytes/op"
    );

    let payload = B64.encode(vec![0xAB_u8; args.payload_bytes]);
    let body = serde_json::json!({
        "key_id": args.key_id,
        "algorithm": "ECDSA_P256_SHA256",
        "payload": payload,
    })
    .to_string();

    for conc in levels {
        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(conc * 2)
            .tcp_nodelay(true)
            .http1_only() // simpler latency accounting
            .timeout(Duration::from_secs(10))
            .build()?;

        // Warmup
        run_level(
            &client,
            &args.url,
            &body,
            conc,
            Duration::from_secs(args.warmup_secs),
            true,
        )
        .await?;

        let report = run_level(
            &client,
            &args.url,
            &body,
            conc,
            Duration::from_secs(args.duration_secs),
            false,
        )
        .await?;
        println!(
            "{:>7} {:>10.0} {:>10.2} {:>10.2} {:>10.2} {:>10.2} {:>10.2} {:>10.0} {:>12.0}",
            conc,
            report.rps,
            report.p50,
            report.p95,
            report.p99,
            report.max,
            report.err_pct,
            report.allocs_per_op,
            report.bytes_per_op
        );
    }
    Ok(())
}

struct Report {
    rps: f64,
    p50: f64,
    p95: f64,
    p99: f64,
    max: f64,
    err_pct: f64,
    allocs_per_op: f64,
    bytes_per_op: f64,
}

async fn run_level(
    client: &reqwest::Client,
    url: &str,
    body: &str,
    concurrency: usize,
    duration: Duration,
    warmup: bool,
) -> Result<Report> {
    let hist = Arc::new(Mutex::new(Histogram::<u64>::new_with_bounds(
        1, 60_000_000, 3,
    )?));
    let ok = Arc::new(AtomicU64::new(0));
    let err = Arc::new(AtomicU64::new(0));
    alloc_counter::CountingAllocator::reset();
    let stop_at = Instant::now() + duration;

    let tasks: Vec<_> = (0..concurrency)
        .map(|_| {
            let client = client.clone();
            let url = url.to_owned();
            let body = body.to_owned();
            let hist = hist.clone();
            let ok = ok.clone();
            let err = err.clone();
            tokio::spawn(async move {
                while Instant::now() < stop_at {
                    let t0 = Instant::now();
                    let res = client
                        .post(&url)
                        .header("content-type", "application/json")
                        .body(body.clone())
                        .send()
                        .await;
                    let dt_us = t0.elapsed().as_micros() as u64;
                    match res {
                        Ok(r) if r.status().is_success() => {
                            ok.fetch_add(1, Ordering::Relaxed);
                            let _ = hist.lock().unwrap().record(dt_us);
                        }
                        _ => {
                            err.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            })
        })
        .collect();
    join_all(tasks).await;

    let ok = ok.load(Ordering::Relaxed);
    let err = err.load(Ordering::Relaxed);
    let total = ok + err;
    let h = hist.lock().unwrap();
    let p50 = h.value_at_quantile(0.50) as f64 / 1000.0;
    let p95 = h.value_at_quantile(0.95) as f64 / 1000.0;
    let p99 = h.value_at_quantile(0.99) as f64 / 1000.0;
    let max = h.max() as f64 / 1000.0;
    let rps = ok as f64 / duration.as_secs_f64();
    let err_pct = if total == 0 {
        0.0
    } else {
        (err as f64 / total as f64) * 100.0
    };
    let (allocs, bytes) = alloc_counter::CountingAllocator::snapshot();
    let allocs_per_op = if total > 0 {
        allocs as f64 / total as f64
    } else {
        0.0
    };
    let bytes_per_op = if total > 0 {
        bytes as f64 / total as f64
    } else {
        0.0
    };
    if warmup {
        tracing::info!(concurrency, rps, p99, "warmup done");
    }
    Ok(Report {
        rps,
        p50,
        p95,
        p99,
        max,
        err_pct,
        allocs_per_op,
        bytes_per_op,
    })
}
