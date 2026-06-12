// Task supervision + bounded retry -- the auto-recovery.
use std::future::Future;
use std::time::{Duration, Instant};
use metrics::counter;
use tokio_util::sync::CancellationToken;
use tracing::{error, warn};

/// Run a long-lived fallible task, restarting it on `Err` with exponential
/// backoff (capped). Returns:
///   * `Ok(())`  -- the task returned `Ok` (graceful, e.g. on cancellation), or
///                  the cancel token fired during a backoff.
///   * `Err(..)` -- the task failed `max_consecutive_failures` times in a row
///                  without a healthy run; the caller should treat this as fatal.
///
/// The consecutive-failure counter resets after any run that lasted at least
/// `healthy_after`, so a transient fault days apart never accumulates to give-up.
pub async fn supervise<F, Fut>(
    name: &'static str,
    cancel: CancellationToken,
    max_consecutive_failures: u32,
    healthy_after: Duration,
    base_backoff: Duration,
    max_backoff: Duration,
    mut make: F,
) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    let mut backoff = base_backoff;
    let mut failures: u32 = 0;

    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }

        let started = Instant::now();
        match make().await {
            Ok(()) => return Ok(()),
            Err(e) => {
                // A long, healthy run before the fault clears the budget.
                if started.elapsed() >= healthy_after {
                    failures = 0;
                    backoff = base_backoff;
                }
                failures += 1;
                counter!("gateway.task_restarts", "task" => name).increment(1);
                warn!(task = name, failures, ?backoff, "task faulted: {e}; restarting");

                if failures >= max_consecutive_failures {
                    error!(task = name, failures, "exhausted restart budget -- fatal");
                    return Err(anyhow::anyhow!(
                        "{name}: {failures} consecutive failures without a healthy run"
                    ));
                }

                tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(max_backoff);
            }
        }
    }
}

/// Try `f` up to `attempts` times (>=1), sleeping `delay` between tries. Returns
/// `Some` on the first success, `None` if every attempt failed. Used to make a
/// non-critical dependency (Redis) a soft, retryable startup dependency instead
/// of a hard one that aborts boot.
pub async fn retry<T, E, F, Fut>(attempts: u32, delay: Duration, mut f: F) -> Option<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let attempts = attempts.max(1);
    for attempt in 1..=attempts {
        match f().await {
            Ok(v) => return Some(v),
            Err(e) => {
                warn!(attempt, attempts, "attempt failed: {e}");
                if attempt < attempts {
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn retry_succeeds_after_transient_failures() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let out = retry(5, Duration::from_millis(1), move || {
            let c = c.clone();
            async move {
                let n = c.fetch_add(1, Ordering::SeqCst) + 1;
                if n < 3 { Err("not yet") } else { Ok::<u32, &str>(n) }
            }
        })
        .await;
        assert_eq!(out, Some(3));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn retry_gives_up_after_all_attempts() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let out: Option<u32> = retry(3, Duration::from_millis(1), move || {
            let c = c.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Err::<u32, &str>("always")
            }
        })
        .await;
        assert_eq!(out, None);
        assert_eq!(calls.load(Ordering::SeqCst), 3, "must try exactly `attempts` times");
    }

    #[tokio::test]
    async fn supervise_restarts_until_a_healthy_run() {
        let cancel = CancellationToken::new();
        let runs = Arc::new(AtomicU32::new(0));
        let r = runs.clone();
        let inner_cancel = cancel.clone();

        let handle = tokio::spawn(supervise(
            "t",
            cancel.clone(),
            10,
            Duration::from_millis(50),
            Duration::from_millis(1),
            Duration::from_millis(5),
            move || {
                let r = r.clone();
                let inner_cancel = inner_cancel.clone();
                async move {
                    let n = r.fetch_add(1, Ordering::SeqCst) + 1;
                    if n < 3 {
                        anyhow::bail!("boom {n}");
                    }
                    // healthy long-runner: stay up until cancelled
                    inner_cancel.cancelled().await;
                    Ok(())
                }
            },
        ));

        tokio::time::sleep(Duration::from_millis(40)).await;
        cancel.cancel();
        let res = handle.await.unwrap();
        assert!(res.is_ok(), "graceful cancellation must yield Ok");
        assert!(runs.load(Ordering::SeqCst) >= 3, "must have restarted past the faulty runs");
    }

    #[tokio::test]
    async fn supervise_gives_up_after_budget() {
        let cancel = CancellationToken::new();
        let res = supervise(
            "t",
            cancel,
            3,
            Duration::from_secs(10),
            Duration::from_millis(1),
            Duration::from_millis(2),
            || async { anyhow::bail!("always fails") },
        )
        .await;
        assert!(res.is_err(), "must return Err once the restart budget is exhausted");
    }

    #[tokio::test]
    async fn supervise_stops_on_cancel_without_running() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let ran = Arc::new(AtomicU32::new(0));
        let r = ran.clone();
        let res = supervise(
            "t",
            cancel,
            3,
            Duration::from_millis(10),
            Duration::from_millis(1),
            Duration::from_millis(2),
            move || {
                let r = r.clone();
                async move {
                    r.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
        )
        .await;
        assert!(res.is_ok());
        assert_eq!(ran.load(Ordering::SeqCst), 0, "already-cancelled supervisor must not start the task");
    }
}
