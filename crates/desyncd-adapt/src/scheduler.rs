//! Background scheduler for periodic re-testing.

use std::sync::Arc;

use tokio::time;
use tracing::{info, warn};

use crate::{search, AdaptEngine};

/// Run the adaptation scheduler as a background task.
///
/// Periodically re-tests configured domains and updates strategies.
pub async fn run_scheduler(engine: Arc<AdaptEngine>) {
    if !engine.config.enabled {
        info!("adaptation scheduler disabled");
        return;
    }

    if engine.config.test_domains.is_empty() {
        info!("no test domains configured, scheduler idle");
        return;
    }

    let interval = engine.config.test_interval();
    info!(
        interval_secs = interval.as_secs(),
        domains = ?engine.config.test_domains,
        "adaptation scheduler started"
    );

    let mut ticker = time::interval(interval);
    // Skip the first immediate tick — give the system time to start up.
    ticker.tick().await;

    loop {
        ticker.tick().await;

        for domain in &engine.config.test_domains {
            info!(%domain, "scheduler: running adaptation probe");

            match search::find_best_strategy(&engine, domain).await {
                Ok(result) => {
                    if let Some(ref strategy) = result.best_strategy {
                        info!(
                            %domain,
                            strategy = %strategy.name,
                            score = result.best_score,
                            probes = result.probes.len(),
                            "scheduler: strategy updated"
                        );
                    } else {
                        info!(%domain, "scheduler: domain not blocked or no strategy found");
                    }
                }
                Err(e) => {
                    warn!(%domain, error = %e, "scheduler: adaptation failed");
                }
            }

            // Rate limit between domains.
            time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }
}
