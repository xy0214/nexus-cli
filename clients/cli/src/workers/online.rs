//! Online Workers
//!
//! Handles network-dependent operations including:
//! - Task fetching from the orchestrator
//! - Proof submission to the orchestrator
//! - Network error handling with exponential backoff

use crate::analytics::{
    track_got_task, track_proof_accepted, track_proof_submission_error,
    track_proof_submission_success,
};
use crate::consts::prover::{
    BACKOFF_DURATION, ERR_BACKOFF_DURATION, LOW_WATER_MARK, QUEUE_LOG_INTERVAL, TASK_QUEUE_SIZE,
};
use crate::environment::Environment;
use crate::error_classifier::{ErrorClassifier, LogLevel};
use crate::events::Event;
use crate::orchestrator::Orchestrator;
use crate::orchestrator::error::OrchestratorError;
use crate::task::Task;
use crate::task_cache::TaskCache;
use ed25519_dalek::{SigningKey, VerifyingKey};
use nexus_sdk::stwo::seq::Proof;
use sha3::{Digest, Keccak256};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

/// Result of a proof generation, including combined hash for multiple inputs
pub struct ProofResult {
    pub proof: Proof,
    pub combined_hash: String,
}

/// Helper to send events with consistent error handling
async fn send_event(
    event_sender: &mpsc::Sender<Event>,
    message: String,
    event_type: crate::events::EventType,
    log_level: LogLevel,
) {
    let _ = event_sender
        .send(Event::task_fetcher_with_level(
            message, event_type, log_level,
        ))
        .await;
}

/// Helper to send proof submission events with consistent error handling
async fn send_proof_event(
    event_sender: &mpsc::Sender<Event>,
    message: String,
    event_type: crate::events::EventType,
    log_level: LogLevel,
) {
    let _ = event_sender
        .send(Event::proof_submitter_with_level(
            message, event_type, log_level,
        ))
        .await;
}

// =============================================================================
// TASK FETCH STATE
// =============================================================================

/// State for managing task fetching behavior with smart backoff and timing
pub struct TaskFetchState {
    last_fetch_time: std::time::Instant,
    backoff_duration: Duration,
    last_queue_log_time: std::time::Instant,
    queue_log_interval: Duration,
    pub error_classifier: ErrorClassifier,
}

impl TaskFetchState {
    pub fn new() -> Self {
        Self {
            last_fetch_time: std::time::Instant::now()
                - Duration::from_millis(BACKOFF_DURATION + 1000), // Allow immediate first fetch
            backoff_duration: Duration::from_millis(BACKOFF_DURATION), // Start with 120 second backoff
            last_queue_log_time: std::time::Instant::now(),
            queue_log_interval: Duration::from_millis(QUEUE_LOG_INTERVAL), // Log queue status every 30 seconds
            error_classifier: ErrorClassifier::new(),
        }
    }

    // =========================================================================
    // QUERY METHODS
    // =========================================================================

    /// Check if it's time to log queue status
    pub fn should_log_queue_status(&self) -> bool {
        self.last_queue_log_time.elapsed() >= self.queue_log_interval
    }

    /// Check if enough time has passed since last fetch attempt (respects backoff)
    pub fn can_fetch_now(&self) -> bool {
        self.last_fetch_time.elapsed() >= self.backoff_duration
    }

    /// Get current backoff duration
    pub fn backoff_duration(&self) -> Duration {
        self.backoff_duration
    }

    /// Get time since last fetch attempt
    pub fn time_since_last_fetch(&self) -> Duration {
        self.last_fetch_time.elapsed()
    }

    /// Check if we should fetch tasks (combines queue level and backoff timing)
    pub fn should_fetch(&self, tasks_in_queue: usize) -> bool {
        tasks_in_queue < LOW_WATER_MARK && self.can_fetch_now()
    }

    // =========================================================================
    // MUTATION METHODS
    // =========================================================================

    /// Record that a fetch attempt was made (updates timing)
    pub fn record_fetch_attempt(&mut self) {
        self.last_fetch_time = std::time::Instant::now();
    }

    /// Record that queue status was logged (updates timing)
    pub fn record_queue_log(&mut self) {
        self.last_queue_log_time = std::time::Instant::now();
    }

    /// Reset backoff to default duration (after successful operation)
    pub fn reset_backoff(&mut self) {
        self.backoff_duration = Duration::from_millis(BACKOFF_DURATION);
    }

    /// Set backoff duration from server's Retry-After header (in seconds)
    /// Respects server's exact timing for rate limit compliance
    pub fn set_backoff_from_server(&mut self, retry_after_seconds: u32) {
        self.backoff_duration = Duration::from_secs(retry_after_seconds as u64);
    }

    /// Increase backoff duration for error handling (exponential backoff)
    pub fn increase_backoff_for_error(&mut self) {
        self.backoff_duration = std::cmp::min(
            self.backoff_duration * 1,
            Duration::from_millis(ERR_BACKOFF_DURATION * 1),
        );
    }
}

/// Simple task fetcher: get one task at a time when queue is low.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_prover_tasks(
    node_id: u64,
    verifying_key: VerifyingKey,
    orchestrator_client: Box<dyn Orchestrator>,
    sender: mpsc::Sender<Task>,
    event_sender: mpsc::Sender<Event>,
    mut shutdown: broadcast::Receiver<()>,
    recent_tasks: TaskCache,
    environment: Environment,
    client_id: String,
) {
    let mut state = TaskFetchState::new();

    loop {
        tokio::select! {
            _ = shutdown.recv() => break,
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                let tasks_in_queue = TASK_QUEUE_SIZE - sender.capacity();

                // Log queue status periodically
                if state.should_log_queue_status() {
                    state.record_queue_log();
                    log_queue_status(&event_sender, tasks_in_queue, &state).await;
                }

                // Simple condition: fetch when queue is low and backoff time has passed
                if state.should_fetch(tasks_in_queue) {
                    if let Err(should_return) = fetch_single_task(
                        &*orchestrator_client,
                        &node_id,
                        verifying_key,
                        &sender,
                        &event_sender,
                        &recent_tasks,
                        &mut state,
                        &environment,
                        &client_id,
                    ).await {
                        if should_return {
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// Handle successful task fetch: duplicate check, caching, and queue management
async fn handle_task_success(
    task: Task,
    sender: &mpsc::Sender<Task>,
    event_sender: &mpsc::Sender<Event>,
    recent_tasks: &TaskCache,
    state: &mut TaskFetchState,
    environment: &Environment,
    client_id: &str,
) -> Result<(), bool> {
    // Check for duplicate
    if recent_tasks.contains(&task.task_id).await {
        handle_duplicate_task(event_sender, state).await;
        return Ok(());
    }

    // Process the new task
    process_new_task(
        task,
        sender,
        event_sender,
        recent_tasks,
        state,
        environment,
        client_id,
    )
    .await
}

/// Handle duplicate task detection
async fn handle_duplicate_task(event_sender: &mpsc::Sender<Event>, state: &mut TaskFetchState) {
    state.increase_backoff_for_error();
    send_event(
        event_sender,
        format!(
            "Task was duplicate - backing off for {}s",
            state.backoff_duration().as_secs()
        ),
        crate::events::EventType::Refresh,
        LogLevel::Warn,
    )
    .await;
}

/// Process a new (non-duplicate) task: cache, queue, analytics, and logging
async fn process_new_task(
    task: Task,
    sender: &mpsc::Sender<Task>,
    event_sender: &mpsc::Sender<Event>,
    recent_tasks: &TaskCache,
    state: &mut TaskFetchState,
    environment: &Environment,
    client_id: &str,
) -> Result<(), bool> {
    // Add to cache and queue
    recent_tasks.insert(task.task_id.clone()).await;

    if sender.send(task.clone()).await.is_err() {
        send_event(
            event_sender,
            "Task queue is closed".to_string(),
            crate::events::EventType::Shutdown,
            LogLevel::Error,
        )
        .await;
        return Err(true); // Signal shutdown
    }

    // Track analytics (non-blocking)
    tokio::spawn(track_got_task(
        task,
        environment.clone(),
        client_id.to_string(),
    ));

    // Success: reset backoff and log queue status
    state.reset_backoff();
    log_successful_task_addition(sender, event_sender).await;

    Ok(())
}

/// Log successful task addition with queue status
async fn log_successful_task_addition(
    sender: &mpsc::Sender<Task>,
    event_sender: &mpsc::Sender<Event>,
) {
    let current_queue_level = TASK_QUEUE_SIZE - sender.capacity();
    let queue_percentage = (current_queue_level as f64 / TASK_QUEUE_SIZE as f64 * 100.0) as u32;

    send_event(
        event_sender,
        format!(
            "Queue status: +1 task → {} total ({}% full)",
            current_queue_level, queue_percentage
        ),
        crate::events::EventType::Refresh,
        if queue_percentage >= 80 {
            LogLevel::Info
        } else {
            LogLevel::Debug
        },
    )
    .await;
}

/// Handle fetch timeout with backoff and logging
async fn handle_fetch_timeout(
    timeout_duration: Duration,
    event_sender: &mpsc::Sender<Event>,
    state: &mut TaskFetchState,
) {
    state.increase_backoff_for_error();
    send_event(
        event_sender,
        format!("Fetch timeout after {}s", timeout_duration.as_secs()),
        crate::events::EventType::Error,
        LogLevel::Warn,
    )
    .await;
}

/// Perform task fetch with timeout
async fn fetch_task_with_timeout(
    orchestrator_client: &dyn Orchestrator,
    node_id: &u64,
    verifying_key: VerifyingKey,
    timeout_duration: Duration,
) -> Result<Result<Task, OrchestratorError>, tokio::time::error::Elapsed> {
    let node_id_str = node_id.to_string();
    let fetch_future = orchestrator_client.get_proof_task(&node_id_str, verifying_key);
    tokio::time::timeout(timeout_duration, fetch_future).await
}

/// Simple task fetcher: get one task, prove, submit - perfect 1-2-3 flow
#[allow(clippy::too_many_arguments)]
async fn fetch_single_task(
    orchestrator_client: &dyn Orchestrator,
    node_id: &u64,
    verifying_key: VerifyingKey,
    sender: &mpsc::Sender<Task>,
    event_sender: &mpsc::Sender<Event>,
    recent_tasks: &TaskCache,
    state: &mut TaskFetchState,
    environment: &Environment,
    client_id: &str,
) -> Result<(), bool> {
    // Record fetch attempt and send initial event
    state.record_fetch_attempt();

    send_event(
        event_sender,
        "[Task step 1 of 3] Fetching task... Note: CLI tasks are harder to solve, so they receive more points than web provers".to_string(),
        crate::events::EventType::Refresh,
        LogLevel::Info,
    ).await;

    // Fetch task with timeout
    let timeout_duration = Duration::from_secs(60);
    match fetch_task_with_timeout(
        orchestrator_client,
        node_id,
        verifying_key,
        timeout_duration,
    )
    .await
    {
        Ok(fetch_result) => match fetch_result {
            Ok(task) => {
                handle_task_success(
                    task,
                    sender,
                    event_sender,
                    recent_tasks,
                    state,
                    environment,
                    client_id,
                )
                .await
            }
            Err(e) => {
                handle_fetch_error(e, event_sender, state).await;
                Ok(())
            }
        },
        Err(_timeout) => {
            handle_fetch_timeout(timeout_duration, event_sender, state).await;
            Ok(())
        }
    }
}

/// Log the current queue status with timing information
async fn log_queue_status(
    event_sender: &mpsc::Sender<Event>,
    tasks_in_queue: usize,
    state: &TaskFetchState,
) {
    let time_since_last = state.time_since_last_fetch();
    let backoff_duration = state.backoff_duration();
    let backoff_secs = backoff_duration.as_secs();

    let message = if state.should_fetch(tasks_in_queue) {
        format!(
            "Tasks Queue low: {} tasks to compute, ready to fetch",
            tasks_in_queue
        )
    } else {
        let time_since_secs = time_since_last.as_secs();
        format!(
            "Tasks to compute: {} tasks, waiting {}s more (retry every {}s)",
            tasks_in_queue,
            backoff_secs.saturating_sub(time_since_secs),
            backoff_secs
        )
    };

    send_event(
        event_sender,
        message,
        crate::events::EventType::Refresh,
        LogLevel::Debug,
    )
    .await;
}

/// Handle fetch errors with appropriate backoff
async fn handle_fetch_error(
    error: OrchestratorError,
    event_sender: &mpsc::Sender<Event>,
    state: &mut TaskFetchState,
) {
    match error {
        OrchestratorError::Http {
            status: 429,
            ref headers,
            ..
        } => {
            // Debug: print headers for 429 responses
            send_event(
                event_sender,
                format!("429 Rate limit retry-after: {:?}", headers.get("retry-after")),
                crate::events::EventType::Refresh,
                LogLevel::Debug,
            )
            .await;

            if let Some(retry) = error.get_retry_after_seconds() {
                let retry_after_seconds = if retry == 0 { 120 } else { retry }; // todo retry_after_seconds default 60s
                state.set_backoff_from_server(retry_after_seconds);
                send_event(
                    event_sender,
                    format!("Rate limited - retrying in {}s", retry_after_seconds),
                    crate::events::EventType::Error,
                    LogLevel::Warn,
                )
                .await;
            } else {
                // This shouldn't happen with a properly configured server
                state.increase_backoff_for_error();
                send_event(
                    event_sender,
                    "Rate limited - no retry time specified".to_string(),
                    crate::events::EventType::Error,
                    LogLevel::Error,
                )
                .await;
            }
        }
        _ => {
            state.increase_backoff_for_error();
            let log_level = state.error_classifier.classify_fetch_error(&error);
            let event = Event::task_fetcher_with_level(
                format!(
                    "Failed to fetch task: {}, retrying in {} seconds",
                    error,
                    state.backoff_duration().as_secs()
                ),
                crate::events::EventType::Error,
                log_level,
            );
            if event.should_display() {
                let _ = event_sender.send(event).await;
            }
        }
    }
}

/// Submits proofs to the orchestrator
#[allow(clippy::too_many_arguments)]
pub async fn submit_proofs(
    signing_key: SigningKey,
    orchestrator: Box<dyn Orchestrator>,
    num_workers: usize,
    mut results: mpsc::Receiver<(Task, ProofResult)>,
    event_sender: mpsc::Sender<Event>,
    mut shutdown: broadcast::Receiver<()>,
    completed_tasks: TaskCache,
    environment: Environment,
    client_id: String,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                maybe_item = results.recv() => {
                    match maybe_item {
                        Some((task, proof_result)) => {
                            process_proof_submission(
                                task,
                                proof_result.proof,
                                proof_result.combined_hash,
                                &*orchestrator,
                                &signing_key,
                                num_workers,
                                &event_sender,
                                &completed_tasks,
                                &environment,
                                &client_id,
                            ).await;
                        }
                        None => break,
                    }
                }

                _ = shutdown.recv() => break,
            }
        }
    })
}

/// Check if task was already submitted (successfully or failed)
async fn check_duplicate_submission(
    task: &Task,
    submitted_tasks: &TaskCache,
    event_sender: &mpsc::Sender<Event>,
) -> bool {
    if submitted_tasks.contains(&task.task_id).await {
        let msg = format!(
            "Ignoring proof for previously processed task {}",
            task.task_id
        );
        send_proof_event(
            event_sender,
            msg,
            crate::events::EventType::Error,
            LogLevel::Warn,
        )
        .await;
        return true; // Is duplicate
    }
    false // Not duplicate
}

/// Generate proof hash from combined hash or by computing from proof
fn generate_proof_hash(proof: &Proof, combined_hash: String) -> String {
    if !combined_hash.is_empty() {
        combined_hash
    } else {
        // Serialize proof and generate hash
        let proof_bytes = postcard::to_allocvec(proof).expect("Failed to serialize proof");
        format!("{:x}", Keccak256::digest(&proof_bytes))
    }
}

/// Submit proof to orchestrator and handle the result
#[allow(clippy::too_many_arguments)]
async fn submit_proof_to_orchestrator(
    task: &Task,
    proof: &Proof,
    proof_hash: &str,
    orchestrator: &dyn Orchestrator,
    signing_key: &SigningKey,
    num_workers: usize,
    event_sender: &mpsc::Sender<Event>,
    completed_tasks: &TaskCache,
    environment: &Environment,
    client_id: &str,
) {
    // Serialize proof for submission
    let proof_bytes = postcard::to_allocvec(proof).expect("Failed to serialize proof");

    // Submit to orchestrator
    match orchestrator
        .submit_proof(
            &task.task_id,
            proof_hash,
            proof_bytes,
            signing_key.clone(),
            num_workers,
            task.task_type,
        )
        .await
    {
        Ok(_) => {
            // Track analytics for proof submission success (non-blocking)
            tokio::spawn(track_proof_submission_success(
                task.clone(),
                environment.clone(),
                client_id.to_string(),
            ));
            handle_submission_success(task, event_sender, completed_tasks, environment, client_id)
                .await;
        }
        Err(e) => {
            handle_submission_error(
                task,
                e,
                event_sender,
                completed_tasks,
                environment,
                client_id,
            )
            .await;
        }
    }
}

/// Process a single proof submission
#[allow(clippy::too_many_arguments)]
async fn process_proof_submission(
    task: Task,
    proof: Proof,
    combined_hash: String,
    orchestrator: &dyn Orchestrator,
    signing_key: &SigningKey,
    num_workers: usize,
    event_sender: &mpsc::Sender<Event>,
    completed_tasks: &TaskCache,
    environment: &Environment,
    client_id: &str,
) {
    // Check for duplicate submissions
    if check_duplicate_submission(&task, completed_tasks, event_sender).await {
        return; // Skip duplicate task
    }

    // Generate proof hash
    let proof_hash = generate_proof_hash(&proof, combined_hash);

    // Submit to orchestrator and handle result
    submit_proof_to_orchestrator(
        &task,
        &proof,
        &proof_hash,
        orchestrator,
        signing_key,
        num_workers,
        event_sender,
        completed_tasks,
        environment,
        client_id,
    )
    .await;
}

/// Handle successful proof submission
async fn handle_submission_success(
    task: &Task,
    event_sender: &mpsc::Sender<Event>,
    completed_tasks: &TaskCache,
    environment: &Environment,
    client_id: &str,
) {
    completed_tasks.insert(task.task_id.clone()).await;
    let msg = format!(
        "[Task step 3 of 3] Proof submitted (Task ID: {}) Points for this node will be updated in https://app.nexus.xyz/rewards within 10 minutes",
        task.task_id
    );
    // Track analytics for proof acceptance (non-blocking)
    tokio::spawn(track_proof_accepted(
        task.clone(),
        environment.clone(),
        client_id.to_string(),
    ));

    send_proof_event(
        event_sender,
        msg,
        crate::events::EventType::Success,
        LogLevel::Info,
    )
    .await;
}

/// Handle proof submission errors
async fn handle_submission_error(
    task: &Task,
    error: OrchestratorError,
    event_sender: &mpsc::Sender<Event>,
    completed_tasks: &TaskCache,
    environment: &Environment,
    client_id: &str,
) {
    let (msg, status_code) = match error {
        OrchestratorError::Http {
            status,
            ref message,
            ..
        } => (
            format!(
                "Failed to submit proof for task {}. Status: {}, Message: {}",
                task.task_id, status, message
            ),
            Some(status),
        ),
        e => (
            format!("Failed to submit proof for task {}: {}", task.task_id, e),
            None,
        ),
    };

    // Add to cache to prevent resubmission of failed proofs
    // Once a proof fails, we don't want to waste resources trying again
    completed_tasks.insert(task.task_id.clone()).await;

    // Track analytics for proof submission error (non-blocking)
    tokio::spawn(track_proof_submission_error(
        task.clone(),
        msg.clone(),
        status_code,
        environment.clone(),
        client_id.to_string(),
    ));

    send_proof_event(
        event_sender,
        msg.to_string(),
        crate::events::EventType::Error,
        LogLevel::Error,
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_set_backoff_from_server() {
        let mut state = TaskFetchState::new();

        // Test setting a reasonable retry time
        state.set_backoff_from_server(60);
        assert_eq!(state.backoff_duration, Duration::from_secs(60));

        // Test that longer retry times are respected (no capping)
        state.set_backoff_from_server(300); // 5 minutes
        assert_eq!(state.backoff_duration, Duration::from_secs(300));

        // Test zero retry time
        state.set_backoff_from_server(0);
        assert_eq!(state.backoff_duration, Duration::from_secs(0));
    }

    #[test]
    fn test_server_retry_times_respected() {
        let mut state = TaskFetchState::new();

        // Test that very long retry times are respected
        state.set_backoff_from_server(3600); // 1 hour
        assert_eq!(state.backoff_duration, Duration::from_secs(3600));
    }

    #[test]
    fn test_reset_backoff() {
        let mut state = TaskFetchState::new();

        // Test that reset sets backoff to default 120s
        state.reset_backoff();
        assert_eq!(
            state.backoff_duration,
            Duration::from_millis(BACKOFF_DURATION)
        );
    }
}
