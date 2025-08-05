//! Prover Runtime
//!
//! Main orchestrator for authenticated and anonymous proving modes.
//! Coordinates online workers (network I/O) and offline workers (computation).

use crate::consts::prover::MAX_COMPLETED_TASKS;
use crate::environment::Environment;
use crate::events::Event;
use crate::orchestrator::OrchestratorClient;
use crate::task::Task;
use crate::task_cache::TaskCache;
use crate::version_checker::start_version_checker_task;
use crate::workers::online::ProofResult;
use crate::workers::{offline, online};
use ed25519_dalek::SigningKey;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

/// Starts authenticated workers that fetch tasks from the orchestrator and process them.
use std::sync::Arc;
use tokio::sync::Semaphore;

#[allow(clippy::too_many_arguments)]
pub async fn start_authenticated_workers(
    node_id: u64,
    signing_key: SigningKey,
    mut orchestrator: OrchestratorClient,
    num_workers: usize,
    shutdown: broadcast::Receiver<()>,
    environment: Environment,
    client_id: String,
    max_tasks: Option<u32>,
    semaphore: Arc<Semaphore>, // 新增参数
) -> (mpsc::Receiver<Event>, Vec<JoinHandle<()>>) {
    // 确保orchestrator客户端设置了node_id
    if orchestrator.get_node_id().is_none() {
        orchestrator = orchestrator.with_node_id(node_id.to_string());
    }
    let mut join_handles = Vec::new();
    // Worker events
    let (event_sender, event_receiver) =
        mpsc::channel::<Event>(crate::consts::prover::EVENT_QUEUE_SIZE);

    // todo 去掉版本check
    // Start version checker
    // let version_checker_handle = {
    //     let current_version = env!("CARGO_PKG_VERSION").to_string();
    //     let event_sender = event_sender.clone();
    //     let shutdown = shutdown.resubscribe();
    //     tokio::spawn(async move {
    //         start_version_checker_task(current_version, event_sender, shutdown).await;
    //     })
    // };
    // join_handles.push(version_checker_handle);

    // A bounded list of recently fetched task IDs (prevents refetching currently processing tasks)
    let enqueued_tasks = TaskCache::new(MAX_COMPLETED_TASKS);

    // Task fetching
    let (task_sender, task_receiver) =
        mpsc::channel::<Task>(crate::consts::prover::TASK_QUEUE_SIZE);
    let verifying_key = signing_key.verifying_key();
    let fetch_prover_tasks_handle = {
        let orchestrator = orchestrator.clone();
        let event_sender = event_sender.clone();
        let shutdown = shutdown.resubscribe(); // Clone the receiver for task fetching

        let client_id = client_id.clone();
        let environment = environment.clone();
        tokio::spawn(async move {
            online::fetch_prover_tasks(
                node_id,
                verifying_key,
                Box::new(orchestrator),
                task_sender,
                event_sender,
                shutdown,
                enqueued_tasks,
                environment,
                client_id,
            )
            .await;
        })
    };
    join_handles.push(fetch_prover_tasks_handle);

    // Workers
    let (result_sender, result_receiver) =
        mpsc::channel::<(Task, ProofResult)>(crate::consts::prover::RESULT_QUEUE_SIZE);

    let (worker_senders, worker_handles) = offline::start_workers(
        num_workers,
        result_sender,
        event_sender.clone(),
        shutdown.resubscribe(),
        environment.clone(),
        client_id.clone(),
        semaphore.clone(), // 新增参数
    ).await;
    join_handles.extend(worker_handles);

    // Dispatch tasks to workers
    let dispatcher_handle =
        offline::start_dispatcher(task_receiver, worker_senders, shutdown.resubscribe());
    join_handles.push(dispatcher_handle);

    // A bounded list of recently completed task IDs (prevents duplicate proof submissions)
    let completed_tasks = TaskCache::new(MAX_COMPLETED_TASKS);

    // Send proofs to the orchestrator
    let submit_proofs_handle = online::submit_proofs(
        signing_key,
        Box::new(orchestrator),
        num_workers,
        result_receiver,
        event_sender.clone(),
        shutdown.resubscribe(),
        completed_tasks.clone(),
        environment,
        client_id,
        max_tasks,
    )
    .await;
    join_handles.push(submit_proofs_handle);

    (event_receiver, join_handles)
}

/// Starts anonymous workers that repeatedly prove a program with hardcoded inputs.
pub async fn start_anonymous_workers(
    num_workers: usize,
    shutdown: broadcast::Receiver<()>,
    environment: Environment,
    client_id: String,
) -> (mpsc::Receiver<Event>, Vec<JoinHandle<()>>) {
    let mut join_handles = Vec::new();
    // Worker events
    let (event_sender, event_receiver) =
        mpsc::channel::<Event>(crate::consts::prover::EVENT_QUEUE_SIZE);

    // Start version checker
    let version_checker_handle = {
        let current_version = env!("CARGO_PKG_VERSION").to_string();
        let event_sender = event_sender.clone();
        let shutdown = shutdown.resubscribe();
        tokio::spawn(async move {
            start_version_checker_task(current_version, event_sender, shutdown).await;
        })
    };
    join_handles.push(version_checker_handle);

    // Start anonymous workers
    let (anonymous_event_receiver, anonymous_handles) =
        offline::start_anonymous_workers(num_workers, shutdown, environment, client_id).await;
    join_handles.extend(anonymous_handles);

    // Forward events from anonymous workers to our event sender
    let event_forwarder_handle = tokio::spawn(async move {
        let mut anonymous_event_receiver = anonymous_event_receiver;
        while let Some(event) = anonymous_event_receiver.recv().await {
            if event_sender.send(event).await.is_err() {
                break; // Main event channel closed
            }
        }
    });
    join_handles.push(event_forwarder_handle);

    (event_receiver, join_handles)
}

#[cfg(test)]
mod tests {
    use crate::orchestrator::MockOrchestrator;
    use crate::prover_runtime::{Event, MAX_COMPLETED_TASKS, online::fetch_prover_tasks};
    use crate::task::Task;
    use crate::task_cache::TaskCache;
    use std::time::Duration;
    use tokio::sync::{broadcast, mpsc};

    /// Creates a mock orchestrator client that simulates fetching tasks.
    fn get_mock_orchestrator_client() -> MockOrchestrator {
        let mut i = 0;
        let mut mock = MockOrchestrator::new();
        mock.expect_get_proof_task().returning_st(move |_, _| {
            // Simulate a task with dummy data
            let task = Task::new(
                i.to_string(),
                format!("Task {}", i),
                vec![1, 2, 3],
                crate::nexus_orchestrator::TaskType::ProofRequired,
            );
            i += 1;
            Ok(task)
        });
        mock
    }

    #[tokio::test]
    // Should fetch and enqueue tasks from the orchestrator.
    async fn test_task_fetching() {
        let orchestrator_client = Box::new(get_mock_orchestrator_client());
        let signer_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signer_key.verifying_key();
        let node_id = 1234;

        let task_queue_size = 10;
        let (task_sender, mut task_receiver) = mpsc::channel::<Task>(task_queue_size);

        // Run task_master in a tokio task to stay in the same thread context
        let (shutdown_sender, _) = broadcast::channel(1); // Only one shutdown signal needed
        let (event_sender, _event_receiver) = mpsc::channel::<Event>(100);
        let shutdown_receiver = shutdown_sender.subscribe();
        let submitted_tasks = TaskCache::new(MAX_COMPLETED_TASKS);

        let task_master_handle = tokio::spawn(async move {
            fetch_prover_tasks(
                node_id,
                verifying_key,
                orchestrator_client,
                task_sender,
                event_sender,
                shutdown_receiver,
                submitted_tasks,
                crate::environment::Environment::Production,
                "test-client-id".to_string(),
            )
            .await;
        });

        // Receive tasks
        let mut received = 0;
        for _i in 0..task_queue_size {
            match tokio::time::timeout(Duration::from_secs(2), task_receiver.recv()).await {
                Ok(Some(task)) => {
                    println!("Received task {}: {:?}", received, task);
                    received += 1;
                }
                Ok(None) => {
                    eprintln!("Channel closed unexpectedly");
                    break;
                }
                Err(_) => {
                    eprintln!("Timed out waiting for task {}", received);
                    break;
                }
            }
        }

        task_master_handle.abort();
    }
}
