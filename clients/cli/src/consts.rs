
pub mod prover {
    // Queue sizes. Chosen to be larger than the tasks API page size (currently, 50)
    pub const TASK_QUEUE_SIZE: usize = 100;
    pub const EVENT_QUEUE_SIZE: usize = 100;
    pub const RESULT_QUEUE_SIZE: usize = 100;

    // Task fetching thresholds
    // pub const BATCH_SIZE: usize = TASK_QUEUE_SIZE / 5; // Fetch this many tasks at once
    pub const BATCH_SIZE: usize = 1; // todo

    pub const LOW_WATER_MARK: usize = TASK_QUEUE_SIZE / 4; // Fetch new tasks when queue drops below this  4 --> fast 2 --> normal 4
    pub const MAX_404S_BEFORE_GIVING_UP: usize = 5; // Allow several 404s before stopping batch fetch 5 --> fast 50 --> normal 5
    pub const BACKOFF_DURATION: u64 = 60000; // 120 seconds --> fast 30s  --> normal 60s
    pub const QUEUE_LOG_INTERVAL: u64 = 60000; // 1 minute --> fast 30s --> normal 60s

    /// How long a task ID remains in the duplicate-prevention cache before expiring.
    pub const CACHE_EXPIRATION: u64 = 300000; // 5 minutes --> fast 3 minutes  --> normal 5 minutes
}
