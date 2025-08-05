//! Prover Task
//!
//! This abstracts over the two "task" types used in the Nexus Orchestrator:
//! * Task (Returned by GetTasks)
//! * GetProofTaskResponse.

use sha3::{Digest, Keccak256};
use std::fmt::Display;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Task {
    /// Orchestrator task ID
    pub task_id: String,

    /// ID of the program to be executed
    pub program_id: String,

    /// Public inputs for the task (legacy field for backward compatibility)
    pub public_inputs: Vec<u8>,

    /// Multiple public inputs for the task (new field)
    pub public_inputs_list: Vec<Vec<u8>>,

    /// The type of task (proof required or only hash)
    pub task_type: crate::nexus_orchestrator::TaskType,
}

impl Task {
    /// Creates a new task with the given parameters.
    #[allow(unused)]
    pub fn new(
        task_id: String,
        program_id: String,
        public_inputs: Vec<u8>,
        task_type: crate::nexus_orchestrator::TaskType,
    ) -> Self {
        Task {
            task_id,
            program_id,
            public_inputs: public_inputs.clone(),
            public_inputs_list: vec![public_inputs],
            task_type,
        }
    }

    /// Combines multiple proof hashes into a single hash using Keccak-256
    /// This matches the JavaScript implementation: combineHashes
    pub fn combine_proof_hashes(hashes: &[String]) -> String {
        if hashes.is_empty() {
            return String::new();
        }

        // Concatenate all hash strings
        let combined = hashes.join("");

        // Hash the combined string using Keccak-256
        let hash = Keccak256::digest(combined.as_bytes());
        format!("{:x}", hash)
    }

    /// Get all inputs for the task
    pub fn all_inputs(&self) -> &[Vec<u8>] {
        &self.public_inputs_list
    }
}

// Display
impl Display for Task {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Task ID: {}, Program ID: {}, Inputs: {}",
            self.task_id,
            self.program_id,
            self.public_inputs_list.len()
        )
    }
}

// From Task
impl From<&crate::nexus_orchestrator::Task> for Task {
    fn from(task: &crate::nexus_orchestrator::Task) -> Self {
        Task {
            task_id: task.task_id.clone(),
            program_id: task.program_id.clone(),
            public_inputs: task.public_inputs_list.first().cloned().unwrap_or_default(),
            public_inputs_list: task.public_inputs_list.clone(),
            task_type: crate::nexus_orchestrator::TaskType::try_from(task.task_type).unwrap(),
        }
    }
}

// From GetProofTaskResponse
impl From<&crate::nexus_orchestrator::GetProofTaskResponse> for Task {
    fn from(response: &crate::nexus_orchestrator::GetProofTaskResponse) -> Self {
        let task_type = crate::nexus_orchestrator::TaskType::try_from(
            response.task.as_ref().unwrap().task_type,
        )
        .unwrap();

        Task {
            task_id: response.task_id.clone(),
            program_id: response.program_id.clone(),
            public_inputs: response.public_inputs.clone(),
            public_inputs_list: vec![response.public_inputs.clone()],
            task_type,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_combine_proof_hashes() {
        // Test with empty array
        assert_eq!(Task::combine_proof_hashes(&[]), "");

        // Test with single hash
        let single_hash = "a1b2c3d4e5f6";
        let result = Task::combine_proof_hashes(&[single_hash.to_string()]);
        assert!(!result.is_empty());
        assert_eq!(result.len(), 64); // Keccak-256 produces 32 bytes = 64 hex chars

        // Test with multiple hashes
        let hashes = vec![
            "a1b2c3d4e5f6".to_string(),
            "7890abcdef12".to_string(),
            "345678901234".to_string(),
        ];
        let combined = Task::combine_proof_hashes(&hashes);
        assert!(!combined.is_empty());
        assert_eq!(combined.len(), 64);

        // Verify that the same hashes produce the same result
        let combined2 = Task::combine_proof_hashes(&hashes);
        assert_eq!(combined, combined2);

        // Verify that different order produces different result
        let hashes_reversed = vec![
            "345678901234".to_string(),
            "7890abcdef12".to_string(),
            "a1b2c3d4e5f6".to_string(),
        ];
        let combined_reversed = Task::combine_proof_hashes(&hashes_reversed);
        assert_ne!(combined, combined_reversed);
    }

    #[test]
    fn test_task_input_methods() {
        let task = Task::new(
            "test_task".to_string(),
            "test_program".to_string(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            crate::nexus_orchestrator::TaskType::ProofRequired,
        );

        // Test all_inputs
        let all_inputs = task.all_inputs();
        assert_eq!(all_inputs.len(), 1);
        assert_eq!(all_inputs[0], vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

        // Test first input
        let first_input = all_inputs.first().unwrap();
        assert_eq!(first_input, &vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    }

    #[test]
    fn test_multiple_inputs() {
        // Create a task with multiple inputs
        let mut task = Task::new(
            "test_task".to_string(),
            "test_program".to_string(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            crate::nexus_orchestrator::TaskType::ProofRequired,
        );

        // Add additional inputs
        task.public_inputs_list
            .push(vec![13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24]);
        task.public_inputs_list
            .push(vec![25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36]);

        // Test all_inputs
        let all_inputs = task.all_inputs();
        assert_eq!(all_inputs.len(), 3);
        assert_eq!(all_inputs[0], vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        assert_eq!(
            all_inputs[1],
            vec![13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24]
        );
        assert_eq!(
            all_inputs[2],
            vec![25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36]
        );

        // Test first input
        let first_input = all_inputs.first().unwrap();
        assert_eq!(first_input, &vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    }

    #[test]
    fn test_backward_compatibility() {
        let task = Task::new(
            "test_task".to_string(),
            "fib_input_initial".to_string(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            crate::nexus_orchestrator::TaskType::ProofRequired,
        );

        // Test that both legacy and new fields work
        assert_eq!(task.all_inputs().len(), 1);
        assert_eq!(
            task.all_inputs()[0],
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
        );

        println!("Backward compatibility test passed");
    }
}
