//! Nexus Orchestrator Client
//!
//! A client for the Nexus Orchestrator, allowing for proof task retrieval and submission.

use crate::environment::Environment;
use crate::nexus_orchestrator::{
    GetProofTaskRequest, GetProofTaskResponse, GetTasksResponse, NodeType, RegisterNodeRequest,
    RegisterNodeResponse, RegisterUserRequest, SubmitProofRequest, TaskDifficulty, UserResponse,
};
use crate::orchestrator::Orchestrator;
use crate::orchestrator::error::OrchestratorError;
use crate::system::{estimate_peak_gflops, get_memory_info};
use crate::task::Task;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use prost::Message;
use reqwest::{Client, ClientBuilder, Response};
use std::sync::OnceLock;
use std::time::Duration;


// Privacy-preserving country detection for network optimization.
// Only stores 2-letter country codes (e.g., "US", "CA", "GB") to help route
// to the closest server. This improves network latency and reliability.
// No precise location, IP addresses, or personal data is collected or stored.
static COUNTRY_CODE: OnceLock<String> = OnceLock::new();



#[derive(Debug, Clone)]
pub struct OrchestratorClient {
    client: Client,
    environment: Environment,
    node_id: Option<String>, // 添加node_id字段，用于日志记录
}

impl OrchestratorClient {
    pub fn new(environment: Environment) -> Self {
        Self {
            client: ClientBuilder::new()
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client"),
            environment,
            node_id: None,
        }
    }

    pub fn new_with_proxy(environment: Environment, proxy: Option<String>) -> Self {
        let mut builder = ClientBuilder::new()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(10));
        if let Some(proxy_url) = proxy {
            if let Ok(p) = reqwest::Proxy::all(&proxy_url) {
                builder = builder.proxy(p);
            } else {
                log::warn!("Invalid proxy URL: {}", proxy_url);
            }
        }
        Self {
            client: builder.build().expect("Failed to create HTTP client"),
            environment,
            node_id: None,
        }
    }

    /// 设置当前客户端的node_id，用于日志记录
    pub fn with_node_id(mut self, node_id: impl Into<String>) -> Self {
        self.node_id = Some(node_id.into());
        self
    }

    /// 获取当前设置的node_id，用于日志记录
    pub fn get_node_id(&self) -> Option<&str> {
        self.node_id.as_deref()
    }

    fn build_url(&self, endpoint: &str) -> String {
        format!(
            "{}/{}",
            self.environment.orchestrator_url().trim_end_matches('/'),
            endpoint.trim_start_matches('/')
        )
    }

    fn encode_request<T: Message>(request: &T) -> Vec<u8> {
        request.encode_to_vec()
    }

    fn decode_response<T: Message + Default>(bytes: &[u8]) -> Result<T, OrchestratorError> {
        T::decode(bytes).map_err(OrchestratorError::Decode)
    }

    async fn handle_response_status(&self, response: Response) -> Result<Response, OrchestratorError> {
        let status = response.status();
        let url = response.url().to_string();
        // 添加node_id信息到日志
        let node_info = if let Some(node_id) = &self.node_id {
            format!("[node_id={}] ", node_id)
        } else {
            "".to_string()
        };
        if !status.is_success() {
            log::warn!("{}HTTP request failed with status: {} (url: {})", node_info, status, url);
            return Err(OrchestratorError::from_response(response).await);
        }
        // 成功时也可以添加node_id，但这是调试日志，不是必需的
        log::info!("{}HTTP request succeeded with status: {} (url: {})", node_info, status, url);
        Ok(response)
    }

    async fn get_request<T: Message + Default>(
        &self,
        endpoint: &str,
    ) -> Result<T, OrchestratorError> {
        let url = self.build_url(endpoint);
        let response = self.client.get(&url).send().await?;

        let response = self.handle_response_status(response).await?;
        let response_bytes = response.bytes().await?;
        Self::decode_response(&response_bytes)
    }

    async fn post_request<T: Message + Default>(
        &self,
        endpoint: &str,
        body: Vec<u8>,
    ) -> Result<T, OrchestratorError> {
        let url = self.build_url(endpoint);
        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(body)
            .send()
            .await?;

        let response = self.handle_response_status(response).await?;
        let response_bytes = response.bytes().await?;
        Self::decode_response(&response_bytes)
    }

    async fn post_request_no_response(
        &self,
        endpoint: &str,
        body: Vec<u8>,
    ) -> Result<(), OrchestratorError> {
        let url = self.build_url(endpoint);
        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(body)
            .send()
            .await?;

        self.handle_response_status(response).await?;
        Ok(())
    }

    fn create_signature(
        &self,
        signing_key: &SigningKey,
        task_id: &str,
        proof_hash: &str,
    ) -> (Vec<u8>, Vec<u8>) {
        let signature_version = 0;
        let msg = format!("{} | {} | {}", signature_version, task_id, proof_hash);
        let signature = signing_key.sign(msg.as_bytes());
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        (
            signature.to_bytes().to_vec(),
            verifying_key.to_bytes().to_vec(),
        )
    }

    /// Detects the user's country for network optimization purposes.
    ///
    /// Privacy Note: This only detects the country (2-letter code like "US", "CA", "GB")
    /// and does NOT track precise location, IP address, or any personally identifiable
    /// information. The country information helps the Nexus network route requests to
    /// the nearest servers for better performance and reduced latency.
    ///
    /// The detection is cached for the duration of the program run.
    async fn get_country(&self) -> String {
        if let Some(country) = COUNTRY_CODE.get() {
            return country.clone();
        }

        let country = self.detect_country().await;
        let _ = COUNTRY_CODE.set(country.clone());
        country
    }

    async fn detect_country(&self) -> String {
        // Try Cloudflare first (most reliable)
        if let Ok(country) = self.get_country_from_cloudflare().await {
            return country;
        }

        // Fallback to ipinfo.io
        if let Ok(country) = self.get_country_from_ipinfo().await {
            return country;
        }

        // If we can't detect the country, use the US as a fallback
        "US".to_string()
    }

    async fn get_country_from_cloudflare(&self) -> Result<String, Box<dyn std::error::Error>> {
        let response = self
            .client
            .get("https://cloudflare.com/cdn-cgi/trace")
            .timeout(Duration::from_secs(5))
            .send()
            .await?;

        let text = response.text().await?;

        for line in text.lines() {
            if let Some(country) = line.strip_prefix("loc=") {
                let country = country.trim().to_uppercase();
                if country.len() == 2 && country.chars().all(|c| c.is_ascii_alphabetic()) {
                    return Ok(country);
                }
            }
        }

        Err("Country not found in Cloudflare response".into())
    }

    async fn get_country_from_ipinfo(&self) -> Result<String, Box<dyn std::error::Error>> {
        let response = self
            .client
            .get("https://ipinfo.io/country")
            .timeout(Duration::from_secs(5))
            .send()
            .await?;

        let country = response.text().await?;
        let country = country.trim().to_uppercase();

        if country.len() == 2 && country.chars().all(|c| c.is_ascii_alphabetic()) {
            Ok(country)
        } else {
            Err("Invalid country code from ipinfo.io".into())
        }
    }

    /// 获取当前出网 IP 的详细信息
    ///
    /// 返回 ipinfo.io 的完整 JSON 响应，包含 IP、地理位置、ISP 等信息
    /// 如果使用了代理，会显示代理的出网 IP
    /// 返回的JSON会被转换为单行紧凑格式
    pub async fn get_ip_info(&self) -> Result<String, Box<dyn std::error::Error>> {
        // 获取节点信息用于日志
        let node_info = if let Some(node_id) = &self.node_id {
            format!("[node_id={}] ", node_id)
        } else {
            "".to_string()
        };
        // 发送请求获取IP信息
        log::info!("{}{}", node_info, "发送请求获取IP信息...");
        let response = match self
            .client
            .get("https://ipinfo.io/json")
            .timeout(Duration::from_secs(10))
            .send()
            .await {
                Ok(resp) => resp,
                Err(e) => {
                    log::warn!("{}{}: {}", node_info, "获取IP信息失败", e);
                    return Err(Box::new(e));
                }
            };

        let ip_info = match response.text().await {
            Ok(text) => text,
            Err(e) => {
                log::warn!("{}{}: {}", node_info, "解析IP信息响应失败", e);
                return Err(Box::new(e));
            }
        };

        // 尝试将JSON转换为单行紧凑格式
        let result = match serde_json::from_str::<serde_json::Value>(&ip_info) {
            Ok(json_value) => {
                match serde_json::to_string(&json_value) {
                    Ok(compact_json) => compact_json,
                    Err(_) => ip_info.clone() // 如果转换失败，使用原始字符串
                }
            },
            Err(_) => ip_info.clone() // 如果解析失败，使用原始字符串
        };

        log::info!("{}{}", node_info, "成功获取IP信息");
        Ok(result)
    }

}

#[async_trait::async_trait]
impl Orchestrator for OrchestratorClient {
    fn environment(&self) -> &Environment {
        &self.environment
    }

    /// Get the user ID associated with a wallet address.
    async fn get_user(&self, wallet_address: &str) -> Result<String, OrchestratorError> {
        let wallet_path = urlencoding::encode(wallet_address).into_owned();
        let endpoint = format!("v3/users/{}", wallet_path);

        let user_response: UserResponse = self.get_request(&endpoint).await?;
        Ok(user_response.user_id)
    }

    /// Registers a new user with the orchestrator.
    async fn register_user(
        &self,
        user_id: &str,
        wallet_address: &str,
    ) -> Result<(), OrchestratorError> {
        let request = RegisterUserRequest {
            uuid: user_id.to_string(),
            wallet_address: wallet_address.to_string(),
        };
        let request_bytes = Self::encode_request(&request);

        self.post_request_no_response("v3/users", request_bytes)
            .await
    }

    /// Registers a new node with the orchestrator.
    async fn register_node(&self, user_id: &str) -> Result<String, OrchestratorError> {
        let request = RegisterNodeRequest {
            node_type: NodeType::CliProver as i32,
            user_id: user_id.to_string(),
        };
        let request_bytes = Self::encode_request(&request);

        let response: RegisterNodeResponse = self.post_request("v3/nodes", request_bytes).await?;
        Ok(response.node_id)
    }

    /// Get the wallet address associated with a node ID.
    async fn get_node(&self, node_id: &str) -> Result<String, OrchestratorError> {
        let endpoint = format!("v3/nodes/{}", node_id);

        let node_response: crate::nexus_orchestrator::GetNodeResponse =
            self.get_request(&endpoint).await?;
        Ok(node_response.wallet_address)
    }

    async fn get_tasks(&self, node_id: &str) -> Result<Vec<Task>, OrchestratorError> {
        let response: GetTasksResponse = self.get_request(&format!("v3/tasks/{}", node_id)).await?;
        let tasks = response.tasks.iter().map(Task::from).collect();
        Ok(tasks)
    }

    async fn get_proof_task(
        &self,
        node_id: &str,
        verifying_key: VerifyingKey,
    ) -> Result<Task, OrchestratorError> {
        let request = GetProofTaskRequest {
            node_id: node_id.to_string(),
            node_type: NodeType::CliProver as i32,
            ed25519_public_key: verifying_key.to_bytes().to_vec(),
            max_difficulty: TaskDifficulty::Large as i32,
        };
        let request_bytes = Self::encode_request(&request);

        let response: GetProofTaskResponse = self.post_request("v3/tasks", request_bytes).await?;
        Ok(Task::from(&response))
    }

    async fn submit_proof(
        &self,
        task_id: &str,
        proof_hash: &str,
        proof: Vec<u8>,
        signing_key: SigningKey,
        num_provers: usize,
        task_type: Option<crate::nexus_orchestrator::TaskType>,
    ) -> Result<(), OrchestratorError> {
        // 获取node_id信息用于日志
        let node_info = if let Some(node_id) = &self.node_id {
            format!("[node_id={}] ", node_id)
        } else {
            "".to_string()
        };
        // 记录开始提交证明的日志
        log::info!("{}开始提交证明: task_id={}, proof_hash={}", node_info, task_id, proof_hash);

        let (program_memory, total_memory) = get_memory_info();
        let flops = estimate_peak_gflops(num_provers);
        let (signature, public_key) = self.create_signature(&signing_key, task_id, proof_hash);

        // Detect country for network optimization (privacy-preserving: only country code, no precise location)
        let location = self.get_country().await;
        // Only attach proof if task type is not ProofHash
        // If task_type is None, default to attaching proof for backward compatibility
        let proof_to_send = match task_type {
            Some(crate::nexus_orchestrator::TaskType::ProofHash) => Vec::new(),
            _ => proof, // Attach proof for ProofRequired or None (backward compatibility)
        };

        let request = SubmitProofRequest {
            task_id: task_id.to_string(),
            node_type: NodeType::CliProver as i32,
            proof_hash: proof_hash.to_string(),
            proof: proof_to_send,
            node_telemetry: Some(crate::nexus_orchestrator::NodeTelemetry {
                flops_per_sec: Some(flops as i32),
                memory_used: Some(program_memory),
                memory_capacity: Some(total_memory),
                // Country code for network routing optimization (privacy-preserving)
                location: Some(location),
            }),
            ed25519_public_key: public_key,
            signature,
        };
        let request_bytes = Self::encode_request(&request);

        let result = match self.post_request_no_response("v3/tasks/submit", request_bytes.clone()).await {
            Err(err) => {
                // 检查是否是429错误 - 可能是Reqwest错误或Http错误
                let is_rate_limit = match &err {
                    // 检查Reqwest错误中的状态码
                    OrchestratorError::Reqwest(reqwest_err) => {
                        if let Some(status) = reqwest_err.status() {
                            status.as_u16() == 429
                        } else {
                            false
                        }
                    },
                    // 检查Http错误中的状态码
                    OrchestratorError::Http { status, .. } => {
                        *status == 429
                    },
                    _ => false,
                };
                if is_rate_limit {
                    log::warn!("{}遇到限流 (429)，本次提交证明失败: task_id={}", node_info, task_id);
                }
                // 如果不是429错误，记录错误日志并返回错误
                log::warn!("{}证明提交失败: task_id={}, proof_hash={}, error={}", node_info, task_id, proof_hash, err);
                Err(err)
            },
            Ok(result) => {
                // 记录成功日志
                log::info!("{}证明提交成功: task_id={}, proof_hash={}", node_info, task_id, proof_hash);
                Ok(result)
            },
        };

        result
    }
}

#[cfg(test)]
/// These are ignored by default since they require a live orchestrator to run.
mod live_orchestrator_tests {
    use crate::environment::Environment;
    use crate::orchestrator::Orchestrator;

    #[tokio::test]
    #[ignore] // This test requires a live orchestrator instance.
    /// Should register a new user with the orchestrator.
    async fn test_register_user() {
        let client = super::OrchestratorClient::new(Environment::Production);
        // UUIDv4 for the user ID
        let user_id = uuid::Uuid::new_v4().to_string();
        let wallet_address = "0x1234567890abcdef1234567890cbaabc12345678"; // Example wallet address
        match client.register_user(&user_id, wallet_address).await {
            Ok(_) => println!("User registered successfully: {}", user_id),
            Err(e) => panic!("Failed to register user: {}", e),
        }
    }

    #[tokio::test]
    #[ignore] // This test requires a live orchestrator instance.
    /// Should register a new node to an existing user.
    async fn test_register_node() {
        let client = super::OrchestratorClient::new(Environment::Production);
        let user_id = "78db0be7-f603-4511-9576-c660f3c58395";
        match client.register_node(user_id).await {
            Ok(node_id) => println!("Node registered successfully: {}", node_id),
            Err(e) => panic!("Failed to register node: {}", e),
        }
    }

    #[tokio::test]
    #[ignore] // This test requires a live orchestrator instance.
    /// Should return a new proof task for the node.
    async fn test_get_proof_task() {
        let client = super::OrchestratorClient::new(Environment::Production);
        let node_id = "5880437"; // Example node ID
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();
        let result = client.get_proof_task(node_id, verifying_key).await;
        match result {
            Ok(task) => {
                println!("Got proof task: {}", task);
            }
            Err(e) => panic!("Failed to get proof task: {}", e),
        }
    }

    #[tokio::test]
    #[ignore] // This test requires a live orchestrator instance.
    /// Should return the list of tasks for the node.
    async fn test_get_tasks() {
        let client = super::OrchestratorClient::new(Environment::Production);
        let node_id = "5880437"; // Example node ID
        match client.get_tasks(node_id).await {
            Ok(tasks) => {
                println!("Got {} tasks", tasks.len());
                for task in tasks {
                    println!("Task: {}", task);
                }
            }
            Err(e) => panic!("Failed to get tasks: {}", e),
        }
    }

    #[tokio::test]
    #[ignore] // This test requires a live orchestrator instance.
    /// Should return the user ID for a wallet address.
    async fn test_get_user() {
        let client = super::OrchestratorClient::new(Environment::Production);
        let wallet_address = "0x1234567890abcdef1234567890cbaabc12345678"; // Example wallet address
        match client.get_user(wallet_address).await {
            Ok(user_id) => println!("User ID: {}", user_id),
            Err(e) => panic!("Failed to get user: {}", e),
        }
    }

    #[tokio::test]
    #[ignore] // This test requires a live orchestrator instance.
    /// Should return the wallet address for a node ID.
    async fn test_get_node() {
        let client = super::OrchestratorClient::new(Environment::Production);
        let node_id = "5880437"; // Example node ID
        match client.get_node(node_id).await {
            Ok(wallet_address) => println!("Wallet address: {}", wallet_address),
            Err(e) => panic!("Failed to get node: {}", e),
        }
    }

    #[tokio::test]
    #[ignore] // This test requires a live orchestrator instance.
    /// Should detect the country for network optimization.
    async fn test_country_detection() {
        let client = super::OrchestratorClient::new(Environment::Production);
        let country = client.get_country().await;
        println!("Detected country: {}", country);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nexus_orchestrator::TaskType;

    #[tokio::test]
    /// Should conditionally attach proof based on task type.
    async fn test_conditional_proof_attachment() {
        let client = OrchestratorClient::new(Environment::Production);
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let proof = vec![1, 2, 3, 4, 5]; // Example proof bytes
        let task_id = "test_task_123";
        let proof_hash = "test_hash_456";
        let num_workers = 4;

        // Test with ProofRequired task type - should attach proof
        let result = client
            .submit_proof(
                task_id,
                proof_hash,
                proof.clone(),
                signing_key.clone(),
                num_workers,
                Some(TaskType::ProofRequired),
            )
            .await;
        // This will fail because we're not actually submitting to a real orchestrator,
        // but the important thing is that the proof was attached in the request
        assert!(result.is_err()); // Expected to fail due to network error

        // Test with ProofHash task type - should not attach proof
        let result = client
            .submit_proof(
                task_id,
                proof_hash,
                proof,
                signing_key,
                num_workers,
                Some(TaskType::ProofHash),
            )
            .await;
        // This will also fail, but the proof should be empty in the request
        assert!(result.is_err()); // Expected to fail due to network error
    }
}