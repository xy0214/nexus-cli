// Copyright (c) 2024 Nexus. All rights reserved.

mod analytics;
mod config;
mod consts;
mod environment;
mod error_classifier;
mod events;
mod keys;
mod logging;
#[path = "proto/nexus.orchestrator.rs"]
mod nexus_orchestrator;
mod orchestrator;
mod pretty;
mod prover;
mod prover_runtime;
mod register;
pub mod system;
mod task;
mod task_cache;
mod ui;
mod version_checker;
mod version_requirements;
mod workers;

use crate::config::{Config, get_config_path};
use crate::environment::Environment;
use crate::orchestrator::{Orchestrator, OrchestratorClient};
use crate::pretty::print_cmd_info;
use crate::prover_runtime::{start_anonymous_workers, start_authenticated_workers};
use crate::register::{register_node, register_user};
use crate::version_requirements::{VersionRequirements, VersionRequirementsError};
use clap::{ArgAction, Parser, Subcommand};
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ed25519_dalek::SigningKey;
use ratatui::{Terminal, backend::CrosstermBackend};
use std::{error::Error, io};
use tokio::sync::broadcast;

use std::fs::File;
use std::io::BufRead;
use rand::{distributions::Alphanumeric, Rng};
use std::time::{SystemTime, UNIX_EPOCH};

// 包装start函数，处理错误日志记录
async fn start_node_wrapper(node_id: u64, env: Environment, config_path: std::path::PathBuf,
                          headless: bool, max_threads: Option<u32>, proxy: Option<String>) {
    if let Err(e) = start(Some(node_id), env, config_path, headless, max_threads, proxy).await {
        log::error!("Error starting node {}: {}", node_id, e);
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
/// Command-line arguments
struct Args {
    /// Command to execute
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the prover
    Start {
        /// CSV 文件路径
        #[arg(long, value_name = "NODE_ID_FILE")]
        node_id_file: String,

        /// Run without the terminal UI
        #[arg(long = "headless", action = ArgAction::SetTrue)]
        headless: bool,

        /// Maximum number of threads to use for proving.
        #[arg(long = "max-threads", value_name = "MAX_THREADS")]
        max_threads: Option<u32>,
    },
    /// Register a new user
    RegisterUser {
        /// User's public Ethereum wallet address. 42-character hex string starting with '0x'
        #[arg(long, value_name = "WALLET_ADDRESS")]
        wallet_address: String,
    },
    /// Register multiple nodes for users based on a CSV file
    RegisterNode {
        /// CSV file path containing user_id, node_qty, and proxy information
        #[arg(long, value_name = "REGISTER_NODE_FILE")]
        wait_register_node_file: String,
    },
    /// Clear the node configuration and logout.
    Logout,
}


/// 生成随机session ID，格式为：当前时间戳毫秒 + 10个随机小写字母
fn generate_random_session_id() -> String {
    // 获取当前时间戳（毫秒）
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis();

    // 生成16位数字+大小写字母混合字符串
    use rand::distributions::Uniform;
    use rand::distributions::Distribution;
    const CHARSET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut rng = rand::thread_rng();
    let rand_chars: String = (0..10)
        .map(|_| {
            let idx = Uniform::from(0..CHARSET.len()).sample(&mut rng);
            CHARSET[idx] as char
        })
        .collect();

    format!("{}{}", timestamp, rand_chars)
}

fn convert_proxy_format(proxy: &str) -> Option<String> {
    // 如果代理字符串为空，返回None
    if proxy.trim().is_empty() {
        return None;
    }

    let parts: Vec<&str> = proxy.split(':').collect();
    if parts.len() == 4 {
        // 检查username部分是否包含{random_session_id}
        let username = parts[2];
        let username_with_session_id = if username.contains("{random_session_id}") {
            // 生成随机session ID
            let session_id = generate_random_session_id();
            // 替换username中的占位符
            let updated_username = username.replace("{random_session_id}", &session_id);
            log::info!("替换代理URL的username中的随机session ID: {}", updated_username);
            updated_username
        } else {
            username.to_string()
        };

        // ip:port:user:pass => http://user:pass@ip:port
        Some(format!("http://{}:{}@{}:{}", username_with_session_id, parts[3], parts[0], parts[1]))
    } else if proxy.starts_with("http://") || proxy.starts_with("https://") {
        Some(proxy.to_string())
    } else {
        Some(proxy.to_string())
    }
}

fn read_node_id_csv(path: &str) -> io::Result<Vec<(u64, Option<String>)>> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut result = Vec::new();
    for (i, line) in reader.lines().enumerate() {
        // 每次循环同步停顿1毫秒
        std::thread::sleep(std::time::Duration::from_millis(1));
        let line = line?;
        if i == 0 { continue; } // 跳过表头
        let mut parts = line.splitn(2, ',');
        let node_id = parts.next().unwrap_or("").trim().parse::<u64>().ok();
        let proxy = parts.next().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        if let Some(node_id) = node_id {
            let proxy = proxy.and_then(|p| convert_proxy_format(&p));
            result.push((node_id, proxy));
        }
    }
    Ok(result)
}

/// 读取用户注册节点的 CSV 文件
/// CSV 格式: user_id,node_qty,proxy
/// user_id: 字符串类型，表示用户 ID
/// node_qty: 整数类型，表示需要创建的节点数量
/// proxy: 代理服务器地址，格式如 45.38.111.5:5920:pjspqvjc:65ipqktn2z5z
fn read_register_node_csv(path: &str) -> io::Result<Vec<(String, u32, Option<String>, Option<String>)>> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut result = Vec::new();

    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        if i == 0 { continue; } // 跳过表头

        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() < 2 {
            log::warn!("Invalid CSV line format: {}", line);
            continue;
        }

        let user_id = parts[0].trim().to_string();
        if user_id.is_empty() {
            log::warn!("Empty user_id in line: {}", line);
            continue;
        }

        let node_qty = match parts[1].trim().parse::<u32>() {
            Ok(qty) => qty,
            Err(_) => {
                log::warn!("Invalid node_qty in line: {}", line);
                continue;
            }
        };

        // 保存原始代理字符串和转换后的代理字符串
        let (original_proxy, converted_proxy) = if parts.len() > 2 && !parts[2].trim().is_empty() {
            let proxy_str = parts[2].trim().to_string();
            (Some(proxy_str.clone()), convert_proxy_format(&proxy_str))
        } else {
            (None, None)
        };

        result.push((user_id, node_qty, original_proxy, converted_proxy));
    }

    Ok(result)
}

/// 将注册结果写入 CSV 文件
fn write_register_results_csv(
    results: &[(u64, Option<String>, String)],
    output_path: &str,
) -> io::Result<()> {
    use std::io::Write;

    let mut file = std::fs::File::create(output_path)?;

    // 写入 CSV 表头
    writeln!(file, "node_id,proxy,user_id")?;

    // 写入数据行
    for (node_id, proxy, user_id) in results {
        let proxy_str = proxy.as_deref().unwrap_or("");
        writeln!(file, "{},{},{}", node_id, proxy_str, user_id)?;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 使用最简单可靠的方式初始化日志系统
    env_logger::init();

    // 记录启动日志
    log::info!("Starting nexus-network-batch with logging enabled");
    let nexus_environment_str = std::env::var("NEXUS_ENVIRONMENT").unwrap_or_default();
    let environment = nexus_environment_str
        .parse::<Environment>()
        .unwrap_or(Environment::default());

    let config_path = get_config_path()?;

    let args = Args::parse();
    match args.command {
        Command::RegisterNode {
            wait_register_node_file,
        } => {
            log::info!("Reading register node file: {}", wait_register_node_file);
            let register_infos = read_register_node_csv(&wait_register_node_file)?;

            if register_infos.is_empty() {
                log::warn!("No valid entries found in the register node file");
                return Ok(());
            }

            log::info!("Found {} user entries to register nodes", register_infos.len());

            // 创建结果收集器
            let mut results = Vec::new();

            // 生成输出文件名（使用当前时间）
            use chrono::Local;
            let now = Local::now();
            let output_filename = format!("register_results_{}.csv", now.format("%Y%m%d_%H%M%S"));

            // 为每个用户注册指定数量的节点
            for (user_id, node_qty, original_proxy, converted_proxy) in register_infos {
                log::info!("Processing user_id: {}, node_qty: {}", user_id, node_qty);

                // 创建 OrchestratorClient 实例，带有可选的代理
                let orchestrator_client = OrchestratorClient::new_with_proxy(environment.clone(), converted_proxy.clone());
                // 获取当前出网 IP 信息
                match orchestrator_client.get_ip_info().await {
                    Ok(ip_info) => {
                        if let Some(ref proxy) = converted_proxy {
                            log::info!("当前出网 IP 信息: {}, 使用代理: {}", ip_info, proxy);
                        } else {
                            log::info!("当前出网 IP 信息: {}, 未使用代理", ip_info);
                        }
                    },
                    Err(e) => {
                        if let Some(ref proxy) = converted_proxy {
                            log::warn!("获取 IP 信息失败: {}, 使用代理: {}", e, proxy);
                        } else {
                            log::warn!("获取 IP 信息失败: {}, 未使用代理", e);
                        }
                    },
                }

                // 为该用户注册指定数量的节点
                let mut rate_limited = false;
                for _ in 0..node_qty {
                    if rate_limited {
                        break; // 如果遇到速率限制，跳出循环
                    }

                    match orchestrator_client.register_node(&user_id).await {
                        Ok(node_id) => {
                            // 尝试将 node_id 解析为 u64
                            match node_id.parse::<u64>() {
                                Ok(node_id_u64) => {
                                    log::info!("Successfully registered node {} for user {}", node_id_u64, user_id);
                                    // 使用原始代理字符串存储结果
                                    results.push((node_id_u64, original_proxy.clone(), user_id.clone()));
                                },
                                Err(e) => {
                                    log::error!("Failed to parse node_id {} as u64: {}", node_id, e);
                                }
                            }
                        },
                        Err(e) => {
                            // 检查是否是 HTTP 429 错误
                            if let crate::orchestrator::error::OrchestratorError::Http { status, .. } = &e {
                                if *status == 429 || *status == 409 {
                                    log::warn!("Rate limit or conflict (HTTP {}) for user {}, stopping registration", status, user_id);
                                    rate_limited = true;
                                    break; // 遇到速率限制或冲突，立即跳出循环
                                }
                            }
                            log::error!("Failed to register node for user {}: {}", user_id, e);
                        }
                    }

                    if !rate_limited {
                        // 添加短暂延迟，避免请求过于频繁
                        tokio::time::sleep(tokio::time::Duration::from_millis(1100)).await;
                    }
                }
            }

            // 将结果写入 CSV 文件
            if !results.is_empty() {
                match write_register_results_csv(&results, &output_filename) {
                    Ok(_) => log::info!("Successfully wrote {} results to {}", results.len(), output_filename),
                    Err(e) => log::error!("Failed to write results to CSV: {}", e),
                }
            } else {
                log::warn!("No nodes were successfully registered");
            }

            log::info!("Node registration completed");
            return Ok(());
        },
        Command::Start {
            node_id_file,
            headless,
            max_threads,
        } => {
            let node_infos = read_node_id_csv(&node_id_file)?;
            let mut handles = Vec::new();

            // 计算启动多个节点所需的总时间（以毫秒为单位）
            // 目标：2分钟内启动所有节点
            let total_time_ms = 120 * 1000;

            // 计算最佳节点启动间隔
            let num_nodes = node_infos.len();
            log::info!("共找到 {} 个节点需要启动", num_nodes);

            // 动态调整延迟区间
            let (min_delay, max_delay, total_time_ms, delay_desc) = if num_nodes <= 1 {
                (0, 0, 0, "无需延迟".to_string())
            } else if num_nodes <= 200 {
                // 少量节点时，直接用100~200ms的随机延迟
                (100, 200, 0, "每节点延迟100~200ms".to_string())
            } else {
                // 大量节点时，2分钟内均匀分配，且每次最小不少于100ms
                let total_time_ms = 120 * 1000;
                let min_delay = ((total_time_ms as f64 * 0.9) / (num_nodes as f64 - 1.0)) as u64;
                let min_delay = min_delay.max(100);
                let max_delay = (min_delay as f64 * 1.5) as u64;
                (min_delay, max_delay, total_time_ms, format!("预计在2分钟内完成（节点启动间隔: {}-{}ms）", min_delay, max_delay))
            };
            log::info!("开始启动 {} 个节点，{}", num_nodes, delay_desc);

            // 逐个启动节点
            for (i, (node_id, proxy)) in node_infos.into_iter().enumerate() {
                let env = environment.clone();
                let config_path = config_path.clone();
                let proxy_clone = proxy.clone();

                // 使用包装函数启动节点，完全在内部处理错误
                let node_id_copy = node_id;
                let handle = tokio::spawn(async move {
                    start_node_wrapper(node_id_copy, env, config_path, headless, max_threads, proxy_clone).await;
                });
                handles.push(handle);

                // 在启动下一个节点之前随机暂停
                if i < num_nodes - 1 { // 最后一个节点不需要暂停
                    use rand::Rng;
                    let delay = rand::thread_rng().gen_range(min_delay..=max_delay);

                    // 如果是大量节点，定期输出进度日志
                    if num_nodes > 100 && (i + 1) % 100 == 0 {
                        let progress = (i + 1) * 100 / num_nodes;
                        log::info!("已启动 {}/{} 个节点 ({}%)", i + 1, num_nodes, progress);
                    } else {
                        log::debug!("启动节点 {} 后暂停 {}ms", node_id, delay);
                    }

                    tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
                }
            }

            log::info!("所有 {} 个节点已成功启动", num_nodes);
            for handle in handles {
                let _ = handle.await;
            }
        }
        Command::RegisterUser { wallet_address } => {
            log::info!("Registering user with wallet address: {}", wallet_address);
            let orchestrator = Box::new(OrchestratorClient::new(environment));
            match register_user(&wallet_address, &config_path, orchestrator).await {
                Ok(_) => log::info!("Successfully registered user with wallet address: {}", wallet_address),
                Err(e) => log::error!("Failed to register user: {}", e),
            }
        }
        Command::Logout => {
            if config_path.exists() {
                match std::fs::remove_file(&config_path) {
                    Ok(_) => log::info!("Successfully logged out and removed configuration."),
                    Err(e) => log::error!("Failed to remove configuration file: {}", e),
                }
            } else {
                log::info!("No configuration found. Already logged out.");
            }
        }

    }

    Ok(())
}

/// Starts the Nexus CLI application.
///
/// # Arguments
/// * `node_id` - This client's unique identifier, if available.
/// * `env` - The environment to connect to.
/// * `config_path` - Path to the configuration file.
/// * `headless` - If true, runs without the terminal UI.
/// * `max_threads` - Optional maximum number of threads to use for proving.
async fn start(
    node_id: Option<u64>,
    env: Environment,
    config_path: std::path::PathBuf,
    _headless: bool,
    max_threads: Option<u32>,
    proxy: Option<String>,
) -> Result<(), Box<dyn Error>> {
    // Check version requirements before starting any workers
    match VersionRequirements::fetch().await {
        Ok(requirements) => {
            let current_version = env!("CARGO_PKG_VERSION");
            match requirements.check_version_constraints(current_version, None, None) {
                Ok(Some(violation)) => match violation.constraint_type {
                    crate::version_requirements::ConstraintType::Blocking => {
                        log::info!("❌ Version requirement not met: {}", violation.message);
                        std::process::exit(1);
                    }
                    crate::version_requirements::ConstraintType::Warning => {
                        log::info!("⚠️  {}", violation.message);
                    }
                    crate::version_requirements::ConstraintType::Notice => {
                        log::info!("ℹ️  {}", violation.message);
                    }
                },
                Ok(None) => {
                    // No violations found, continue
                }
                Err(e) => {
                    log::error!("❌ Failed to parse version requirements: {}", e);
                    log::error!(
                        "If this issue persists, please file a bug report at: https://github.com/nexus-xyz/nexus-cli/issues"
                    );
                    std::process::exit(1);
                }
            }
        }
        Err(VersionRequirementsError::Fetch(e)) => {
            log::error!("❌ Failed to fetch version requirements: {}", e);
            log::error!(
                "If this issue persists, please file a bug report at: https://github.com/nexus-xyz/nexus-cli/issues"
            );
            std::process::exit(1);
        }
        Err(e) => {
            log::error!("❌ Failed to check version requirements: {}", e);
            log::error!(
                "If this issue persists, please file a bug report at: https://github.com/nexus-xyz/nexus-cli/issues"
            );
            std::process::exit(1);
        }
    }

    let mut node_id = node_id;

    // If no node ID is provided, try to load it from the config file.
    if node_id.is_none() && config_path.exists() {
        let config = Config::load_from_file(&config_path)?;

        // Check if user is registered but node_id is missing or invalid
        if !config.user_id.is_empty() {
            if config.node_id.is_empty() {
                log::warn!("✅ User registered, but no node found. Please register a node to continue: nexus-cli register-node");
                return Err(
                    "Node registration required. Please run 'nexus-cli register-node' first."
                        .into(),
                );
            }

            match config.node_id.parse::<u64>() {
                Ok(id) => {
                    node_id = Some(id);
                    log::info!("✅ Found Node ID from config file, Node ID: {}", id);
                }
                Err(_) => {
                    log::error!("❌ Invalid node ID in config file. Please register a new node: nexus-cli register-node");
                    return Err("Invalid node ID in config. Please run 'nexus-cli register-node' to fix this.".into());
                }
            }
        } else {
            log::error!("❌ No user registration found. Please register your wallet address first: nexus-cli register-user --wallet-address <your-wallet-address>");
            return Err("User registration required. Please run 'nexus-cli register-user --wallet-address <your-wallet-address>' first.".into());
        }
    } else if node_id.is_none() {
        // No config file exists at all
        log::info!("Welcome to Nexus CLI! Please register your wallet address to get started: nexus-cli register-user --wallet-address <your-wallet-address>");
    }

    // Create a signing key for the prover.
    let mut csprng = rand_core::OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);

    // 创建OrchestratorClient并设置node_id
    let orchestrator_client = if let Some(id) = node_id {
        OrchestratorClient::new_with_proxy(env.clone(), proxy.clone()).with_node_id(id.to_string())
    } else {
        OrchestratorClient::new_with_proxy(env.clone(), proxy.clone())
    };

        // 获取当前出网 IP 信息
    match orchestrator_client.get_ip_info().await {
        Ok(ip_info) => {
            if let Some(id) = node_id {
                if let Some(ref proxy_str) = proxy {
                    log::info!("[node_id={}] 当前出网 IP 信息: {}, 使用代理: {}", id, ip_info, proxy_str);
                } else {
                    log::info!("[node_id={}] 当前出网 IP 信息: {}, 未使用代理", id, ip_info);
                }
            } else {
                if let Some(ref proxy_str) = proxy {
                    log::info!("当前出网 IP 信息: {}, 使用代理: {}", ip_info, proxy_str);
                } else {
                    log::info!("当前出网 IP 信息: {}, 未使用代理", ip_info);
                }
            }
        },
        Err(e) => {
            if let Some(id) = node_id {
                if let Some(ref proxy_str) = proxy {
                    log::warn!("[node_id={}] 获取 IP 信息失败: {}, 使用代理: {}", id, e, proxy_str);
                } else {
                    log::warn!("[node_id={}] 获取 IP 信息失败: {}, 未使用代理", id, e);
                }
            } else {
                if let Some(ref proxy_str) = proxy {
                    log::warn!("获取 IP 信息失败: {}, 使用代理: {}", e, proxy_str);
                } else {
                    log::warn!("获取 IP 信息失败: {}, 未使用代理", e);
                }
            }
        }
    }
    // 每个node_id只使用一个工作线程，因为我们的设计是一个node_id对应一个线程
    let num_workers: usize = 1;
    let (shutdown_sender, _) = broadcast::channel(1); // Only one shutdown signal needed

    // Get client_id for analytics - use wallet address from API if available, otherwise "anonymous"
    let client_id = if let Some(node_id) = node_id {
        match orchestrator_client.get_node(&node_id.to_string()).await {
            Ok(wallet_address) => {
                // Use wallet address as client_id for analytics
                wallet_address
            }
            Err(_) => {
                // If API call fails, use "anonymous" regardless of config
                "anonymous".to_string()
            }
        }
    } else {
        // No node_id available, use "anonymous"
        "anonymous".to_string()
    };
    log::info!("[node_id={}] 获取client_id:{}", node_id.unwrap(), client_id.clone());

    let (mut event_receiver, mut join_handles) = match node_id {
        Some(node_id) => {
            start_authenticated_workers(
                node_id,
                signing_key.clone(),
                orchestrator_client.clone(),
                num_workers,
                shutdown_sender.subscribe(),
                env.clone(),
                client_id,
            )
                .await
        }
        None => {
            start_anonymous_workers(num_workers, shutdown_sender.subscribe(), env, client_id).await
        }
    };

    // 日志模式: log events to console, 标记 node_id
    let node_id_display = node_id.map(|id| id.to_string()).unwrap_or_else(|| "anonymous".to_string());
    let shutdown_sender_clone = shutdown_sender.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = shutdown_sender_clone.send(());
        }
    });
    let mut shutdown_receiver = shutdown_sender.subscribe();
    loop {
        tokio::select! {
            Some(event) = event_receiver.recv() => {
                log::info!("[node_id={}] {}", node_id_display, event);
            }
            _ = shutdown_receiver.recv() => {
                break;
            }
        }
    }
    log::info!("\nExiting...");
    for handle in join_handles.drain(..) {
        let _ = handle.await;
    }
    log::info!("Nexus CLI application exited successfully.");
    Ok(())
}
