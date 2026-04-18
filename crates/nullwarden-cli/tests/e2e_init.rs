use nullwarden_cli::config::Config;
use nullwarden_cli::input::validate_password_strength;
use nullwarden_cli::session::{save_access_token, load_access_token, clear_access_token};
use tempfile::tempdir;
use std::fs;

#[test]
fn test_password_strength_validation() {
    assert!(validate_password_strength("weak").is_err());
    assert!(validate_password_strength("this-is-a-strong-password-123!").is_ok());
}

#[tokio::test]
async fn test_config_lifecycle() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    let vault_path = dir.path().join("vault.nwd");
    
    let mut config = Config::default();
    config.vault_path = vault_path.clone();
    config.server_url = "http://localhost:8080".to_string();
    
    // Test saving
    fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    let toml = toml::to_string_pretty(&config).unwrap();
    fs::write(&config_path, toml).unwrap();
    
    // Test loading
    let raw = fs::read_to_string(&config_path).unwrap();
    let loaded: Config = toml::from_str(&raw).unwrap();
    
    assert_eq!(loaded.server_url, config.server_url);
    assert_eq!(loaded.vault_path, config.vault_path);
}
