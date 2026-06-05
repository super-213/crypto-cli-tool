// Interactive wizard for user-friendly encryption/decryption workflows.
// 交互式向导，用于更友好的加密/解密流程。

use crate::app::Application;
use crate::error::{CryptoError, Result};
use crate::file_handler::{Algorithm as FileAlgorithm, EncryptedFileHeader};
use crate::i18n::{self, Language};
use crate::key_manager::{self, KdfAlgorithm, SecureBytes, SecureString};
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Input, Password, Select};
use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardOperation {
    Encrypt,
    Decrypt,
}

#[derive(Debug, Clone, Copy)]
pub struct AlgorithmChoice {
    pub algorithm: FileAlgorithm,
    pub name: &'static str,
    pub description_en: &'static str,
    pub description_zh: &'static str,
}

const ENCRYPTION_ALGORITHMS: &[AlgorithmChoice] = &[
    AlgorithmChoice {
        algorithm: FileAlgorithm::Aes256Gcm,
        name: "AES-256-GCM",
        description_en: "default recommendation, suitable for most files, detects tampering",
        description_zh: "默认推荐，适合大多数文件，支持篡改检测",
    },
    AlgorithmChoice {
        algorithm: FileAlgorithm::ChaCha20Poly1305,
        name: "ChaCha20-Poly1305",
        description_en: "good for mobile or systems without AES hardware acceleration",
        description_zh: "适合移动设备或无 AES 硬件加速环境",
    },
    AlgorithmChoice {
        algorithm: FileAlgorithm::Aes256Cbc,
        name: "AES-256-CBC",
        description_en: "legacy compatibility; integrity protected with HMAC-SHA256",
        description_zh: "兼容旧系统，使用 HMAC-SHA256 提供完整性保护",
    },
    AlgorithmChoice {
        algorithm: FileAlgorithm::RsaOaep2048,
        name: "RSA-OAEP-2048",
        description_en: "hybrid public-key encryption for sharing encrypted files",
        description_zh: "非对称混合加密，适合共享加密文件",
    },
    AlgorithmChoice {
        algorithm: FileAlgorithm::RsaOaep4096,
        name: "RSA-OAEP-4096",
        description_en: "higher security margin, slower than RSA-OAEP-2048",
        description_zh: "安全余量更高，但速度更慢",
    },
    AlgorithmChoice {
        algorithm: FileAlgorithm::EciesP256,
        name: "ECIES-P256",
        description_en: "shorter keys and efficient hybrid public-key encryption",
        description_zh: "密钥较短，效率较高的非对称混合加密",
    },
];

pub fn run(app: &Application) -> Result<()> {
    let theme = ColorfulTheme::default();
    let language = select_language(&theme)?;
    i18n::set_language(language);

    let input_path = prompt_input_path(&theme)?;
    let operation = select_operation(&theme, &input_path)?;

    match operation {
        WizardOperation::Encrypt => {
            let algorithm = select_encryption_algorithm(&theme)?;
            let (key, kdf_params) = prompt_encryption_key(app, &theme)?;
            let default_output = default_output_path(&input_path, operation)?;
            let output_path = prompt_output_path(&theme, &default_output)?;

            println!("{}", i18n::t("Encrypting...", "正在加密..."));
            app.encrypt_with_key(
                &input_path,
                &output_path,
                &key,
                algorithm,
                None,
                Some(kdf_params),
                input_path.is_dir(),
            )?;

            println!(
                "{}",
                if i18n::is_zh() {
                    format!("加密完成：{}", output_path.display())
                } else {
                    format!("Encryption completed: {}", output_path.display())
                }
            );
        }
        WizardOperation::Decrypt => {
            let header = detect_header(&input_path)?;
            if let Some(header) = &header {
                println!(
                    "{}",
                    if i18n::is_zh() {
                        format!("已识别算法：{}", algorithm_name(header.algorithm))
                    } else {
                        format!("Detected algorithm: {}", algorithm_name(header.algorithm))
                    }
                );
            } else {
                println!(
                    "{}",
                    i18n::t(
                        "Could not read algorithm metadata from the file. This version can only decrypt CRYPTOOL files with a valid header.",
                        "无法从文件读取算法元数据。当前版本只能解密包含有效 CRYPTOOL 文件头的文件。",
                    )
                );
                let _ = select_fallback_algorithm(&theme)?;
            }

            let header = header.ok_or(CryptoError::InvalidFileFormat)?;
            let key = prompt_decryption_key(&theme, &header)?;
            let default_output = default_output_path(&input_path, operation)?;
            let output_path = prompt_output_path(&theme, &default_output)?;
            decrypt_with_retries(app, &theme, &input_path, &output_path, &header, key)?;
        }
    }

    Ok(())
}

fn select_language(theme: &ColorfulTheme) -> Result<Language> {
    let items = ["中文", "English"];
    let default = if i18n::is_zh() { 0 } else { 1 };
    let selected = Select::with_theme(theme)
        .with_prompt("Select language / 请选择语言")
        .items(&items)
        .default(default)
        .interact_opt()
        .map_err(dialoguer_error)?;

    match selected {
        Some(0) => Ok(Language::Chinese),
        Some(_) => Ok(Language::English),
        None => cancelled(),
    }
}

fn prompt_input_path(theme: &ColorfulTheme) -> Result<PathBuf> {
    loop {
        let raw: String = Input::with_theme(theme)
            .with_prompt(i18n::t(
                "Enter the file or directory path to process (you can drag it into the terminal)",
                "请输入要处理的文件或目录路径（可直接拖入终端）",
            ))
            .interact_text()
            .map_err(dialoguer_error)?;

        if is_quit(&raw) {
            return cancelled();
        }

        match clean_dragged_path(&raw).and_then(validate_input_path) {
            Ok(path) => return Ok(path),
            Err(error) => eprintln!("{}: {}", i18n::t("Error", "错误"), error),
        }
    }
}

fn select_operation(theme: &ColorfulTheme, input_path: &Path) -> Result<WizardOperation> {
    let items = [
        i18n::t("Encrypt", "加密").to_string(),
        i18n::t("Decrypt", "解密").to_string(),
    ];
    let default = match default_operation(input_path) {
        WizardOperation::Encrypt => 0,
        WizardOperation::Decrypt => 1,
    };

    let selected = Select::with_theme(theme)
        .with_prompt(i18n::t("Select operation", "请选择操作"))
        .items(&items)
        .default(default)
        .interact_opt()
        .map_err(dialoguer_error)?;

    match selected {
        Some(0) => Ok(WizardOperation::Encrypt),
        Some(1) => Ok(WizardOperation::Decrypt),
        _ => cancelled(),
    }
}

fn select_encryption_algorithm(theme: &ColorfulTheme) -> Result<FileAlgorithm> {
    loop {
        let items: Vec<String> = encryption_algorithm_options()
            .iter()
            .map(format_algorithm_choice)
            .collect();

        let selected = Select::with_theme(theme)
            .with_prompt(i18n::t("Select encryption algorithm", "请选择加密算法"))
            .items(&items)
            .default(0)
            .interact_opt()
            .map_err(dialoguer_error)?;

        let Some(index) = selected else {
            return cancelled();
        };

        let algorithm = encryption_algorithm_options()[index].algorithm;
        if is_asymmetric(algorithm) {
            println!(
                "{}",
                i18n::t(
                    "Public-key file encryption is listed for compatibility, but is not wired into the current file format implementation yet. Please choose a symmetric algorithm.",
                    "非对称文件加密已在算法列表中保留，但当前文件格式实现尚未接入。请先选择对称算法。",
                )
            );
            continue;
        }

        return Ok(algorithm);
    }
}

fn select_fallback_algorithm(theme: &ColorfulTheme) -> Result<FileAlgorithm> {
    let items: Vec<String> = encryption_algorithm_options()
        .iter()
        .map(format_algorithm_choice)
        .collect();
    let selected = Select::with_theme(theme)
        .with_prompt(i18n::t("Select algorithm manually", "请手动选择算法"))
        .items(&items)
        .default(0)
        .interact_opt()
        .map_err(dialoguer_error)?;

    selected
        .map(|index| encryption_algorithm_options()[index].algorithm)
        .ok_or_else(cancelled_error)
}

fn prompt_encryption_key(
    app: &Application,
    theme: &ColorfulTheme,
) -> Result<(SecureBytes, (KdfAlgorithm, u32, Vec<u8>))> {
    loop {
        let password = Password::with_theme(theme)
            .with_prompt(i18n::t("Enter password", "请输入密码"))
            .interact()
            .map_err(dialoguer_error)?;

        let confirm = Password::with_theme(theme)
            .with_prompt(i18n::t("Confirm password", "请再次输入密码"))
            .interact()
            .map_err(dialoguer_error)?;

        if password != confirm {
            eprintln!(
                "{}",
                i18n::t(
                    "Passwords do not match. Please try again.",
                    "两次输入的密码不一致，请重新输入。",
                )
            );
            continue;
        }

        if password.len() < 12 {
            let keep = Confirm::with_theme(theme)
                .with_prompt(i18n::t(
                    "Password is shorter than 12 characters. Continue anyway?",
                    "密码少于 12 个字符，存在风险。仍然继续？",
                ))
                .default(false)
                .interact()
                .map_err(dialoguer_error)?;
            if !keep {
                continue;
            }
        }

        let password = SecureString::from(password);
        let salt = key_manager::generate_salt()?;
        let key = derive_key_from_password(app, &password, &salt, None)?;
        let kdf_params = (
            app.config().default_kdf,
            app.config().kdf_iterations,
            salt.to_vec(),
        );
        return Ok((key, kdf_params));
    }
}

fn decrypt_with_retries(
    app: &Application,
    theme: &ColorfulTheme,
    input_path: &Path,
    output_path: &Path,
    header: &EncryptedFileHeader,
    initial_key: SecureBytes,
) -> Result<()> {
    let mut key = initial_key;
    loop {
        println!("{}", i18n::t("Decrypting...", "正在解密..."));
        match app.decrypt_with_key(input_path, output_path, &key) {
            Ok(()) => {
                println!(
                    "{}",
                    if i18n::is_zh() {
                        format!("解密完成：{}", output_path.display())
                    } else {
                        format!("Decryption completed: {}", output_path.display())
                    }
                );
                return Ok(());
            }
            Err(CryptoError::AuthenticationFailed)
            | Err(CryptoError::InvalidPassword)
            | Err(CryptoError::DecryptionFailed(_)) => {
                eprintln!(
                    "{}",
                    i18n::t(
                        "Decryption failed or authentication failed.",
                        "解密失败或认证失败。",
                    )
                );
                let retry = Confirm::with_theme(theme)
                    .with_prompt(i18n::t("Try another password?", "是否重新输入密码？"))
                    .default(true)
                    .interact()
                    .map_err(dialoguer_error)?;
                if !retry {
                    return cancelled();
                }
                key = prompt_decryption_key(theme, header)?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn prompt_decryption_key(
    theme: &ColorfulTheme,
    header: &EncryptedFileHeader,
) -> Result<SecureBytes> {
    let password = Password::with_theme(theme)
        .with_prompt(i18n::t("Enter password", "请输入密码"))
        .interact()
        .map_err(dialoguer_error)?;
    let password = SecureString::from(password);
    derive_key_from_header(&password, header)
}

fn prompt_output_path(theme: &ColorfulTheme, default_output: &Path) -> Result<PathBuf> {
    loop {
        let prompt = if i18n::is_zh() {
            format!("保存路径（直接回车使用默认：{}）", default_output.display())
        } else {
            format!(
                "Output path (press Enter for default: {})",
                default_output.display()
            )
        };

        let raw: String = Input::with_theme(theme)
            .with_prompt(prompt)
            .allow_empty(true)
            .interact_text()
            .map_err(dialoguer_error)?;

        if is_quit(&raw) {
            return cancelled();
        }

        let output = if raw.trim().is_empty() {
            default_output.to_path_buf()
        } else {
            let cleaned = clean_dragged_path(&raw)?;
            if cleaned.is_dir() {
                let file_name = default_output.file_name().ok_or_else(|| {
                    CryptoError::InvalidArguments(
                        i18n::t(
                            "Default output path has no file name",
                            "默认输出路径缺少文件名",
                        )
                        .to_string(),
                    )
                })?;
                cleaned.join(file_name)
            } else {
                cleaned
            }
        };

        validate_output_parent(&output)?;
        if !output.exists() {
            return Ok(output);
        }

        match confirm_overwrite(theme, &output)? {
            OverwriteDecision::Reenter => continue,
            OverwriteDecision::Overwrite => return Ok(output),
            OverwriteDecision::Cancel => return cancelled(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum OverwriteDecision {
    Reenter,
    Overwrite,
    Cancel,
}

fn confirm_overwrite(theme: &ColorfulTheme, output: &Path) -> Result<OverwriteDecision> {
    eprintln!(
        "{}",
        if i18n::is_zh() {
            format!("输出路径已存在：{}", output.display())
        } else {
            format!("Output path already exists: {}", output.display())
        }
    );

    let items = [
        i18n::t("Enter another path", "重新输入路径").to_string(),
        i18n::t("Overwrite", "覆盖").to_string(),
        i18n::t("Cancel", "取消操作").to_string(),
    ];

    let selected = Select::with_theme(theme)
        .with_prompt(i18n::t("Choose how to continue", "请选择如何继续"))
        .items(&items)
        .default(0)
        .interact_opt()
        .map_err(dialoguer_error)?;

    match selected {
        Some(0) => Ok(OverwriteDecision::Reenter),
        Some(1) => Ok(OverwriteDecision::Overwrite),
        Some(2) => Ok(OverwriteDecision::Cancel),
        _ => cancelled(),
    }
}

fn derive_key_from_header(
    password: &SecureString,
    header: &EncryptedFileHeader,
) -> Result<SecureBytes> {
    let (Some(kdf), Some(iterations), Some(salt)) =
        (header.kdf, header.kdf_iterations, header.salt.as_ref())
    else {
        return Err(CryptoError::InvalidArguments(
            i18n::t(
                "File was not encrypted with password-based encryption",
                "文件未使用基于密码的加密方式",
            )
            .to_string(),
        ));
    };

    derive_key_by_kdf(password, salt, kdf, iterations)
}

fn derive_key_from_password(
    app: &Application,
    password: &SecureString,
    salt: &[u8],
    iterations: Option<u32>,
) -> Result<SecureBytes> {
    derive_key_by_kdf(
        password,
        salt,
        app.config().default_kdf,
        iterations.unwrap_or(app.config().kdf_iterations),
    )
}

fn derive_key_by_kdf(
    password: &SecureString,
    salt: &[u8],
    kdf: KdfAlgorithm,
    iterations: u32,
) -> Result<SecureBytes> {
    match kdf {
        KdfAlgorithm::Pbkdf2Sha256 => {
            key_manager::derive_key_pbkdf2(password, salt, iterations, 32)
        }
        KdfAlgorithm::Argon2id => key_manager::derive_key_argon2id(password, salt, 19456, 2, 32),
    }
}

fn detect_header(input_path: &Path) -> Result<Option<EncryptedFileHeader>> {
    let input_file = fs::File::open(input_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CryptoError::FileNotFound(input_path.to_path_buf())
        } else if e.kind() == std::io::ErrorKind::PermissionDenied {
            CryptoError::PermissionDenied(input_path.to_path_buf())
        } else {
            CryptoError::FileReadError(input_path.to_path_buf(), e)
        }
    })?;
    let mut reader = BufReader::new(input_file);

    match EncryptedFileHeader::read_from(&mut reader) {
        Ok(header) => Ok(Some(header)),
        Err(CryptoError::InvalidFileFormat)
        | Err(CryptoError::CorruptedHeader)
        | Err(CryptoError::UnsupportedVersion(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

pub fn clean_dragged_path(raw: &str) -> Result<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CryptoError::InvalidArguments(
            i18n::t("Path cannot be empty", "路径不能为空").to_string(),
        ));
    }

    if let Ok(parts) = shell_words::split(trimmed) {
        if parts.len() == 1 {
            return Ok(PathBuf::from(&parts[0]));
        }

        let joined = parts.join(" ");
        if Path::new(&joined).exists() {
            return Ok(PathBuf::from(joined));
        }
    }

    let unquoted = trimmed
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| {
            trimmed
                .strip_prefix('\'')
                .and_then(|s| s.strip_suffix('\''))
        })
        .unwrap_or(trimmed);

    let mut output = String::with_capacity(unquoted.len());
    let mut escaped = false;
    for ch in unquoted.chars() {
        if escaped {
            output.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else {
            output.push(ch);
        }
    }
    if escaped {
        output.push('\\');
    }

    Ok(PathBuf::from(output))
}

fn validate_input_path(path: PathBuf) -> Result<PathBuf> {
    let metadata = fs::metadata(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CryptoError::FileNotFound(path.clone())
        } else if e.kind() == std::io::ErrorKind::PermissionDenied {
            CryptoError::PermissionDenied(path.clone())
        } else {
            CryptoError::FileReadError(path.clone(), e)
        }
    })?;

    if metadata.is_file() {
        fs::File::open(&path).map_err(|e| CryptoError::FileReadError(path.clone(), e))?;
        return Ok(path);
    }

    if metadata.is_dir() {
        if !directory_has_processable_content(&path)? {
            return Err(CryptoError::InvalidArguments(
                i18n::t(
                    "Directory has no processable files",
                    "目录中没有可处理的文件",
                )
                .to_string(),
            ));
        }
        return Ok(path);
    }

    Err(CryptoError::InvalidPath(path))
}

fn directory_has_processable_content(path: &Path) -> Result<bool> {
    for entry in
        fs::read_dir(path).map_err(|e| CryptoError::FileReadError(path.to_path_buf(), e))?
    {
        let entry = entry.map_err(|e| CryptoError::FileReadError(path.to_path_buf(), e))?;
        let metadata = entry
            .metadata()
            .map_err(|e| CryptoError::FileReadError(entry.path(), e))?;
        if metadata.is_file() {
            return Ok(true);
        }
        if metadata.is_dir() && directory_has_processable_content(&entry.path())? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_output_parent(output: &Path) -> Result<()> {
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let metadata = fs::metadata(parent).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CryptoError::DirectoryNotFound(parent.to_path_buf())
        } else if e.kind() == std::io::ErrorKind::PermissionDenied {
            CryptoError::PermissionDenied(parent.to_path_buf())
        } else {
            CryptoError::FileReadError(parent.to_path_buf(), e)
        }
    })?;

    if !metadata.is_dir() {
        return Err(CryptoError::NotADirectory(parent.to_path_buf()));
    }

    let probe = parent.join(format!(".crypto_cli_write_test_{}", std::process::id()));
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = fs::remove_file(&probe);
            Ok(())
        }
        Err(e) => Err(CryptoError::FileWriteError(parent.to_path_buf(), e)),
    }
}

pub fn default_operation(input_path: &Path) -> WizardOperation {
    if input_path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("enc"))
    {
        WizardOperation::Decrypt
    } else {
        WizardOperation::Encrypt
    }
}

pub fn default_output_path(input_path: &Path, operation: WizardOperation) -> Result<PathBuf> {
    let cwd = std::env::current_dir().map_err(CryptoError::IoError)?;
    let file_name = input_path
        .file_name()
        .ok_or_else(|| CryptoError::InvalidPath(input_path.to_path_buf()))?;
    let file_name = file_name.to_string_lossy();

    let output_name = match operation {
        WizardOperation::Encrypt => format!("{}.enc", file_name),
        WizardOperation::Decrypt => file_name
            .strip_suffix(".enc")
            .map(str::to_string)
            .unwrap_or_else(|| format!("{}.dec", file_name)),
    };

    Ok(cwd.join(output_name))
}

pub fn encryption_algorithm_options() -> &'static [AlgorithmChoice] {
    ENCRYPTION_ALGORITHMS
}

fn format_algorithm_choice(choice: &AlgorithmChoice) -> String {
    let description = if i18n::is_zh() {
        choice.description_zh
    } else {
        choice.description_en
    };
    format!("{:<20} {}", choice.name, description)
}

fn algorithm_name(algorithm: FileAlgorithm) -> &'static str {
    match algorithm {
        FileAlgorithm::Aes256Gcm => "AES-256-GCM",
        FileAlgorithm::Aes256Cbc => "AES-256-CBC",
        FileAlgorithm::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        FileAlgorithm::RsaOaep2048 => "RSA-OAEP-2048",
        FileAlgorithm::RsaOaep4096 => "RSA-OAEP-4096",
        FileAlgorithm::EciesP256 => "ECIES-P256",
    }
}

fn is_asymmetric(algorithm: FileAlgorithm) -> bool {
    matches!(
        algorithm,
        FileAlgorithm::RsaOaep2048 | FileAlgorithm::RsaOaep4096 | FileAlgorithm::EciesP256
    )
}

fn is_quit(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "q" | "quit" | "exit"
    )
}

fn cancelled<T>() -> Result<T> {
    Err(cancelled_error())
}

fn cancelled_error() -> CryptoError {
    CryptoError::InvalidArguments(i18n::t("Operation cancelled", "用户取消操作").to_string())
}

fn dialoguer_error(error: dialoguer::Error) -> CryptoError {
    CryptoError::SystemError(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_dragged_path_handles_quotes_and_escapes() {
        assert_eq!(
            clean_dragged_path("\"/tmp/a b.txt\"").unwrap(),
            PathBuf::from("/tmp/a b.txt")
        );
        assert_eq!(
            clean_dragged_path("'/tmp/a b.txt'").unwrap(),
            PathBuf::from("/tmp/a b.txt")
        );
        assert_eq!(
            clean_dragged_path("/tmp/a\\ b.txt").unwrap(),
            PathBuf::from("/tmp/a b.txt")
        );
    }

    #[test]
    fn default_operation_prefers_decrypt_for_enc_extension() {
        assert_eq!(
            default_operation(Path::new("secret.txt.enc")),
            WizardOperation::Decrypt
        );
        assert_eq!(
            default_operation(Path::new("secret.txt")),
            WizardOperation::Encrypt
        );
    }

    #[test]
    fn algorithm_options_include_required_descriptions() {
        let options = encryption_algorithm_options();
        assert_eq!(options.len(), 6);
        assert!(options.iter().any(|item| item.name == "AES-256-GCM"
            && !item.description_en.is_empty()
            && !item.description_zh.is_empty()));
        assert!(options.iter().any(|item| item.name == "ECIES-P256"
            && !item.description_en.is_empty()
            && !item.description_zh.is_empty()));
    }
}
