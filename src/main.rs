// Cryptographic CLI Tool
// 加密 CLI 工具
// A professional-grade command-line tool for file and directory encryption
// 专业级的文件和目录加密命令行工具

use crypto_cli_tool::{cli, app, CryptoError, i18n};
use std::process;

fn main() {
    // Parse command-line arguments
    // 解析命令行参数
    let cli_args = cli::parse_args();

    // Initialize language from CLI flag
    // 从命令行参数初始化语言
    let language = match i18n::parse_language(&cli_args.language) {
        Some(lang) => lang,
        None => {
            cli::print_error(&format!(
                "Invalid language: {}. Supported: en, zh",
                cli_args.language
            ));
            process::exit(4);
        }
    };
    i18n::set_language(language);
    
    // Create application with default configuration
    // 使用默认配置创建应用程序
    let application = app::Application::new();

    let result = if cli_args.wizard {
        application.run_interactive_wizard()
    } else if let Some(command) = cli_args.command {
        application.execute(command)
    } else {
        Err(CryptoError::MissingRequiredArgument(
            i18n::t("missing command", "缺少命令").to_string(),
        ))
    };
    
    // Execute the command and handle errors
    // 执行命令并处理错误
    if let Err(e) = result {
        // Print error message to stderr
        // 将错误消息打印到 stderr
        cli::print_error(&format!("{}", e));
        
        // Set appropriate exit code based on error type
        // 根据错误类型设置适当的退出代码
        let exit_code = match e {
            CryptoError::FileNotFound(_) => 2,
            CryptoError::PermissionDenied(_) => 3,
            CryptoError::InvalidArguments(_) => 4,
            CryptoError::MissingRequiredArgument(_) => 4,
            CryptoError::AuthenticationFailed => 5,
            CryptoError::InvalidPassword => 5,
            CryptoError::DecryptionFailed(_) => 5,
            CryptoError::EncryptionFailed(_) => 6,
            CryptoError::InvalidKey => 7,
            CryptoError::KeyDerivationFailed => 7,
            CryptoError::KeyGenerationFailed => 7,
            CryptoError::InvalidFileFormat => 8,
            CryptoError::UnsupportedVersion(_) => 8,
            CryptoError::CorruptedHeader => 8,
            CryptoError::InsufficientMemory => 9,
            _ => 1, // Generic error / 通用错误
        };
        
        process::exit(exit_code);
    }
    
    // Success - exit with code 0
    // 成功 - 以代码 0 退出
    process::exit(0);
}
