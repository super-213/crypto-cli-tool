// Cryptographic CLI Tool
// A professional-grade command-line tool for file and directory encryption

use crypto_cli_tool::{cli, app, CryptoError};
use std::process;

fn main() {
    // Parse command-line arguments
    let cli_args = cli::parse_args();
    
    // Create application with default configuration
    let application = app::Application::new();
    
    // Execute the command and handle errors
    if let Err(e) = application.execute(cli_args.command) {
        // Print error message to stderr
        cli::print_error(&format!("{}", e));
        
        // Set appropriate exit code based on error type
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
            _ => 1, // Generic error
        };
        
        process::exit(exit_code);
    }
    
    // Success - exit with code 0
    process::exit(0);
}
