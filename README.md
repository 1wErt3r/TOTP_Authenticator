# TOTP Authenticator

A command-line Time-Based One-Time Password (TOTP) generator and manager with secure storage, built in C++.

## Features

- Generate TOTP codes compatible with Google Authenticator, Authy, and other 2FA services
- Securely store accounts with AES-256-GCM encryption
- Master password protection for the entire vault
- Simple command-line interface
- Cross-platform support (Linux, macOS, Windows, Haiku)

## How It Works

This TOTP Authenticator implements the standard TOTP algorithm (RFC 6238) which is used by most two-factor authentication services. When you set up 2FA on a website, you typically scan a QR code or manually enter a secret key. This application stores those secret keys securely and generates the time-based codes when you need them.

## Security

- All account data is encrypted using AES-256-GCM
- Master password is derived using PBKDF2-SHA256 with 100,000 iterations
- Each vault has a unique salt for key derivation
- Secrets are stored in an encrypted file (`accounts.dat`) in the current directory
- Memory is cleared of sensitive data when the application exits

## Prerequisites

- CMake 3.10 or higher
- OpenSSL development libraries
- C++17 compatible compiler (GCC, Clang, MSVC)

## Building

```bash
# Create build directory
mkdir build
cd build

# Configure with CMake
cmake ..

# Build the project
make

# Optionally install
# sudo make install
```

## Usage

When you first run the application, you'll be prompted to create a master password for your vault:

```bash
./TOTP_Authenticator
```

After setting up your vault, you can use the following commands:

### Add an Account

```bash
./TOTP_Authenticator add "account_name" "base32_secret"
```

Example:
```bash
./TOTP_Authenticator add "GitHub" "JBSWY3DPEHPK3PXP"
```

### List All Accounts

```bash
./TOTP_Authenticator list
```

### Generate a Code

```bash
./TOTP_Authenticator generate "account_name"
```

Example:
```bash
./TOTP_Authenticator generate "GitHub"
# Output: Code: 123456
```

### Delete an Account

```bash
./TOTP_Authenticator delete "account_name"
```

### Show Help

```bash
./TOTP_Authenticator help
```

## Storage

Account data is stored in an encrypted file named `accounts.dat` in the current directory. The file format is:

```
HATOTP1.0[KDF ID][16-byte salt][4-byte iterations][verifier block][accounts block]
```

Where:
- `HATOTP1.0` is the file header
- KDF ID: 1 = PBKDF2-SHA256
- Salt: Random 16-byte value for key derivation
- Iterations: Number of PBKDF2 iterations (100,000)
- Verifier block: Encrypted "VERIFIER" string to verify passphrase
- Accounts block: Encrypted account data

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Acknowledgments

- Implements RFC 6238 for TOTP generation
- Uses OpenSSL for cryptographic operations
- Base32 encoding/decoding based on RFC 4648