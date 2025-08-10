#include "storage.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <termios.h>
#include <unistd.h>
#include <filesystem>

#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

// Helper: read password from terminal without echo
namespace {
    std::string promptPassphraseInternal(const std::string& prompt) {
        std::cout << prompt;
        std::cout.flush();

        struct termios oldt, newt;
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);

        std::string pass;
        std::getline(std::cin, pass);

        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        std::cout << std::endl;
        return pass;
    }
}

TOTPStorage::TOTPStorage()
{
    // Build storage path
    storagePath = std::string(STORAGE_DIR) + "/" + STORAGE_FILE;

    // Ensure storage directory exists
    std::filesystem::path dirPath(STORAGE_DIR);
    if (!std::filesystem::exists(dirPath)) {
        std::filesystem::create_directories(dirPath);
    }

    // If no file exists, initialize a new vault (first run)
    if (!fileExists()) {
        std::string pass = promptPassphraseInternal("Create a master password for your vault: ");
        std::string passConfirm = promptPassphraseInternal("Confirm master password: ");
        if (pass != passConfirm) {
            std::cerr << "Passwords do not match. Aborting vault creation." << std::endl;
            throw std::runtime_error("Vault creation failed");
        }
        if (!initializeNewVault(pass)) {
            std::cerr << "Vault initialization failed." << std::endl;
            throw std::runtime_error("Vault initialization failed");
        }
        vaultUnlocked = true;
        std::cout << "New vault created and unlocked." << std::endl;
        return;
    }

    // Existing vault: prompt to unlock
    std::string pass = promptPassphraseInternal("Enter vault passphrase: ");
    std::cout << "Attempting to unlock vault..." << std::endl;
    
    // Load encrypted data from file first
    if (!loadFromFile()) {
        std::cerr << "Failed to load vault data from file." << std::endl;
        throw std::runtime_error("Failed to load vault data");
    }
    
    // Now try to unlock with the passphrase
    if (!unlockVaultWithPassphrase(pass)) {
        std::cerr << "Invalid passphrase." << std::endl;
        throw std::runtime_error("Failed to unlock vault");
    }

    std::cout << "Vault unlocked successfully." << std::endl;
}

TOTPStorage::~TOTPStorage() {
    clearSensitive();
    // Do not attempt to re-encrypt on destruction; caller manages persistence.
}

bool TOTPStorage::addAccount(const TOTPAccount& account) {
    // Check if account already exists
    for (auto& acc : accounts) {
        if (acc.name == account.name) {
            printf("Account '%s' already exists\n", account.name.c_str());
            return false;
        }
    }

    accounts.push_back(account);
    printf("[DEBUG] Account added to vector, attempting save...\n");
    bool saveResult = saveToFile();
    printf("[DEBUG] saveToFile returned: %s\n", saveResult ? "true" : "false");
    return saveResult;
}

bool TOTPStorage::deleteAccount(const std::string& name) {
    for (auto it = accounts.begin(); it != accounts.end(); ++it) {
        if (it->name == name) {
            accounts.erase(it);
            return saveToFile();
        }
    }
    return false;
}

std::vector<TOTPAccount> TOTPStorage::listAccounts() const {
    return accounts;
}

TOTPAccount TOTPStorage::getAccount(const std::string& name) const {
    for (const auto& acc : accounts) {
        if (acc.name == name) {
            return acc;
        }
    }
    throw std::runtime_error("Account not found");
}

bool TOTPStorage::saveToFile()
{
    if (!vaultUnlocked) {
        fprintf(stderr, "Vault not unlocked; cannot save.\n");
        return false;
    }

    try {
        // Prepare plaintext of accounts
        std::stringstream plainData;
        for (const auto& account : accounts) {
            plainData << account.name << "\n"
                      << account.secret << "\n"
                      << account.digits << "\n"
                      << account.period << "\n"
                      << account.issuer << "\n---\n";
        }

        std::string plaintextAccounts = plainData.str();

        // Encrypt accounts with masterKey (AES-256-GCM)
        std::vector<unsigned char> accountsCipherText;
        unsigned char accountsIv[12];
        if (RAND_bytes(accountsIv, sizeof(accountsIv)) != 1) {
            throw std::runtime_error("Failed to generate accounts IV");
        }

        unsigned char accountsTag[16];
        if (!encryptWithGCM(plaintextAccounts,
                            masterKey,
                            accountsIv,
                            accountsTag,
                            accountsCipherText)) {
            throw std::runtime_error("Accounts encryption failed");
        }

        // Prepare verifier: encrypt a known plaintext "VERIFIER"
        const std::string verifierPlain = "VERIFIER";
        unsigned char verifierIv[12];
        if (RAND_bytes(verifierIv, sizeof(verifierIv)) != 1) {
            throw std::runtime_error("Failed to generate verifier IV");
        }
        std::vector<unsigned char> verifierCipher;
        unsigned char verifierTag[16];
        if (!encryptWithGCM(verifierPlain,
                            masterKey,
                            verifierIv,
                            verifierTag,
                            verifierCipher)) {
            throw std::runtime_error("Verifier encryption failed");
        }

        // Write all to file in a fixed layout
        std::ofstream file(storagePath, std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            printf("Failed to open storage file for writing: %s\n", storagePath.c_str());
            return false;
        }

        // Header
        file.write(FILE_HEADER, 8);

        // KDF params
        file.put(static_cast<char>(kdf_id)); // 1 = PBKDF2-SHA256
        file.write(reinterpret_cast<const char*>(salt), 16);
        // iterations little-endian
        uint32_t itLE = iterations;
        file.write(reinterpret_cast<const char*>(&itLE), 4);

        // Verifier block
        file.write(reinterpret_cast<const char*>(verifierIv), 12);
        file.write(reinterpret_cast<const char*>(verifierTag), 16);
        uint32_t verCipherLen = static_cast<uint32_t>(verifierCipher.size());
        file.write(reinterpret_cast<const char*>(&verCipherLen), 4);
        if (verCipherLen > 0) {
            file.write(reinterpret_cast<const char*>(verifierCipher.data()), verCipherLen);
        }

        // Accounts block
        file.write(reinterpret_cast<const char*>(accountsIv), 12);
        file.write(reinterpret_cast<const char*>(accountsTag), 16);
        uint32_t accCipherLen = static_cast<uint32_t>(accountsCipherText.size());
        file.write(reinterpret_cast<const char*>(&accCipherLen), 4);
        if (accCipherLen > 0) {
            file.write(reinterpret_cast<const char*>(accountsCipherText.data()), accCipherLen);
        }

        file.close();
        return true;
    } catch (const std::exception& e) {
        fprintf(stderr, "Save failed: %s\n", e.what());
        return false;
    }
}

bool TOTPStorage::loadFromFile()
{
    std::filesystem::path filePath(storagePath);
    if (!std::filesystem::exists(filePath)) {
        // No file is not an error on first run; handled in constructor
        return false;
    }

    std::ifstream file(storagePath, std::ios::binary);
    if (!file.is_open()) {
        printf("Failed to open storage file\n");
        return false;
    }

    // Read header
    char header[9] = {0};
    file.read(header, 8);
    if (strncmp(header, FILE_HEADER, 8) != 0) {
        printf("Corrupted storage file - invalid header\n");
        file.close();
        return false;
    }

    // Read KDF params
    uint8_t read_kdf_id = 0;
    file.get(reinterpret_cast<char&>(read_kdf_id));
    kdf_id = read_kdf_id;
    file.read(reinterpret_cast<char*>(salt), 16);
    file.read(reinterpret_cast<char*>(&iterations), 4);
    
    // Convert iterations from little-endian to host byte order if needed
    // For simplicity, we assume little-endian file format on all platforms

    // Read verifier block
    file.read(reinterpret_cast<char*>(verifier_iv), 12);
    file.read(reinterpret_cast<char*>(verifier_tag), 16);
    file.read(reinterpret_cast<char*>(&verifier_cipher_len), 4);
    verifier_cipher.clear();
    verifier_cipher.resize(verifier_cipher_len);
    if (verifier_cipher_len > 0) {
        file.read(reinterpret_cast<char*>(verifier_cipher.data()), verifier_cipher_len);
    }

    // Read accounts block
    file.read(reinterpret_cast<char*>(accounts_iv), 12);
    file.read(reinterpret_cast<char*>(accounts_tag), 16);
    file.read(reinterpret_cast<char*>(&accounts_cipher_len), 4);
    accounts_cipher.clear();
    accounts_cipher.resize(accounts_cipher_len);
    if (accounts_cipher_len > 0) {
        file.read(reinterpret_cast<char*>(accounts_cipher.data()), accounts_cipher_len);
    }

    file.close();

    // At this point, we should have the encrypted payload; now we need the passphrase to decrypt
    // However, this function is used after unlocking. For safety, we'll just return true here
    // and actual decryption happens in unlockVaultWithPassphrase().
    return true;
}

void TOTPStorage::clearAll()
{
    accounts.clear();
    std::filesystem::remove(storagePath);
    clearSensitive();
}

std::string TOTPStorage::promptPassphrase(const std::string& prompt)
{
    return promptPassphraseInternal(prompt);
}

int TOTPStorage::deriveKeyFromPassphrase(const std::string& passphrase,
                                       const unsigned char* salt_in,
                                       uint32_t iterations_in,
                                       unsigned char* outKey) const
{
    // PBKDF2-HMAC-SHA256
    if (PKCS5_PBKDF2_HMAC(passphrase.c_str(),
                          static_cast<int>(passphrase.length()),
                          salt_in,
                          16,
                          iterations_in,
                          EVP_sha256(),
                          32,
                          outKey) != 1) {
        return -1;
    }
    return 0;
}

bool TOTPStorage::fileExists() const
{
    return std::filesystem::exists(storagePath);
}

bool TOTPStorage::initializeNewVault(const std::string& passphrase)
{
    std::cout << "[DEBUG] Initializing new vault" << std::endl;
    
    // Generate new salt
    if (RAND_bytes(salt, 16) != 1) {
        std::cout << "[DEBUG] Failed to generate salt" << std::endl;
        return false;
    }
    iterations = 100000; // tune as needed
    kdf_id = 1; // PBKDF2-SHA256

    // Derive key
    unsigned char derivedKey[32];
    if (deriveKeyFromPassphrase(passphrase, salt, iterations, derivedKey) != 0) {
        std::cout << "[DEBUG] Failed to derive key from passphrase" << std::endl;
        return false;
    }
    std::cout << "[DEBUG] Key derivation successful" << std::endl;

    // Create verifier: "VERIFIER" plaintext
    const std::string verifierPlain = "VERIFIER";
    unsigned char verifierIvLocal[12];
    if (RAND_bytes(verifierIvLocal, sizeof(verifierIvLocal)) != 1) {
        std::cout << "[DEBUG] Failed to generate verifier IV" << std::endl;
        return false;
    }
    
    std::vector<unsigned char> verifierCipherVec;
    unsigned char verifierTagLocal[16];
    if (!encryptWithGCM(verifierPlain, derivedKey, verifierIvLocal, verifierTagLocal, verifierCipherVec)) {
        std::cout << "[DEBUG] Failed to encrypt verifier" << std::endl;
        return false;
    }
    std::cout << "[DEBUG] Verifier encryption successful" << std::endl;
    
    // Store verifier data for later use
    std::memcpy(verifier_iv, verifierIvLocal, 12);
    verifier_cipher_len = static_cast<uint32_t>(verifierCipherVec.size());
    verifier_cipher = verifierCipherVec;
    std::memcpy(verifier_tag, verifierTagLocal, 16);

    // Accounts block starts empty
    unsigned char accountsIvLocal[12];
    if (RAND_bytes(accountsIvLocal, sizeof(accountsIvLocal)) != 1) {
        std::cout << "[DEBUG] Failed to generate accounts IV" << std::endl;
        return false;
    }
    
    // Empty accounts plaintext
    std::string accountsPlain = "";
    std::vector<unsigned char> accountsCipherVec;
    unsigned char accountsTagLocal[16];
    if (!encryptWithGCM(accountsPlain, derivedKey, accountsIvLocal, accountsTagLocal, accountsCipherVec)) {
        std::cout << "[DEBUG] Failed to encrypt accounts" << std::endl;
        return false;
    }
    std::cout << "[DEBUG] Accounts encryption successful" << std::endl;
    
    // Store accounts data for later use
    std::memcpy(accounts_iv, accountsIvLocal, 12);
    accounts_cipher_len = static_cast<uint32_t>(accountsCipherVec.size());
    accounts_cipher = accountsCipherVec;
    std::memcpy(accounts_tag, accountsTagLocal, 16);

    // Write all to file in a fixed layout
    std::ofstream file(storagePath, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        printf("Failed to open storage file for writing: %s\n", storagePath.c_str());
        return false;
    }

    // Header
    file.write(FILE_HEADER, 8);

    // KDF params
    file.put(static_cast<char>(kdf_id)); // 1 = PBKDF2-SHA256
    file.write(reinterpret_cast<const char*>(salt), 16);
    // iterations little-endian
    uint32_t itLE = iterations;
    file.write(reinterpret_cast<const char*>(&itLE), 4);

    // Verifier block
    file.write(reinterpret_cast<const char*>(verifier_iv), 12);
    file.write(reinterpret_cast<const char*>(verifier_tag), 16);
    uint32_t verCipherLen = static_cast<uint32_t>(verifierCipherVec.size());
    file.write(reinterpret_cast<const char*>(&verCipherLen), 4);
    if (verCipherLen > 0) {
        file.write(reinterpret_cast<const char*>(verifierCipherVec.data()), verCipherLen);
    }

    // Accounts block
    file.write(reinterpret_cast<const char*>(accounts_iv), 12);
    file.write(reinterpret_cast<const char*>(accounts_tag), 16);
    uint32_t accCipherLen = static_cast<uint32_t>(accountsCipherVec.size());
    file.write(reinterpret_cast<const char*>(&accCipherLen), 4);
    if (accCipherLen > 0) {
        file.write(reinterpret_cast<const char*>(accountsCipherVec.data()), accCipherLen);
    }

    file.close();
    std::cout << "[DEBUG] New vault created and saved to file successfully" << std::endl;
    return true;
}

bool TOTPStorage::unlockVaultWithPassphrase(const std::string& passphrase)
{
    std::cout << "[DEBUG] Attempting to unlock vault with provided passphrase" << std::endl;
    
    // Derive key with same salt and iterations
    unsigned char derivedKey[32];
    if (deriveKeyFromPassphrase(passphrase, salt, iterations, derivedKey) != 0) {
        std::cout << "[DEBUG] Failed to derive key from passphrase" << std::endl;
        return false;
    }
    std::cout << "[DEBUG] Key derivation successful" << std::endl;

    // Attempt to decrypt verifier:
    // verifier_cipher_len gives length
    std::string verifierPlainGuess;
    if (!decryptWithGCM(derivedKey, verifier_iv, verifier_tag, verifier_cipher, verifierPlainGuess)) {
        // Wrong passphrase
        std::cout << "[DEBUG] Failed to decrypt verifier - incorrect passphrase" << std::endl;
        return false;
    }
    std::cout << "[DEBUG] Verifier decryption successful" << std::endl;
    
    // Optional: check verifierPlainGuess == "VERIFIER"
    if (verifierPlainGuess != "VERIFIER") {
        std::cout << "[DEBUG] Verifier content mismatch. Expected 'VERIFIER', got '" << verifierPlainGuess << "'" << std::endl;
        return false;
    }
    std::cout << "[DEBUG] Verifier content verified successfully" << std::endl;

    // Passphrase verified, now copy the derived key to masterKey
    std::memcpy(masterKey, derivedKey, 32);
    vaultUnlocked = true;
    std::cout << "[DEBUG] Vault unlocked successfully" << std::endl;

    // If there is an accounts payload, decrypt it to memory
    if (accounts_cipher_len > 0) {
        std::cout << "[DEBUG] Decrypting accounts data" << std::endl;
        std::string accountsPlain;
        if (!decryptWithGCM(masterKey, accounts_iv, accounts_tag, accounts_cipher, accountsPlain)) {
            std::cout << "[DEBUG] Failed to decrypt accounts data" << std::endl;
            return false;
        }
        std::cout << "[DEBUG] Accounts decryption successful" << std::endl;
        
        // Parse accountsPlain into accounts vector
        accounts.clear();
        std::stringstream ss(accountsPlain);
        std::string line;
        TOTPAccount currentAccount;
        int field = 0;
        while (std::getline(ss, line)) {
            if (line == "---") {
                accounts.push_back(currentAccount);
                currentAccount = TOTPAccount();
                field = 0;
                continue;
            }
            switch (field) {
                case 0: currentAccount.name = line; break;
                case 1: currentAccount.secret = line; break;
                case 2: currentAccount.digits = std::stoi(line); break;
                case 3: currentAccount.period = std::stoi(line); break;
                case 4: currentAccount.issuer = line; break;
            }
            field++;
        }
        std::cout << "[DEBUG] Parsed " << accounts.size() << " accounts from storage" << std::endl;
        // If file ends without trailing "---", it's a corrupted format; ignore for now
    }

    return true;
}

bool TOTPStorage::encryptWithGCM(const std::string& plaintext,
                               const unsigned char* key,
                               unsigned char* iv_out,
                               unsigned char* tag_out,
                               std::vector<unsigned char>& ciphertext_out) const
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv_out) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int len = 0;
    ciphertext_out.resize(plaintext.size());
    if (EVP_EncryptUpdate(ctx, ciphertext_out.data(), &len,
                          reinterpret_cast<const unsigned char*>(plaintext.data()),
                          (int)plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext_out.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;
    ciphertext_out.resize(ciphertext_len);

    // Get the GCM tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag_out) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool TOTPStorage::decryptWithGCM(const unsigned char* key,
                               const unsigned char* iv,
                               const unsigned char* tag,
                               const std::vector<unsigned char>& ciphertext,
                               std::string& plaintext_out) const
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int len = 0;
    std::vector<unsigned char> plaintext(ciphertext.size());
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                          ciphertext.data(), (int)ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int plaintext_len = len;

    // Set the expected GCM tag for decryption
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len += len;

    plaintext_out.assign(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

void TOTPStorage::clearSensitive()
{
    std::memset(masterKey, 0, sizeof(masterKey));
    vaultUnlocked = false;
    // Do not clear stored accounts; they are part of the vault content
}

#include <openssl/evp.h>
#include <openssl/rand.h>
