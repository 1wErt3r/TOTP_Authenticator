#ifndef STORAGE_H
#define STORAGE_H

#include <vector>
#include <string>
#include <filesystem>
#include "totp.h"

static constexpr const char* FILE_HEADER = "HATOTP1.0";
static constexpr const char* STORAGE_DIR = "./";
static constexpr const char* STORAGE_FILE = "accounts.dat";

class TOTPStorage {
public:
    TOTPStorage();
    ~TOTPStorage();

    bool addAccount(const TOTPAccount& account);
    bool deleteAccount(const std::string& name);
    std::vector<TOTPAccount> listAccounts() const;
    TOTPAccount getAccount(const std::string& name) const;

    bool saveToFile();
    bool loadFromFile();
    void clearAll();

private:
    std::string storagePath;
    std::vector<TOTPAccount> accounts;

    // Master key (derived from passphrase)
    unsigned char masterKey[32];
    bool vaultUnlocked;

    // KDF parameters (stored in the header)
    uint8_t kdf_id;             // e.g., 1 = PBKDF2-SHA256
    unsigned char salt[16];     // KDF salt
    uint32_t iterations;         // KDF iterations

    // Verifier block (to verify correct passphrase)
    unsigned char verifier_iv[12];
    unsigned char verifier_tag[16];
    uint32_t verifier_cipher_len;
    std::vector<unsigned char> verifier_cipher; // ciphertext length = verifier_plain_len (8 for "VERIFIER")

    // Accounts ciphertext block
    unsigned char accounts_iv[12];
    unsigned char accounts_tag[16];
    uint32_t accounts_cipher_len;
    std::vector<unsigned char> accounts_cipher;

    // Helpers
    static std::string promptPassphrase(const std::string& prompt);
    int deriveKeyFromPassphrase(const std::string& passphrase,
                                const unsigned char* salt,
                                uint32_t iterations,
                                unsigned char* outKey) const;

    bool fileExists() const;

    // Vault setup and unlock helpers
    bool initializeNewVault(const std::string& passphrase);
    bool unlockVaultWithPassphrase(const std::string& passphrase);

    // Crypto helpers
    bool encryptWithGCM(const std::string& plaintext,
                        const unsigned char* key,
                        unsigned char* iv_out,
                        unsigned char* tag_out,
                        std::vector<unsigned char>& ciphertext_out) const;

    bool decryptWithGCM(const unsigned char* key,
                        const unsigned char* iv,
                        const unsigned char* tag,
                        const std::vector<unsigned char>& ciphertext,
                        std::string& plaintext_out) const;

    void clearSensitive();
};

#endif // STORAGE_H
