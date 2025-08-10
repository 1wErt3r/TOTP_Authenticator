#include "totp.h"
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <ctime>
#include <cmath>
#include <algorithm>

TOTP::TOTP(const std::string& secret, int digits, int period) 
    : digits(digits), period(period) {
    // Convert base32 secret to bytes
    // (Implementation depends on your base32 decoder)
}

uint64_t TOTP::getCurrentTimestamp() const {
    return static_cast<uint64_t>(time(nullptr)) / period;
}

std::vector<uint8_t> TOTP::hmacSha1(const std::vector<uint8_t>& key, const std::vector<uint8_t>& msg) const {
    std::vector<uint8_t> result(SHA_DIGEST_LENGTH);
    unsigned int len = SHA_DIGEST_LENGTH;
    
    HMAC(EVP_sha1(), key.data(), key.size(), msg.data(), msg.size(), result.data(), &len);
    
    return result;
}

int TOTP::dynamicTruncation(const std::vector<uint8_t>& hmacResult) const {
    int offset = hmacResult[hmacResult.size() - 1] & 0x0F;
    
    int binary = ((hmacResult[offset] & 0x7F) << 24) |
                 ((hmacResult[offset + 1] & 0xFF) << 16) |
                 ((hmacResult[offset + 2] & 0xFF) << 8) |
                 (hmacResult[offset + 3] & 0xFF);
    
    return binary;
}

std::string TOTP::generateCode() const {
    uint64_t counter = getCurrentTimestamp();
    
    std::vector<uint8_t> counterBytes(8);
    for (int i = 7; i >= 0; --i) {
        counterBytes[i] = static_cast<uint8_t>(counter & 0xFF);
        counter >>= 8;
    }
    
    auto hmacResult = hmacSha1(secretKey, counterBytes);
    int code = dynamicTruncation(hmacResult) % static_cast<int>(std::pow(10, digits));
    
    // Format with leading zeros
    char format[10];
    snprintf(format, sizeof(format), "%%0%dd", digits);
    
    char codeStr[digits + 1];
    snprintf(codeStr, sizeof(codeStr), format, code);
    
    return std::string(codeStr);
}

bool TOTP::verifyCode(const std::string& secret, const std::string& code, int digits, int period) {
    TOTP totp(secret, digits, period);
    return totp.generateCode() == code;
}
