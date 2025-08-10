#ifndef TOTP_H
#define TOTP_H

#include <string>
#include <vector>

// Struct to represent a TOTP account
struct TOTPAccount {
    std::string name;
    std::string secret;
    int digits;
    int period;
    std::string issuer;
};

class TOTP {
public:
    TOTP(const std::string& secret, int digits = 6, int period = 30);
    
    std::string generateCode() const;
    static bool verifyCode(const std::string& secret, const std::string& code, int digits = 6, int period = 30);
    
private:
    std::vector<uint8_t> secretKey;
    int digits;
    int period;
    
    uint64_t getCurrentTimestamp() const;
    std::vector<uint8_t> hmacSha1(const std::vector<uint8_t>& key, const std::vector<uint8_t>& msg) const;
    int dynamicTruncation(const std::vector<uint8_t>& hmacResult) const;
};

#endif // TOTP_H
