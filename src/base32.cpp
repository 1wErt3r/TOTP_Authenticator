#include "base32.h"
#include <cctype>
#include <stdexcept>
#include <vector>

namespace Base32 {
    // RFC 4648 Base32 alphabet (with case-insensitive support)
    static const std::string BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    static const char PADDING_CHAR = '=';

    std::vector<uint8_t> decode(const std::string& encoded) {
        std::vector<uint8_t> result;
        int buffer = 0;
        int bitsLeft = 0;
        size_t paddingCount = 0;

        for (char c : encoded) {
            // Skip whitespace and padding
            if (isspace(c)) continue;
            if (c == PADDING_CHAR) {
                paddingCount++;
                continue;
            }

            // Convert to uppercase and find index in alphabet
            c = toupper(c);
            size_t index = BASE32_CHARS.find(c);
            if (index == std::string::npos) {
                throw std::invalid_argument("Invalid Base32 character");
            }

            // Add 5 bits to the buffer
            buffer <<= 5;
            buffer |= index & 0x1F;
            bitsLeft += 5;

            // Extract complete bytes
            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                result.push_back(static_cast<uint8_t>((buffer >> bitsLeft) & 0xFF));
            }
        }

        // Verify padding
        if (paddingCount > 6 || (paddingCount > 0 && (bitsLeft + paddingCount * 5) % 8 != 0)) {
            throw std::invalid_argument("Invalid Base32 padding");
        }

        return result;
    }

    std::string encode(const std::vector<uint8_t>& data) {
        std::string result;
        int buffer = 0;
        int bitsLeft = 0;

        for (uint8_t byte : data) {
            buffer <<= 8;
            buffer |= byte & 0xFF;
            bitsLeft += 8;

            while (bitsLeft >= 5) {
                bitsLeft -= 5;
                int index = (buffer >> bitsLeft) & 0x1F;
                result += BASE32_CHARS[index];
            }
        }

        // Handle remaining bits
        if (bitsLeft > 0) {
            buffer <<= (5 - bitsLeft);
            int index = buffer & 0x1F;
            result += BASE32_CHARS[index];
        }

        // Add padding if needed
        size_t padding = (8 - (result.size() % 8)) % 8;
        result.append(padding, PADDING_CHAR);

        return result;
    }
}
