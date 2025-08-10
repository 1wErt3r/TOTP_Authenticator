#ifndef BASE32_H
#define BASE32_H

#include <string>
#include <vector>

namespace Base32 {
    std::vector<uint8_t> decode(const std::string& encoded);
    std::string encode(const std::vector<uint8_t>& data);
}

#endif // BASE32_H
