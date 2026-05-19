#include "obfuscation.h"
#include <algorithm>

namespace Obfuscation {

std::string XorString(const std::string& input, uint8_t key) {
    std::string out(input);
    for (auto& c : out) {
        c = static_cast<char>(static_cast<uint8_t>(c) ^ key);
    }
    return out;
}

std::string Decrypt(const uint8_t* data, std::size_t length, uint8_t key) {
    std::string out;
    out.reserve(length);
    for (std::size_t i = 0; i < length; ++i) {
        out.push_back(static_cast<char>(data[i] ^ key));
    }
    return out;
}

void SecureWipe(std::string& s) {
    // `volatile` discourages the optimizer from removing the wipe.
    volatile char* p = const_cast<volatile char*>(s.data());
    for (std::size_t i = 0; i < s.size(); ++i) p[i] = 0;
    s.clear();
}

} // namespace Obfuscation
