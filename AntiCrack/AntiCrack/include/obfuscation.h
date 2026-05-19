#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

namespace Obfuscation {

    std::string XorString(const std::string& input, uint8_t key);
    std::string Decrypt(const uint8_t* data, std::size_t length, uint8_t key);
    void SecureWipe(std::string& s);

}
