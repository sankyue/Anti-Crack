#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

namespace Obfuscation {

    // XOR every byte of `input` with `key` and return the result.
    // Symmetric: encrypt and decrypt are the same operation.
    std::string XorString(const std::string& input, uint8_t key);

    // Decrypt an obfuscated byte array (the form stored in the binary)
    // back to a usable string at runtime.
    std::string Decrypt(const uint8_t* data, std::size_t length, uint8_t key);

    // Wipe a string from memory (overwrite with zeros).
    // Use after you're done with a decrypted secret to limit how long
    // it sits readable in RAM.
    void SecureWipe(std::string& s);

} // namespace Obfuscation
