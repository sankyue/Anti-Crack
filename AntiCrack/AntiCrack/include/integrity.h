#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace Integrity {
    uint32_t ComputeCRC32(const std::string& filepath);
    bool VerifyFileHash(const std::string& filepath, uint32_t expectedCRC);
    std::string GetExecutablePath();

    bool VerifySelf();

} 
