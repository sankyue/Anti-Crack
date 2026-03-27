#pragma once
#include <string>
#include <cstdint>
#include <vector>

namespace Integrity {

    // CRC32 hash тооцох
    uint32_t ComputeCRC32(const std::string& filepath);

    // Файлын hash-ийг хадгалсантай харьцуулах
    bool VerifyFileHash(const std::string& filepath, uint32_t expectedCRC);

    // Өөрийн exe-г шалгах (self-integrity)
    bool VerifySelf();

} // namespace Integrity