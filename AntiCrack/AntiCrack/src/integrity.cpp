#include "integrity.h"
#include <array>
#include <fstream>
#include <iostream>

#ifdef _WIN32
    #include <windows.h>
#elif defined(__APPLE__)
    #include <mach-o/dyld.h>
    #include <climits>
#elif defined(__linux__)
    #include <unistd.h>
    #include <climits>
#endif

namespace Integrity {

static std::array<uint32_t, 256> BuildCRC32Table() {
    std::array<uint32_t, 256> table{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int j = 0; j < 8; ++j) {
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        table[i] = c;
    }
    return table;
}

static const auto CRC32_TABLE = BuildCRC32Table();

uint32_t ComputeCRC32(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return 0;

    uint32_t crc = 0xFFFFFFFFu;
    char buffer[4096];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        std::streamsize count = file.gcount();
        for (std::streamsize i = 0; i < count; ++i) {
            uint8_t byte = static_cast<uint8_t>(buffer[i]);
            crc = CRC32_TABLE[(crc ^ byte) & 0xFFu] ^ (crc >> 8);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

bool VerifyFileHash(const std::string& filepath, uint32_t expectedCRC) {
    return ComputeCRC32(filepath) == expectedCRC;
}

// ---------------------------------------------------------------------
// Resolve the running executable's full path (platform-specific)
// ---------------------------------------------------------------------
std::string GetExecutablePath() {
#ifdef _WIN32
    char path[MAX_PATH];
    DWORD len = GetModuleFileNameA(nullptr, path, MAX_PATH);
    return std::string(path, len);
#elif defined(__APPLE__)
    char path[1024];
    uint32_t size = sizeof(path);
    if (_NSGetExecutablePath(path, &size) == 0) {
        return std::string(path);
    }
    return "";
#elif defined(__linux__)
    char path[PATH_MAX];
    ssize_t count = readlink("/proc/self/exe", path, PATH_MAX);
    if (count > 0) return std::string(path, count);
    return "";
#else
    return "";
#endif
}

bool VerifySelf() {
    std::string exePath = GetExecutablePath();
    if (exePath.empty()) return false;

    std::string hashPath = exePath + ".hash";
    uint32_t currentCRC = ComputeCRC32(exePath);
    if (currentCRC == 0) return false;

    // Try to read the stored baseline hash
    std::ifstream in(hashPath);
    if (in) {
        uint32_t storedCRC = 0;
        in >> std::hex >> storedCRC;
        in.close();
        return storedCRC == currentCRC;
    }

    // First run — write the baseline and accept
    std::ofstream out(hashPath);
    if (!out) return false;
    out << std::hex << currentCRC;
    return true;
}

} // namespace Integrity
