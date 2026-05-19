
#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>

#include "anti_debug.h"
#include "integrity.h"
#include "obfuscation.h"

static int g_failures = 0;

#define EXPECT(cond, label) do {                              \
    if (cond) {                                               \
        std::cout << "  [PASS] " << label << "\n";            \
    } else {                                                  \
        std::cout << "  [FAIL] " << label << "\n";            \
        ++g_failures;                                         \
    }                                                         \
} while(0)

static void TestObfuscation() {
    std::cout << "\n== Obfuscation ==\n";

    std::string original = "hello world";
    std::string encrypted = Obfuscation::XorString(original, 0x42);
    std::string decrypted = Obfuscation::XorString(encrypted, 0x42);
    EXPECT(decrypted == original, "XorString round-trip");
    EXPECT(encrypted != original, "Encrypted differs from plaintext");

    const uint8_t encoded[] = { 0x09, 0x3F, 0x39, 0x28, 0x3F, 0x2E, 0x6B, 0x68, 0x69 };
    std::string secret = Obfuscation::Decrypt(encoded, sizeof(encoded), 0x5A);
    EXPECT(secret == "Secret123", "Decrypt() recovers 'Secret123'");

    std::string sensitive = "password";
    Obfuscation::SecureWipe(sensitive);
    EXPECT(sensitive.empty(), "SecureWipe empties the string");
}

static void TestIntegrity() {
    std::cout << "\n== Integrity ==\n";

    std::string exe = Integrity::GetExecutablePath();
    EXPECT(!exe.empty(), "GetExecutablePath returns a non-empty path");

    uint32_t crc = Integrity::ComputeCRC32(exe);
    EXPECT(crc != 0, "ComputeCRC32 of the running exe is non-zero");

    uint32_t crc2 = Integrity::ComputeCRC32(exe);
    EXPECT(crc == crc2, "CRC32 is stable across two reads");

    uint32_t missing = Integrity::ComputeCRC32("/tmp/this_file_does_not_exist_12345");
    EXPECT(missing == 0, "ComputeCRC32 returns 0 for a missing file");
}

static void TestAntiDebug() {
    std::cout << "\n== Anti-Debug (cross-platform smoke test) ==\n";

    bool win    = AntiCrack::IsDebuggerPresent_Win();
    bool remote = AntiCrack::CheckRemoteDebugger();
    bool linux_ = AntiCrack::IsBeingDebugged_Linux();
    bool mac    = AntiCrack::IsBeingDebugged_macOS();

    std::cout << "  (info) IsDebuggerPresent_Win   = " << win << "\n";
    std::cout << "  (info) CheckRemoteDebugger     = " << remote << "\n";
    std::cout << "  (info) IsBeingDebugged_Linux   = " << linux_ << "\n";
    std::cout << "  (info) IsBeingDebugged_macOS   = " << mac << "\n";

    bool timing = AntiCrack::DetectTimingAttack();
    EXPECT(!timing, "DetectTimingAttack quiet when not debugged");
}

int main() {
    std::cout << "Anti-Crack test suite\n";
    std::cout << "=====================\n";

    TestObfuscation();
    TestIntegrity();
    TestAntiDebug();

    std::cout << "\n";
    if (g_failures == 0) {
        std::cout << "All tests passed.\n";
        return 0;
    }
    std::cout << g_failures << " test(s) failed.\n";
    return 1;
}
