// ============================================================
//  Anti-Crack: Multi-layered Software Protection Demo
//  -----------------------------------------------------------
//  Phase 1: Target program — license prompt
//  Phase 2: Anti-debugging
//  Phase 3: XOR string obfuscation (no plaintext password in binary)
//  Phase 4: Self-integrity check (CRC32)
//  Phase 5: Anti-VM / Anti-sandbox checks
// ============================================================

#include <cstdint>
#include <iostream>
#include <string>

#include "anti_debug.h"
#include "integrity.h"
#include "obfuscation.h"

// ---- Terminate cleanly with a reason ----------------------
[[noreturn]] static void TerminateProgram(const char* reason) {
    std::cerr << "[SECURITY] Terminated: " << reason << std::endl;
    std::exit(1);
}

// ---- Phase 3: XOR-obfuscated license key ------------------
// Plaintext "Secret123" XOR'd byte-by-byte with key 0x5A.
// Stored as raw bytes in the binary; a static analyzer running
// `strings` on the executable will not see "Secret123".
static const uint8_t kEncryptedLicense[] = {
    0x09, 0x3F, 0x39, 0x28, 0x3F, 0x2E, 0x6B, 0x68, 0x69
};
static constexpr uint8_t kXorKey = 0x5A;

int main() {
    std::cout << "============================================\n";
    std::cout << "  Secure License Validator\n";
    std::cout << "============================================\n\n";

    // ---- Phase 2: Anti-debug ------------------------------
    std::cout << "[1/3] Running anti-debug checks...\n";
    if (AntiCrack::IsDebuggerPresent_Win())
        TerminateProgram("Debugger detected (WinAPI)");
    if (AntiCrack::CheckRemoteDebugger())
        TerminateProgram("Remote debugger detected");
    if (AntiCrack::CheckPEB_BeingDebugged())
        TerminateProgram("Debugger detected (PEB)");
    if (AntiCrack::IsBeingDebugged_Linux())
        TerminateProgram("Debugger detected (Linux TracerPid)");
    if (AntiCrack::IsBeingDebugged_macOS())
        TerminateProgram("Debugger detected (macOS sysctl)");
    if (AntiCrack::DetectTimingAttack())
        TerminateProgram("Timing anomaly detected");

    // ---- Phase 5: Anti-VM / Anti-sandbox -------------------
    if (AntiCrack::DetectVirtualMachine())
        TerminateProgram("Virtual machine detected");
    if (AntiCrack::IsRunningInSandbox())
        TerminateProgram("Sandbox environment detected");
    std::cout << "      OK\n";

    // ---- Phase 4: Self-integrity check ---------------------
    std::cout << "[2/3] Verifying binary integrity...\n";
    if (!Integrity::VerifySelf())
        TerminateProgram("Binary has been modified!");
    std::cout << "      OK\n";

    // ---- Phase 1 + 3: License prompt -----------------------
    std::cout << "[3/3] License check\n";
    std::string correct = Obfuscation::Decrypt(
        kEncryptedLicense, sizeof(kEncryptedLicense), kXorKey);

    std::cout << "      Enter license key: ";
    std::string userInput;
    std::getline(std::cin, userInput);

    bool ok = (userInput == correct);
    Obfuscation::SecureWipe(correct);  // don't leave the plaintext in RAM

    if (!ok) {
        std::cout << "\n[FAIL] Invalid license key.\n";
        return 1;
    }

    std::cout << "\n============================================\n";
    std::cout << "  [SUCCESS] License accepted. Welcome!\n";
    std::cout << "============================================\n";

    // Your real application logic would run here.
    return 0;
}

