#include "anti_debug.h"
#include <chrono>
#include <fstream>
#include <string>
#include <thread>
#include <cstring>

#ifdef _WIN32
    #include <windows.h>
    #include <tlhelp32.h>
    #include <intrin.h>
#elif defined(__APPLE__)
    #include <sys/sysctl.h>
    #include <unistd.h>
    #include <sys/types.h>
#elif defined(__linux__)
    #include <unistd.h>
#endif

namespace AntiCrack {

// =====================================================================
// Windows: IsDebuggerPresent() — the simplest possible check
// =====================================================================
bool IsDebuggerPresent_Win() {
#ifdef _WIN32
    return ::IsDebuggerPresent() != FALSE;
#else
    return false;
#endif
}

// =====================================================================
// Windows: CheckRemoteDebuggerPresent() — detects debuggers in other procs
// =====================================================================
bool CheckRemoteDebugger() {
#ifdef _WIN32
    BOOL isRemote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemote);
    return isRemote != FALSE;
#else
    return false;
#endif
}

// =====================================================================
// Windows: Read the PEB->BeingDebugged flag directly from memory.
// Crackers can patch IsDebuggerPresent() to return FALSE, but this
// reads the kernel-maintained flag without going through the API.
// =====================================================================
bool CheckPEB_BeingDebugged() {
#ifdef _WIN32
    #if defined(_M_X64) || defined(__x86_64__)
        // x64: PEB pointer is at gs:[0x60], BeingDebugged at PEB+0x02
        unsigned char* peb = reinterpret_cast<unsigned char*>(__readgsqword(0x60));
        return peb[0x02] != 0;
    #elif defined(_M_IX86) || defined(__i386__)
        // x86: PEB pointer is at fs:[0x30], BeingDebugged at PEB+0x02
        unsigned char* peb = reinterpret_cast<unsigned char*>(__readfsdword(0x30));
        return peb[0x02] != 0;
    #else
        return false;
    #endif
#else
    return false;
#endif
}

// =====================================================================
// Linux: parse /proc/self/status for TracerPid != 0
// =====================================================================
bool IsBeingDebugged_Linux() {
#ifdef __linux__
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.find("TracerPid:") != std::string::npos) {
            int tracerPid = std::stoi(line.substr(line.find(':') + 1));
            return tracerPid != 0;
        }
    }
#endif
    return false;
}

// =====================================================================
// macOS: sysctl returns P_TRACED in kp_proc.p_flag when a debugger
// (lldb, gdb) is attached. Apple's own "anti-debug" textbook trick.
// =====================================================================
bool IsBeingDebugged_macOS() {
#ifdef __APPLE__
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, ::getpid() };
    struct kinfo_proc info;
    std::memset(&info, 0, sizeof(info));
    size_t size = sizeof(info);
    if (::sysctl(mib, 4, &info, &size, nullptr, 0) == 0) {
        return (info.kp_proc.p_flag & P_TRACED) != 0;
    }
#endif
    return false;
}

// =====================================================================
// Timing-based check. Stepping through under a debugger makes a trivial
// loop take far longer than it should.
// =====================================================================
bool DetectTimingAttack() {
    using namespace std::chrono;
    auto start = high_resolution_clock::now();

    volatile int sum = 0;
    for (int i = 0; i < 1000; ++i) sum += i;

    auto end = high_resolution_clock::now();
    auto elapsed = duration_cast<microseconds>(end - start).count();

    // 50ms for 1000 trivial additions = something is single-stepping us.
    return elapsed > 50000;
}

// =====================================================================
// Scan the start of a function for 0xCC (INT3 software breakpoint).
// A real debugger software-breakpoint patches the first instruction.
// =====================================================================
bool CheckMemoryBreakpoints() {
    uint8_t* funcPtr = reinterpret_cast<uint8_t*>(&CheckMemoryBreakpoints);
    if (*funcPtr == 0xCC) return true;
    return false;
}

// =====================================================================
// CPUID hypervisor bit: ECX bit 31 of CPUID leaf 1 is set inside a VM.
// Works on x86/x64 across all OSes. Reliable except against VMs that
// deliberately hide themselves.
// =====================================================================
bool CheckCPUID_Hypervisor() {
#if defined(_M_X64) || defined(__x86_64__) || defined(_M_IX86) || defined(__i386__)
    unsigned int ecx = 0;
    #ifdef _WIN32
        int regs[4];
        __cpuid(regs, 1);
        ecx = static_cast<unsigned int>(regs[2]);
    #else
        unsigned int eax_out, ebx_out, edx_out;
        __asm__ volatile (
            "cpuid"
            : "=a"(eax_out), "=b"(ebx_out), "=c"(ecx), "=d"(edx_out)
            : "a"(1), "c"(0)
        );
        (void)eax_out; (void)ebx_out; (void)edx_out;
    #endif
    return (ecx & (1u << 31)) != 0;
#else
    return false;  // ARM, etc.
#endif
}

// =====================================================================
// Windows registry-based VM detection (VMware / VirtualBox guest tools)
// =====================================================================
bool DetectVirtualMachine() {
#ifdef _WIN32
    const char* vmKeys[] = {
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        nullptr
    };
    for (int i = 0; vmKeys[i]; ++i) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, vmKeys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
    }
#endif
    // Also try the universal CPUID check
    return CheckCPUID_Hypervisor();
}

// =====================================================================
// Sandbox heuristics: few CPUs + short uptime = likely an analysis sandbox
// =====================================================================
bool IsRunningInSandbox() {
#ifdef _WIN32
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) return true;

    DWORD uptime = GetTickCount() / 1000;
    if (uptime < 300) return true;
#endif
    return false;
}

// =====================================================================
// One call to rule them all
// =====================================================================
bool RunAllChecks() {
    if (IsDebuggerPresent_Win())   return true;
    if (CheckRemoteDebugger())     return true;
    if (CheckPEB_BeingDebugged())  return true;
    if (IsBeingDebugged_Linux())   return true;
    if (IsBeingDebugged_macOS())   return true;
    if (DetectTimingAttack())      return true;
    if (CheckMemoryBreakpoints())  return true;
    if (DetectVirtualMachine())    return true;
    if (IsRunningInSandbox())      return true;
    return false;
}

} 
