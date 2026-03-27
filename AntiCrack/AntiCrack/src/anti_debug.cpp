#include "anti_debug.h"
#include <chrono>
#include <fstream>
#include <string>
#include <thread>

#ifdef _WIN32
  #include <windows.h>
  #include <tlhelp32.h>
#endif

namespace AntiCrack {

// Windows: IsDebuggerPresent() API ашиглах

bool IsDebuggerPresent_Win() {
#ifdef _WIN32
    return ::IsDebuggerPresent() != FALSE;
#else
    return false;
#endif
}

// Windows: Remote debugger шалгах

bool CheckRemoteDebugger() {
#ifdef _WIN32
    BOOL isRemote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemote);
    return isRemote != FALSE;
#else
    return false;
#endif
}


// Timing Attack: RDTSC / хугацааны зөрүүг хэмжих
// Debugger байвал гүйцэтгэлийн хугацаа хэт удаан болно 

bool DetectTimingAttack() {
    using namespace std::chrono;
    auto start = high_resolution_clock::now();

    
    volatile int sum = 0;
    for (int i = 0; i < 1000; ++i) sum += i;

    auto end = high_resolution_clock::now();
    auto elapsed = duration_cast<microseconds>(end - start).count();

    // Хэрэв 50ms-аас их байвал debugger байж магадгүй
    return elapsed > 50000;
}


// Linux: /proc/self/status дотор TracerPid шалгах

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


// Memory Breakpoints: INT3 (0xCC) byte scan

bool CheckMemoryBreakpoints() {
    // Энэ функцийн эхний байтыг шалгана
    uint8_t* funcPtr = reinterpret_cast<uint8_t*>(&CheckMemoryBreakpoints);
    // 0xCC = INT3 breakpoint instruction
    if (*funcPtr == 0xCC) return true;
    return false;
}


// VM Detection: Registry / CPUID / artifact

bool DetectVirtualMachine() {
#ifdef _WIN32
    // VMware, VirtualBox registry keys шалгах
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
    return false;
}

// Sandbox Detection: Disk хэмжээ, CPU тоо, uptime

bool IsRunningInSandbox() {
#ifdef _WIN32
    // Sandbox дотор CPU цөм ихэвчлэн 1 байдаг
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) return true;

    // Uptime маш богино байвал (< 5 мин) sandbox байж болно
    DWORD uptime = GetTickCount() / 1000;
    if (uptime < 300) return true;
#endif
    return false;
}

// Бүх шалгалтыг нэгтгэх

bool RunAllChecks() {
    if (IsDebuggerPresent_Win())   return true;
    if (CheckRemoteDebugger())     return true;
    if (DetectTimingAttack())      return true;
    if (IsBeingDebugged_Linux())   return true;
    if (CheckMemoryBreakpoints())  return true;
    if (DetectVirtualMachine())    return true;
    if (IsRunningInSandbox())      return true;
    return false;
}

} 