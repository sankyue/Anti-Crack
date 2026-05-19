#pragma once
#include <cstdint>
#include <string>

namespace AntiCrack {

    //Anti-Debugging
    bool IsDebuggerPresent_Win();      // Windows: IsDebuggerPresent()
    bool CheckRemoteDebugger();        // Windows: CheckRemoteDebuggerPresent()
    bool CheckPEB_BeingDebugged();     // Windows: read PEB directly (advanced)
    bool IsBeingDebugged_Linux();      // Linux:   /proc/self/status TracerPid
    bool IsBeingDebugged_macOS();      // macOS:   sysctl P_TRACED flag
    bool DetectTimingAttack();         // Cross-platform: timing anomaly
    bool CheckMemoryBreakpoints();     // Cross-platform: detect 0xCC bytes

    //Anti-VM / Anti-Sandbox
    bool DetectVirtualMachine();       // VMware, VirtualBox detection
    bool IsRunningInSandbox();         // Cuckoo, generic sandbox detection
    bool CheckCPUID_Hypervisor();      // x86/x64 CPUID hypervisor bit

   
    bool RunAllChecks();

} 
