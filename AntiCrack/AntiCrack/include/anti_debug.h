#pragma once
#include <cstdint>
#include <string>

namespace AntiCrack {

    bool IsDebuggerPresent_Win();
    bool CheckRemoteDebugger();
    bool DetectTimingAttack();
    bool IsBeingDebugged_Linux();
    bool CheckMemoryBreakpoints();
    bool DetectVirtualMachine();
    bool IsRunningInSandbox();
    bool RunAllChecks();

} // namespace AntiCrack