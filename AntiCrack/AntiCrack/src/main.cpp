#include <iostream>

#include "anti_debug.h"

#include "integrity.h"

void TerminateProgram(const char* reason) {

    std::cerr << "[SECURITY] Terminated: " << reason << std::endl;

    // Санах ойг цэвэрлэх, log бичих боломжтой

    std::exit(1);

}

int main() {

    std::cout << "Starting security checks...\n";

    // 1. Anti-debug шалгалт

    if (AntiCrack::IsDebuggerPresent_Win())

        TerminateProgram("Debugger detected (WinAPI)");

    if (AntiCrack::CheckRemoteDebugger())

        TerminateProgram("Remote debugger detected");

    if (AntiCrack::IsBeingDebugged_Linux())

        TerminateProgram("Debugger detected (Linux TracerPid)");

    if (AntiCrack::DetectTimingAttack())

        TerminateProgram("Timing anomaly detected");

    if (AntiCrack::DetectVirtualMachine())

        TerminateProgram("Virtual machine detected");

    // 2. File integrity шалгалт

    // if (!Integrity::VerifySelf())

    //     TerminateProgram("Binary has been modified!");

    std::cout << "All checks passed. Program running.\n";

    // Таны үндсэн программ логик энд орно

    return 0;

}
 
