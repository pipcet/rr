#include <string>

#include "TicksSource.h"

#include <elf.h>
#include "PerfCounters.h"

#include <asm/ldt.h>
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <string>

#include "Flags.h"
#include "kernel_metadata.h"
#include "log.h"
#include "util.h"
#include "Task.h"

#include "AddressSpace.h"
#include "AutoRemoteSyscalls.h"
#include "Event.h"
#include "ExtraRegisters.h"
#include "FdTable.h"
#include "PerfCounters.h"
#include "PropertyTable.h"
#include "Registers.h"
#include "TaskishUid.h"
#include "TraceStream.h"
#include "WaitStatus.h"
#include "kernel_abi.h"
#include "kernel_supplement.h"
#include "remote_code_ptr.h"
#include "util.h"
#include "ReplaySession.h"

using namespace std;

namespace rr {

static string lowercase(const string& s) {
  string c = s;
  transform(c.begin(), c.end(), c.begin(), ::tolower);
  return c;
}

static struct {
  string name;
  CpuMicroarch uarch;
} cpu_microarchs[] = {
  { "IntelMerom", IntelMerom },
  { "IntelPenryn", IntelPenryn },
  { "IntelNehalem", IntelNehalem },
  { "IntelWestmere", IntelWestmere },
  { "IntelSandyBridge", IntelSandyBridge },
  { "IntelIvyBridge", IntelIvyBridge },
  { "IntelHaswell", IntelHaswell },
  { "IntelBroadwell", IntelBroadwell },
  { "IntelSkylake", IntelSkylake },
  { "AMDFamily15h", AMDFamily15h },
  { "IntelMerom", IntelMerom },
};

/**
 * Return the detected, known microarchitecture of this CPU, or don't
 * return; i.e. never return UnknownCpu.
 */
static CpuMicroarch get_cpu_microarch() {
  string forced_uarch = lowercase(Flags::get().forced_uarch);
  if (!forced_uarch.empty()) {
    for (size_t i = 0; i < array_length(cpu_microarchs); ++i) {
      auto& arch = cpu_microarchs[i];
      string name = lowercase(arch.name);
      if (name.npos != name.find(forced_uarch)) {
        LOG(info) << "Using forced uarch " << arch.name;
        return arch.uarch;
      }
    }
    FATAL() << "Forced uarch " << Flags::get().forced_uarch << " isn't known.";
  }

  auto cpuid_data = cpuid(CPUID_GETVENDORSTRING, 0);

  if (cpuid_data.ebx == 'A' + ('u' << 8) + ('t' << 16) + ('h' << 24)) {
    cpuid_data = cpuid(CPUID_GETFEATURES, 0);

    if (((cpuid_data.eax >> 8) & 0xf) +
        ((cpuid_data.eax >> 20) & 0xff) == 0x15)
      return AMDFamily15h;

    FATAL() << "CPU " << HEX(cpuid_data.eax) << " unknown.";
    return UnknownCpu; // not reached
  }

  cpuid_data = cpuid(CPUID_GETFEATURES, 0);
  unsigned int cpu_type = (cpuid_data.eax & 0xF0FF0);
  switch (cpu_type) {
    case 0x006F0:
    case 0x10660:
      return IntelMerom;
    case 0x10670:
    case 0x106D0:
      return IntelPenryn;
    case 0x106A0:
    case 0x106E0:
    case 0x206E0:
      return IntelNehalem;
    case 0x20650:
    case 0x206C0:
    case 0x206F0:
      return IntelWestmere;
    case 0x206A0:
    case 0x206D0:
    case 0x306e0:
      return IntelSandyBridge;
    case 0x306A0:
      return IntelIvyBridge;
    case 0x306C0:
    case 0x306F0:
    case 0x40650:
    case 0x40660:
      return IntelHaswell;
    case 0x306D0:
    case 0x406F0:
    case 0x50660:
      return IntelBroadwell;
    case 0x406e0:
    case 0x506e0:
      return IntelSkylake;
    default:
      FATAL() << "CPU " << HEX(cpu_type) << " unknown.";
      return UnknownCpu; // not reached
  }
}

/* static */ TicksSource* TicksSource::open(Task* t)
{
  CpuMicroarch uarch = get_cpu_microarch();

  switch (uarch) {
  default:
    return new PerfCounters(uarch, t->tid);
  }
}

}
