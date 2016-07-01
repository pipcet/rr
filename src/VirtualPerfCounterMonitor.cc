/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "VirtualPerfCounterMonitor.h"

#include <linux/perf_event.h>
#include <stdlib.h>

#include "AutoRemoteSyscalls.h"
#include "RecordSession.h"
#include "RecordTask.h"
#include "log.h"

using namespace std;

namespace rr {

bool VirtualPerfCounterMonitor::should_virtualize() {
  return true;
}

VirtualPerfCounterMonitor::VirtualPerfCounterMonitor(
    Task* t, Task* target, const struct perf_event_attr& attr)
    : initial_ticks(target->tick_count()),
      target_tuid(target->tuid()),
      owner_tid(0),
      flags(0),
      sig(0),
      enabled(false) {
  (void) attr;
  ASSERT(t, should_virtualize());
  // XXX When we support interrupts, we need to add code for signal dispatching
  ASSERT(t, attr.sample_period == 0xffffffff) << "Don't support interrupts yet";
}

bool VirtualPerfCounterMonitor::emulate_ioctl(RecordTask* t, uint64_t* result) {
  switch ((int)t->regs().arg2()) {
    case PERF_EVENT_IOC_ENABLE:
      *result = 0;
      enabled = true;
      break;
    default:
      ASSERT(t, false) << "Unsupported perf event ioctl "
                       << HEX((int)t->regs().arg2());
      break;
  }
  return true;
}

bool VirtualPerfCounterMonitor::emulate_fcntl(RecordTask* t, uint64_t* result) {
  *result = -(int64_t)EINVAL;
  switch ((int)t->regs().arg2()) {
    case F_SETOWN_EX: {
      auto owner = t->read_mem(remote_ptr<struct f_owner_ex>(t->regs().arg3()));
      ASSERT(t, owner.type == F_OWNER_TID)
          << "Unsupported perf event F_SETOWN_EX type " << owner.type;
      owner_tid = owner.pid;
      *result = 0;
      break;
    }
    case F_SETFL:
      ASSERT(t, !(t->regs().arg3() & ~O_ASYNC))
          << "Unsupported perf event flags " << HEX((int)t->regs().arg3());
      flags = (int)t->regs().arg3();
      *result = 0;
      break;
    case F_SETSIG:
      sig = (int)t->regs().arg3();
      *result = 0;
      break;
    default:
      ASSERT(t, false) << "Unsupported perf event fnctl "
                       << HEX((int)t->regs().arg2());
      break;
  }
  return true;
}

static size_t write_ranges(RecordTask* t,
                           const vector<FileMonitor::Range>& ranges, void* data,
                           size_t size) {
  uint8_t* p = static_cast<uint8_t*>(data);
  size_t s = size;
  size_t result = 0;
  for (auto& r : ranges) {
    size_t bytes = min(s, r.length);
    t->write_bytes_helper(r.data, bytes, p);
    s -= bytes;
    result += bytes;
  }
  return result;
}

bool VirtualPerfCounterMonitor::emulate_read(RecordTask* t,
                                             const vector<Range>& ranges,
                                             int64_t, uint64_t* result) {
  RecordTask* target = t->session().find_task(target_tuid);
  if (target) {
    int64_t val = target->tick_count() - initial_ticks;
    *result = write_ranges(t, ranges, &val, sizeof(val));
  } else {
    *result = 0;
  }
  return true;
}

} // namespace rr
