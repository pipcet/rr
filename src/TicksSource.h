#ifndef RR_TICKSSOURCE_H_
#define RR_TICKSSOURCE_H_

#include <sys/signal.h>

#include "Ticks.h"

namespace rr {

class AddressSpace;
class Task;
class TicksSource;

/*
 * Find out the cpu model using the cpuid instruction.
 * Full list of CPUIDs at http://sandpile.org/x86/cpuid.htm
 * Another list at
 * http://software.intel.com/en-us/articles/intel-architecture-and-processor-identification-with-cpuid-model-and-family-numbers
 */
enum CpuMicroarch {
  UnknownCpu,
  IntelMerom,
  IntelPenryn,
  IntelNehalem,
  IntelWestmere,
  IntelSandyBridge,
  IntelIvyBridge,
  IntelHaswell,
  IntelBroadwell,
  IntelSkylake,
  AMDFamily15h,
};

class TicksSource {
public:
  /**
   * Starts the tick source, and programs an interrupt after n ticks.
   * Returns true if we were interrupted by a signal we have already
   * waited for during setup.
   */
  virtual bool start_with_interval(Ticks) = 0;

  /**
   * Stops the tick source, return the number of ticks since
   * start_with_interval last started the tick source.
   */
  virtual Ticks stop_and_read() = 0;

  /**
   * Stops the tick source.
   */
  virtual void stop() = 0;

  /**
   * Returns the file descriptor associated with the tick source, -1
   * if none */
  virtual int ticks_fd() = 0;

  /**
   * Initializes the tick source for a given task and address space.
   */
  virtual void init(AddressSpace* as) = 0;

  /**
   * Returns true if the siginfo describes a time-slice signal for the
   * tick source.
   */
  virtual bool is_time_slice_signal(const siginfo_t* si) = 0;

  /**
   * Handles a signal, by turning off the tick source if
   * necessary. Returns true if the signal was a time-slice signal.
   */
  virtual bool signal(const siginfo_t* si) = 0;

  /**
   * Updates the thread id of an existing tick source.
   */
  virtual void set_tid(pid_t tid) = 0;

  /**
   * Opens the right tick source for this machine.
   */
  static TicksSource* open(Task*);
};
};

#endif /* RR_TICKSSOURCE_H_ */
