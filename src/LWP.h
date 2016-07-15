#ifndef RR_LWP_H_
#define RR_LWP_H_

#include <signal.h>
#include <stdint.h>
#include <sys/types.h>

#include "remote_ptr.h"
#include "Ticks.h"
#include "ScopedFd.h"

/* 0x8000000 - LwpInt: threshold interrupt
 * 0x4000000 - LwpPTSC: performance time stamp counter in event record
 * 0x2000000 - LwpCont: continuous mode sampling. This is required(?!).
 */
#define LWP_FLAGS 0x80000008L
#define LWP_EVENT          2L
#define LWP_FILTER 0x28000000L
#define LWP_FILTERS 0x28000000L
#define LWP_OFFSET 0
#define LWP_INTERVAL 0x1ffffffL
#define LWP_SIGN 0xffffffffff000000L

struct perf_event_attr;

namespace rr {

  class Task;

  struct lwpcb {
    uint32_t flags;
    uint32_t buffer_size;
    uint64_t buffer_base;
    uint32_t buffer_head_offset;
    uint32_t rsvd20;
    uint64_t missed_events;
    uint32_t threshold;
    uint32_t filters;
    uint64_t base_ip;
    uint64_t limit_ip;
    uint64_t rsvd56;
    uint32_t buffer_tail_offset;
    uint32_t rsvd68;
    uint64_t rsvd72;
    uint64_t rsvd80;
    uint64_t rsvd88;
    uint64_t rsvd96;
    uint64_t rsvd104;
    uint64_t rsvd112;
    uint64_t rsvd120;
    struct {
      uint32_t interval;
      uint32_t counter;
    } event[3];
  };

  class LWP {
  public:
    LWP(Task* task, pid_t tid);
    ~LWP();

    /**
     * Reset all counter values to 0 and program the counters to send
     * TIME_SLICE_SIGNAL when 'ticks_period' tick events have elapsed. (In reality
     * the hardware triggers its interrupt some time after that.)
     * This must be called while the task is stopped, and it must be called
     * before the task is allowed to run again.
     */
    void reset(Ticks ticks_period);

    /**
     * Close the perfcounter fds. They will be automatically reopened if/when
     * reset is called again.
     */
    void stop();

    /**
     * Read the current value of the ticks counter.
     */
    Ticks read_ticks();
    Ticks read_ticks_nondestructively();

    int ticks_fd() const { return fd_ticks.get(); }

    void init_buffer(remote_ptr<void> buffer, size_t buffer_size);

    bool write_lwpcb(remote_ptr<lwpcb> dest_lwp);

    bool read_lwp_xsave();

    bool lwp_xsave_to_lwpcb();

    /* This choice is fairly arbitrary; linux doesn't use SIGSTKFLT so we
     * hope that tracees don't either. */
    enum { TIME_SLICE_SIGNAL = SIGSTKFLT };

    static const struct perf_event_attr& ticks_attr();

    struct lwp_xsave {
      uint64_t lwpcb_address;
      uint32_t flags;
      uint32_t buffer_head_offset;
      uint64_t buffer_base;
      uint32_t buffer_size;
      uint32_t filters;
      uint64_t saved_event_record[4];
      uint32_t event_counter[3];
    };

private:
    Task* task;
    pid_t tid;
    ScopedFd fd_ticks;
    bool started;
    unsigned long last_ticks_period;
    unsigned long saved_ticks;
    unsigned long ticks_read;
    struct lwpcb lwpcb;
    struct lwp_xsave xsave;
    static unsigned int xsave_area_size;
    static unsigned int xsave_lwp_off;
    static unsigned int xsave_lwp_size;
  };
}
#endif /* RR_LWP_H_ */
