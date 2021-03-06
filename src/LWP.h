#ifndef RR_LWP_H_
#define RR_LWP_H_

#include <signal.h>
#include <stdint.h>
#include <sys/types.h>

#include "remote_ptr.h"
#include "AddressSpace.h"
#include "Ticks.h"
#include "TicksSource.h"
#include "ScopedFd.h"

/* 0x8000000 - LwpInt: threshold interrupt
 * 0x4000000 - LwpPTSC: performance time stamp counter in event record
 * 0x2000000 - LwpCont: continuous mode sampling. This is required(?!).
 */

#define LWP_FLAGS_THRESHOLD_INT  0x80000000LL
#define LWP_FLAGS_BRANCHES       (1LL<<(LWP_EVENT_BRANCHES+1))

#define LWP_EVENT_BRANCHES                2LL

#define LWP_FILTER_NO_RELATIVE_BRANCHES  0x20000000LL
#define LWP_FILTER_NO_ABSOLUTE_BRANCHES  0x08000000LL

#define LWP_FLAGS       (LWP_FLAGS_THRESHOLD_INT|LWP_FLAGS_BRANCHES)
#define LWP_EVENT       LWP_EVENT_BRANCHES
#define LWP_FILTERS     (LWP_FILTER_NO_ABSOLUTE_BRANCHES|LWP_FILTER_NO_RELATIVE_BRANCHES)
#define LWP_MAX_PERIOD            0xffffffLL
#define LWP_INTERVAL             0x1ffffffLL
#define LWP_SIGN        0xffffffffff000000LL

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

  class LWP : public TicksSource {
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

    bool init_buffer(remote_ptr<void> buffer, size_t buffer_size);

    bool write_lwpcb(remote_ptr<lwpcb> dest_lwp);

    bool read_lwp_xsave(bool disable_lwp);

    bool lwp_xsave_to_lwpcb();

    bool is_time_slice_signal(const siginfo_t*);
    bool signal(const siginfo_t*);

    void set_tid(pid_t tid);

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

    bool start_with_interval(Ticks);
    Ticks stop_and_read();

    int ticks_fd();
    void init(AddressSpace* as);
private:
    bool set_lwpcb();

    Task* task;
    pid_t tid;
    ScopedFd fd_ticks;
    bool started;
    bool inited;
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
