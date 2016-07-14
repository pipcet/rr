#ifndef RR_LWP_H_
#define RR_LWP_H_
/* 0x8000000 - LwpInt: threshold interrupt
 * 0x4000000 - LwpPTSC: performance time stamp counter in event record
 * 0x2000000 - LwpCont: continuous mode sampling. This is required(?!).
 */
#define LWP_FLAGS 0x80000008L
#define LWP_EVENT          2L
#define LWP_FILTER 0x00000000L
#define LWP_OFFSET 0
#define LWP_INTERVAL 0x1ffffffL
#define LWP_SIGN 0xfffffffff1000000L
namespace rr {

  class Task;

  
  class LWP {
  public:
    LWP(Task* task, pid_t tid);
    ~LWP() {}

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
    
    /**
     * Adjust the LWP counter to account for additional instructions
     */
    void adjust(Ticks);

    /* This choice is fairly arbitrary; linux doesn't use SIGSTKFLT so we
     * hope that tracees don't either. */
    enum { TIME_SLICE_SIGNAL = SIGSTKFLT };

    static const struct perf_event_attr& ticks_attr();

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
      uint64_t rsvd70;
      struct {
        uint32_t interval;
        uint32_t counter;
      } event[3];
    };

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
  };
}
#endif /* RR_LWP_H_ */
