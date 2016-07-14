using namespace std;

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

    /**
     * Adjust the LWP counter to account for additional instructions
     */
    void adjust(Ticks);

    /* This choice is fairly arbitrary; linux doesn't use SIGSTKFLT so we
     * hope that tracees don't either. */
    enum { TIME_SLICE_SIGNAL = SIGSTKFLT };

    static const struct perf_event_attr& ticks_attr();

    struct lwpcb {
      u32 flags;
      u32 buffer_size;
      u64 buffer_base;
      u32 buffer_head_offset;
      u32 rsvd20;
      u64 missed_events;
      u32 threshold;
      u32 filters;
      u64 base_ip;
      u64 limit_ip;
      u64 rsvd56;
      u32 buffer_tail_offset;
      u32 rsvd68;
      u64 rsvd70;
      struct {
        u32 interval;
        u32 counter;
      } event[3];
    };

    struct lwp_xsave {
      u64 lwpcb_address;
      u32 flags;
      u32 buffer_head_offset;
      u64 buffer_base;
      u32 buffer_size;
      u32 filters;
      u64 saved_event_record[4];
      u32 event_counter[3];
    };

private:
    rr::Task* task;
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

static void LWP::init_lwpcb(remote_ptr<void> buffer, size_t buffer_size)
{
  assert(buffer);
  assert(buffer_size >= 32 * 32);
  assert(buffer_size % 32 == 0);

  memset(&lwpcb, 0, sizeof lwpcb);
  lwpcb.flags = LWP_FLAGS;
  lwpcb.buffer_size = buffer_size;
  lwpcb.buffer_base = uintptr_t(buffer);
  lwpcb.event[LWP_EVENT].interval = LWP_INTERVAL;
}

static bool LWP::write_lwpcb(remote_ptr<lwpcb> dest_lwp)
{
  remote_ptr<long> dest = remote_ptr<long>(dest_lwp);
  long *src = (long *)&lwpcb;
  assert(task);
  assert(dest);

  int i;
  for (i = 0; i < (sizeof(lwpcb) + 7) / 8; i++) {
    if (!task->ptrace_if_alive(PTRACE_POKEDATA, dest + i, src[i]))
      return false;
  }

  return true;
}

static bool LWP::read_lwp_xsave()
{
  char *buf = malloc(xsave_area_size);
  if (!buf)
    return false;
  struct iovec vec = { buf, xsave_area_size };
  if (!task->ptrace_if_alive(PTRACE_GETREGSET, NT_X86_XSTATE, &vec))
    return false;
  if (vec.size != xsave_area_size)
    return false;
  memcpy(&xsave, buf, sizeof xsave);
}

static bool LWP::lwp_xsave_to_lwpcb()
{
  lwpcb.flags = xsave.flags;
  lwpcb.buffer_size = xsave.buffer_size;
  lwpcb.buffer_base = xsave.buffer_base;
  lwpcb.buffer_head_offset = xsave.buffer_head_offset;
  lwpcb.filters = xsave.filters;
  lwpcb.event[LWP_EVENT].counter = xsave.event_counter[LWP_EVENT];

  return true;
}

LWP::LWP(Task *task, pid_t tid)
  : task(task), tid(tid), fd_ticks(-1), started(false),
    last_ticks_period(0), saved_ticks(0), ticks_read(0)
{
  memset(&lwpcb, 0, sizeof lwpcb);
  memset(&xsave, 0, sizeof xsave);
}

LWP::~LWP()
{
  if (fd_ticks != -1)
    fd_ticks.close();
}

void LWP::reset(Ticks ticks_period)
{
  assert(ticks_period >= 0);
  assert(ticks_period <= 0xffffff);
  assert(ticks_period <= LWP_INTERVAL);

  xsave.event_counter[LWP_EVENT] = ticks_period;
  lwpcb.event[LWP_EVENT].counter = ticks_period;
}

void LWP::stop()
{
  lwpcb.flags = 0;
  xsave.flags = 0;

  fd_ticks.close();
}

Ticks LWP::read_ticks_nondestructively()
{
  s64 counter_value = lwpcb.event[LWP_EVENT].counter;
  if (counter_value & LWP_SIGN)
    counter_value |= LWP_SIGN;
  assert(counter_value >= -2048);
  long diff = last_ticks_period - counter_value;
  assert(diff >= 0);
  long ret = saved_ticks;
  ret += diff;
  return ret;
}

Ticks LWP::read_ticks()
{
  long ticks = read_ticks_nondestructively();
  long ret = ticks - ticks_read;
  ticks_read = ticks;
  return ret;
}

void LWP::adjust(Ticks diff)
{
  ticks -= diff;
}

static void init_perf_event_attr(struct perf_event_attr* attr,
                                 perf_type_id type, unsigned config) {
  memset(attr, 0, sizeof(*attr));
  attr->type = type;
  attr->size = sizeof(*attr);
  attr->config = config;
  // rr requires that its events count userspace tracee code
  // only.
  attr->exclude_kernel = 1;
  attr->exclude_guest = 1;
}

static bool attributes_initialized;
static struct perf_event_attr ticks_attr;

static void init_attributes() {
  if (attributes_initialized) {
    return;
  }
  attributes_initialized = true;

  FILE *f = fopen("/sys/devices/lwp/type", "r");
  if (!f)
    FATAL() << "LWP events not found";

  int type;
  if (fscanf(f, "%d", &type) != 1)
    FATAL() << "LWP events not found";

  fclose(f);

  init_perf_event_attr(&ticks_attr, (perf_type_id)type, 0);
}

const struct perf_event_attr& PerfCounters::ticks_attr() {
  init_attributes();
  return rr::ticks_attr;
}
