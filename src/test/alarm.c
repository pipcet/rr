/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static void breakpoint(void) {}

static volatile int caught_sig = 0;

void catcher(__attribute__((unused)) int signum,
             __attribute__((unused)) siginfo_t* siginfo_ptr,
             __attribute__((unused)) void* ucontext_ptr) {
  caught_sig = signum;
}

volatile int *okp = (int *)0x70003000;

int main(void) {
  struct sigaction sact;
  int counter;

  sigemptyset(&sact.sa_mask);
  sact.sa_flags = SA_SIGINFO;
  sact.sa_sigaction = catcher;
  sigaction(SIGALRM, &sact, NULL);

  alarm(5); /* timer will pop in 1 second */

  for (counter = 0; counter >= 0 && !caught_sig; counter++) {
    void *out;
    asm volatile("slwpcb %0" : "=r" (out) : : "flags", "memory");
    if (out)
      (*okp)++;
    else {
      atomic_printf("{{{LWP state cleared, counter %d, okcounter %d}}}",
                    counter, *okp);
      asm volatile("llwpcb %0" : : "r" (0x70001000) : "flags", "memory");
    }
  }

  atomic_printf("\nSignal %d caught, Counter is %d\n", caught_sig, counter);
  test_assert(SIGALRM == caught_sig);

  breakpoint();

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
