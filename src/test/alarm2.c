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
    //unsigned long *out;
    //asm volatile(".byte 0x8f, 0xe9, 0xf8, 0x12, 0xc8" : "=a" (out) : : "flags", "memory");
    //*(int *)0x70001000 = 0x80000008;
    //asm volatile(".byte 0x8f, 0xe9, 0x78, 0x12, 0xc0" : : "a" (0x70001000) : "flags", "memory");
    //if (out && (out[0] & 8))
      (*okp)++;
      //else {
      //atomic_printf("{{{LWP state cleared, counter %d, okcounter %d}}}",
      //              counter, *okp);
      // }
  }

  atomic_printf("\nSignal %d caught, Counter is %d\n", caught_sig, counter);
  test_assert(SIGALRM == caught_sig);

  breakpoint();

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
