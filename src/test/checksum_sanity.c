/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void* do_thread(__attribute__((unused)) void* p) { return NULL; }

int main(int argc, char** argv) {
  pthread_t thread;
  pid_t child;
  int status;

  if (argc > 1) {
    return 77;
  }

  pthread_create(&thread, NULL, do_thread, NULL);
  pthread_join(thread, NULL);

  child = fork();
  if (!child) {
    char* args[] = { argv[0], "dummy", NULL };
    execve(argv[0], args, environ);
    test_assert(0 && "exec failed");
  }
  test_assert(child == wait(&status));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  /* Test that checksumming doesn't care if we have a mmap
   * that is not backed by a sufficiently long file */
  static const char name[] = "temp";
  int fd = open(name, O_CREAT | O_RDWR | O_EXCL, 0600);
  /* Have it extend a couple of bytes into the second page */
  test_assert(0 == ftruncate(fd, 35808));
  void* map_addr =
      mmap(NULL, 39904, PROT_READ, MAP_DENYWRITE|MAP_PRIVATE, fd, 0);
  mmap(map_addr + 0x2000, 16384, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x2000);
  mmap(map_addr + 0x6000, 8192, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x6000);
  mmap(map_addr + 0x8000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x7000);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
