#!/usr/bin/env python2

import io
import os
import sys

def write_rr_page(f, is_64, is_replay):
    bytes = bytearray([
        0x0f, 0x05,                    # syscall
        0xc3,
        0x90,
        0x9c,                          # pushfq
        0x50,                          # push %rax
        0xb8, 0x00, 0x10, 0x00, 0x70,  # mov $0x70001000,%eax
        0x8f, 0xe9, 0xf8, 0x12, 0xc0,  # llwpcb %rax
        0x58,                          # pop %rax
        0x9d,                          # popfq
        0xc3,                          # ret
        0x03,
        0x03, 0x03, 0x03, 0xeb,
        0x67, 0x03, 0x03, 0x03,
        0x03, 0x03, 0xeb, 0xfe,
    ])
    nocall_bytes = bytearray([
        0x31, 0xc0,                    # xor %eax,%eax
        0x90, 0xc3,
        0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0xeb,
        0x67, 0x03, 0x03, 0x03,
        0x03, 0x03, 0xeb, 0xfe,
    ])

    # traced
    f.write(bytes)
    # privileged traced
    f.write(bytes)

    # untraced
    f.write(bytes)
    # untraced replay-only
    if is_replay:
        f.write(bytes)
    else:
        f.write(nocall_bytes)
    # untraced record-only
    if is_replay:
        f.write(nocall_bytes)
    else:
        f.write(bytes)

    # privileged untraced
    f.write(bytes)
    # privileged untraced replay-only
    if is_replay:
        f.write(bytes)
    else:
        f.write(nocall_bytes)
    # privileged untraced record-only
    if is_replay:
        f.write(nocall_bytes)
    else:
        f.write(bytes)

    thunk_bytes = bytearray([
        # we sometimes (after interrupted syscalls) jump back two bytes,
        # even though we've modified regs.rip. I can't find documentation
        # for that behavior, and none of the following alternatives for
        # the first two bytes of the thunk appear to do anything useful:
        # 0x0f, 0x05,                  # syscall
        # 0x90, 0x90,                  # nop; nop
        # 0xeb, 0x10,                  # jmp to lretq
        # 0xeb, 0xfe,                  # spin
        #
        # Okay, the problem is we sometimes jump back just one
        # byte. The smart thing to do would have been to put an int3
        # single-byte opcode at that position and handle it in the
        # signal handler, but I wasn't smart, so I put an 0xeb
        # there. The 0xeb combines with the 0x90 of the following nop
        # byte to jump back to code prior to this on the rr page (at
        # 0x70000097), which jumps forward to 0x70000100, which jumps
        # to 0x70000122, where the return address on the stack is
        # mangled to retry the syscall instruction instead; we then
        # lretq.
        #
        # So it doesn't make sense to disassemble the rr page with
        #  $ objdump -jbinary -mi386 rr_page_64
        # because the byte at 0x70000106 is both a nop and a relative
        # offset for the preceding jmp opcode. But it might help, anyway!
        0xeb, 0x18,
        0xeb, 0x02,
        0x90, 0xcc,
        0x90, 0x90,
        0x50,                          # push %rax
        0x9c,                          # pushfq
        0xb8, 0x00, 0x10, 0x00, 0x70,  # mov $0x70001000,%eax
        0x8f, 0xe9, 0xf8, 0x12, 0xc0,  # llwpcb %rax
        0x9d,                          # popfq
        0x58,                          # pop %rax
        0x48, 0xca, 0x80, 0x00,        # lretq $0x80
        0x90,
        0x90,
        0x90,
        0x90,
        0x50,                          # push %rax
        0x9c,                          # pushfq
        0xb8, 0x00, 0x10, 0x00, 0x70,  # mov $0x70001000,%eax
        0x8f, 0xe9, 0xf8, 0x12, 0xc0,  # llwpcb %rax
        0x48, 0x83, 0x6c, 0x24, 0x10, 0x02,  # subq $2, 0x10(%rsp)
        0x9d,                          # popfq
        0x58,                          # pop %rax
        # 0x48, 0xc7, 0xc0, 0xfc, 0xff, 0xff, 0xff,
        0x48, 0xca, 0x80, 0x00,        # lretq $0x80
        0x48, 0xcb,
        0x03,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
    ])

    f.write(thunk_bytes);

    ff_bytes = bytearray([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    f.write(ff_bytes)

generators_for = {
    'rr_page_32': lambda stream: write_rr_page(stream, False, False),
    'rr_page_64': lambda stream: write_rr_page(stream, True, False),
    'rr_page_32_replay': lambda stream: write_rr_page(stream, False, True),
    'rr_page_64_replay': lambda stream: write_rr_page(stream, True, True),
}

def main(argv):
    filename = argv[0]
    base = os.path.basename(filename)

    if os.access(filename, os.F_OK):
        with open(filename, 'r') as f:
            before = f.read()
    else:
        before = ""

    stream = io.BytesIO()
    generators_for[base](stream)
    after = stream.getvalue()
    stream.close()

    if before != after:
        with open(filename, 'w') as f:
            f.write(after)

if __name__ == '__main__':
    main(sys.argv[1:])
