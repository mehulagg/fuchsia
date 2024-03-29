// Copyright 2016 The Fuchsia Authors
// Copyright (c) 2009 Corey Tabaka
// Copyright (c) 2015 Intel Corporation
// Copyright (c) 2016 Travis Geiselbrecht
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include <asm.h>
#include <arch/x86/descriptor.h>
#include <lib/code_patching.h>

#define NUM_INT 256

/*
 * Please note that the macro for generating interrupt routine stubs relies
 * on the macro execution counter \@ which is shared by all invocations across
 * this compilation unit. Be careful when adding additional macros to this
 * file. In particular:
 * 1) No macros can be executed before def_isr (so \@ starts at zero).
 * 2) def_isr cannot have any macros (so \@ increments by one for each
 *    def_isr invocation).
 */

.text

/* interrupt service routine stubs */
_isr:
.macro def_isr
.pushsection .text
FUNCTION_LABEL(_isr_\@)
    .cfi_startproc simple
    .cfi_signal_frame
    /* Set CFA for an interrupt frame. */
.if \@ == 8 || (\@ >= 10 && \@ <= 14) || \@ == 17
    .cfi_def_cfa %rsp, (8 * 6)
.else
    .cfi_def_cfa %rsp, (8 * 5)
.endif
    .cfi_offset %rip, -(5 * 8)
    /* Mark each reg as having the same value as from the "calling" frame.
       This is the default state for callee-saved registers, but for completeness
       sake we do this for all of them. */
    ALL_CFI_SAME_VALUE
    /* Clear the AC flag to prevent ring 0 from performing data accesses to
     * ring 3 if SMAP is available.  If it was set, it will get restored by
     * iretd.  DO NOT REMOVE THIS CLAC, code in idt.c assumes it is here.
     * It MUST be the first instruction of this function. */
    clac
    /* We can't use push_value here: it is a macro invocation and using it
     * will screw up tracking of \@ == isr number. Instead we inline the .cfi
     * directives. */
.if \@ == 8 || (\@ >= 10 && \@ <= 14) || \@ == 17
    /* error code pushed by exception */
    pushq $\@              /* interrupt number */
    .cfi_adjust_cfa_offset 8
    jmp interrupt_common
.else
    pushq $0               /* fill in error code in iframe */
    .cfi_adjust_cfa_offset 8
    pushq $\@              /* interrupt number */
    .cfi_adjust_cfa_offset 8
    jmp interrupt_common
.endif
END_FUNCTION(_isr_\@)
.popsection
.pushsection .rodata.isr
.quad _isr_\@
.popsection
.endm

.pushsection .rodata.isr
/* build a table of isr entry points */
.balign 8
DATA(_isr_table)
.popsection
.rept NUM_INT
def_isr
.endr

FUNCTION_LABEL(interrupt_common)
    .cfi_startproc simple
    .cfi_signal_frame
    /* Set CFA for an interrupt frame. */
    .cfi_def_cfa %rsp, 7 * 8 /* hw + _isr_* push this many values */
    .cfi_offset %rip, -(5 * 8)
    /* Mark each reg as having the same value as from the "calling" frame.
       This is the default state for callee-saved registers, but for completeness
       sake we do this for all of them. */
    ALL_CFI_SAME_VALUE

    /* Clear the direction flag.  Without this, uses of string
       instructions, e.g. REP MOVS in memcpy() or inlined by the compiler,
       can go wrong and copy in the wrong direction, since this code may
       assume that the direction flag is unset. */
    cld

    /* Check to see if we came from user space by testing the PL of the
     * CS register that was saved on the stack automatically. Check for != 0.
     */
    testb $3, 0x18(%rsp)
    jz    1f

    /* swap gs to kernel space */
    swapgs

    /* Spectre V2: Overwrite the Return Address Stack to ensure its not poisoned/can't underflow */
.Lmaybe_exception_ras_fill:
    jmp   1f
    .rept 51
    nop
    .endr
    APPLY_CODE_PATCH_FUNC_WITH_DEFAULT(x86_ras_fill_select, .Lmaybe_exception_ras_fill, 53)

    .align 16
1:
    /* Certain processors may speculative past a conditional swapgs, with a caller-controlled
     * GS_BASE register. This may allow callers to infer the contents of kernel offsets or data.
     * Execute a dispatch-serializing fence to constrain speculation and mitigate the leak.
     */
    APPLY_CODE_PATCH_FUNC(swapgs_bug_postfence, 3)

    /* save general purpose registers */
    push_reg %r15
    push_reg %r14
    push_reg %r13
    push_reg %r12
    push_reg %r11
    push_reg %r10
    push_reg %r9
    push_reg %r8
    push_reg %rax
    push_reg %rcx
    push_reg %rdx
    push_reg %rbx
    push_reg %rbp
    push_reg %rsi
    push_reg %rdi

    movq %rsp, %rdi     /* pass the  iframe using rdi */

    call x86_exception_handler

/* A label to assist gdb's backtracing through kernel exceptions.
   When gdb sees this as the return address it knows it can fetch
   x86_iframe_t from $rsp. See scripts/zircon.elf-gdb.py. */
interrupt_common_iframe_set_up_for_debugger:

    /* restore general purpose registers */
    pop_reg %rdi
    pop_reg %rsi
    pop_reg %rbp
    pop_reg %rbx
    pop_reg %rdx
    pop_reg %rcx
    pop_reg %rax
    pop_reg %r8
    pop_reg %r9
    pop_reg %r10
    pop_reg %r11
    pop_reg %r12
    pop_reg %r13
    pop_reg %r14
    pop_reg %r15

    /* check if we're returning to user space as per before */
    testb $3, 0x18(%rsp)
    jz    1f

.Lmaybe_mds_buff_overwrite:
    call mds_buff_overwrite
    APPLY_CODE_PATCH_FUNC_WITH_DEFAULT(x86_mds_flush_select, .Lmaybe_mds_buff_overwrite, 5)

    /* swap gs back to user space */
    swapgs

1:
    APPLY_CODE_PATCH_FUNC(swapgs_bug_postfence, 3)
    /* drop vector number and error code*/
    add_to_sp 16

    iretq
END_FUNCTION(interrupt_common)

/* Call external interrupt handler manually without actually issuing interrupt.
 *
 * For external interrupts CPU doesn't store error code on stack so we use 0. We
 * additionally use CODE_64_SELECTOR as CS, 0 as SS, RFLAGS value and current
 * stack.
 */
FUNCTION(x86_call_external_interrupt_handler)
    /* save current RFLAGS value */
    pushfq
    popq %r10

    /* save current RSP value */
    movq %rsp, %r11

    /* calculate exit address */
    leaq .Lexit(%rip), %rax

    /* prepare interrupt stack frame in the from interrupt_common expects to see */
    sub_from_sp 0x38
    movq %rdi, 0x00(%rsp)              // rdi holds vector number
    movq $0, 0x08(%rsp)                // error code
    movq %rax, 0x10(%rsp)              // RIP (return address)
    movq $CODE_64_SELECTOR, 0x18(%rsp) // CS
    movq %r10, 0x20(%rsp)              // RFLAGS
    movq %r11, 0x28(%rsp)              // RSP
    movq $0, 0x30(%rsp)                // SS

    /* we can actually avoid this jump if we put this code above
     * interrupt_common and just fall through, but benefits of doing this are
     * not obvious so for now for the sake of clarity keep this jump
     */
    jmp    interrupt_common

.Lexit:
    ret
END_FUNCTION(x86_call_external_interrupt_handler)
