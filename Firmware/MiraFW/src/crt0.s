    .section .rodata
    .global kexec
    .type   kexec, @object
    .align  4
kexec:
    .incbin "kexec.bin"
kexec_end:
    .global kexec_size
    .type   kexec_size, @object
    .align  4
kexec_size:
    .int    kexec_end - kexec

.intel_syntax noprefix
.text

.global _start

_start:
	jmp		mira_entry