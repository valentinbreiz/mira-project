	.section .rodata
	.global kpayload
	.type   kpayload, @object
	.align  4
kpayload:
	.incbin "src/mira/hen/kpayload.bin"
kpayload_end:
	.global kpayload_size
	.type   kpayload_size, @object
	.align  4
kpayload_size:
	.int    kpayload_end - kpayload
