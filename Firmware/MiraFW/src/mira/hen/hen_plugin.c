#include "hen_plugin.h"
#include <oni/utils/kdlsym.h>
#include <oni/utils/kernel.h>
#include <oni/utils/cpu.h>
#include <oni/utils/sys_wrappers.h>
#include <oni/utils/memory/allocator.h>
#include <oni/utils/log/logger.h>
#define LOCK_PROFILING
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sx.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>

#include <sys/ptrace.h>

uint8_t hen_load(struct hen_plugin_t* plugin);
uint8_t hen_unload(struct hen_plugin_t* plugin);

extern uint8_t kpayload[];
extern uint32_t kpayload_size;

#define	KERN_XFAST_SYSCALL	0x1C0		// 5.01 & 5.05
#define KERN_PRISON_0		0x10986A0	// 5.01 & 5.05
#define KERN_ROOTVNODE		0x22C1A70 // 0x22C19F0   (5.01)

#define KERN_PMAP_PROTECT	0x2E3090  // 0x2E2D00   (5.01)
#define KERN_PMAP_PROTECT_P	0x2E30D4  // 0x2E2D44   (5.01)
#define KERN_PMAP_STORE		0x22CB570 // 0x22CB4F0 (5.01)

#define KERN_REGMGR_SETINT	0x4f8d10 // 0x4F8940 (5.01)

#define DT_HASH_SEGMENT		0xB5EF30 // (5.05)

#define X86_CR0_WP (1 << 16)

static inline __attribute__((always_inline)) uint64_t readCr0(void)
{
	uint64_t cr0;
	__asm__ volatile ("movq %0, %%cr0" : "=r" (cr0) : : "memory");
	return cr0;
}

static inline __attribute__((always_inline)) void writeCr0(uint64_t cr0)
{
	__asm__ volatile("movq %%cr0, %0" : : "r" (cr0) : "memory");
}

static inline __attribute__((always_inline)) void disable_interrupts(void)
{
	__asm__ volatile("cli");
}

static inline __attribute__((always_inline)) void enable_interrupts(void)
{
	__asm__ volatile("sti");
}

static inline __attribute__((always_inline)) uint64_t read_flags(void)
{
	uint64_t flags;
	__asm__ volatile("pushf; pop %0;" : "=r" (flags));
	return flags;
}

struct payload_header
{
	uint64_t signature;
	size_t real_info_offset;
	size_t disp_info_offset;
	size_t entrypoint_offset;
};

struct real_info
{
	const size_t kernel_offset;
	const size_t payload_offset;
};

struct disp_info
{
	const size_t call_offset;
	const size_t payload_offset;
};

typedef struct _patch_info
{
	const char* name;
	uint32_t address;
	const char* data;
	uint32_t size;
}
patch_info;

void hen_init(struct hen_plugin_t* plugin)
{
	if (!plugin)
		return;

	plugin->plugin.description = "hen";
	plugin->plugin.name = "hen";
	plugin->plugin.plugin_load = (uint8_t(*)(void*))hen_load;
	plugin->plugin.plugin_unload = (uint8_t(*)(void*))hen_unload;
}

int __strncmp(const char * s1, const char * s2, size_t n)
{
	while (n && *s1 && (*s1 == *s2))
	{
		++s1;
		++s2;
		--n;
	}
	if (n == 0)
	{
		return 0;
	}
	else
	{
		return (*(unsigned char *)s1 - *(unsigned char *)s2);
	}
}

// flatz
struct proc* proc_find_by_name(const char* name) {
	struct proc* p;

	int(*_sx_slock)(struct sx *sx, int opts, const char *file, int line) = kdlsym(_sx_slock);
	void(*_sx_sunlock)(struct sx *sx, const char *file, int line) = kdlsym(_sx_sunlock);
	void(*_mtx_lock_flags)(struct mtx *m, int opts, const char *file, int line) = kdlsym(_mtx_lock_flags);
	void(*_mtx_unlock_flags)(struct mtx *m, int opts, const char *file, int line) = kdlsym(_mtx_unlock_flags);
	struct sx* allproclock = (struct sx*)kdlsym(allproc_lock);
	struct proclist* allproc = (struct proclist*)*(uint64_t*)kdlsym(allproc);


	if (!name)
		return NULL;

	sx_slock(allproclock);

	FOREACH_PROC_IN_SYSTEM(p) {
		PROC_LOCK(p);

		if (__strncmp(p->p_comm, name, sizeof(p->p_comm)) == 0) {
			PROC_UNLOCK(p);
			goto done;
		}

		PROC_UNLOCK(p);
	}

	p = NULL;

done:
	sx_sunlock(allproclock);

	return p;
}


uint8_t hen_load(struct hen_plugin_t* plugin)
{
	uint64_t flags;

	uint8_t* kernel_base = (uint8_t*)gKernelBase;

	void(*pmap_protect)(void * pmap, uint64_t sva, uint64_t eva, uint8_t pr) = (void *)(kernel_base + KERN_PMAP_PROTECT);
	void *kernel_pmap_store = (void *)(kernel_base + KERN_PMAP_STORE);
	void(*kernel_printf)(char *format, ...) = kdlsym(printf);
	void(*critical_enter)(void) = kdlsym(critical_enter);
	void(*critical_exit)(void) = kdlsym(critical_exit);
	void(*_vm_map_lock_read)(vm_map_t map, const char *file, int line) = kdlsym(_vm_map_lock_read);
	void(*_vm_map_unlock_read)(vm_map_t map, const char *file, int line) = kdlsym(_vm_map_unlock_read);
	void(*vmspace_free)(struct vmspace *) = kdlsym(vmspace_free);
	struct vmspace* (*vmspace_acquire_ref)(struct proc *) = kdlsym(vmspace_acquire_ref);

	// set diag auth ID flags
	curthread->td_ucred->cr_sceAuthID = 0x3800000000000007ULL;

	// make system credentials
	curthread->td_ucred->cr_sceCaps[0] = 0xFFFFFFFFFFFFFFFFULL;
	curthread->td_ucred->cr_sceCaps[1] = 0xFFFFFFFFFFFFFFFFULL;

	kernel_printf("\n\n\n\npayload_installer: starting\n");
	kernel_printf("payload_installer: kernel base=%lx\n", kernel_base);

	uint8_t* payload_data = kpayload;
	size_t payload_size = kpayload_size;
	struct payload_header* payload_header = (struct payload_header*)payload_data;

	if (!payload_data ||
		payload_size < sizeof(payload_header) ||
		payload_header->signature != 0x5041594C4F414430ull)
	{
		kernel_printf("payload_installer: bad payload data\n");
		return -2;
	}

	uint8_t* payload_buffer = (uint8_t*)&kernel_base[DT_HASH_SEGMENT];

	kernel_printf("payload_installer: installing...\n");
	kernel_printf("payload_installer: target=%lx\n", payload_buffer);
	kernel_printf("payload_installer: payload=%lx,%lu\n",
		payload_data, payload_size);

	critical_enter();
	cpu_disable_wp();

	kernel_printf("payload_installer: memset\n");
	kmemset(payload_buffer, 0, PAGE_SIZE);

	kernel_printf("payload_installer: memcpy\n");
	kmemcpy(payload_buffer, payload_data, payload_size);

	kernel_printf("payload_installer: remap\n");
	uint64_t sss = ((uint64_t)payload_buffer) & ~(uint64_t)(PAGE_SIZE - 1);
	uint64_t eee = ((uint64_t)payload_buffer + payload_size + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
	kernel_base[KERN_PMAP_PROTECT_P] = 0xEB;
	WriteLog(LL_Debug, "pmap_protect %p kernel_pmap_store %p sss %p eee %p", pmap_protect, kernel_pmap_store, sss, eee);

	pmap_protect(kernel_pmap_store, sss, eee, 7);
	kernel_base[KERN_PMAP_PROTECT_P] = 0x75;

	kernel_printf("payload_installer: patching payload pointers\n");
	if (payload_header->real_info_offset != 0 &&
		payload_header->real_info_offset + sizeof(struct real_info) <= payload_size)
	{
		WriteLog(LL_Debug, "here");
		struct real_info* real_info =
			(struct real_info*)(&payload_data[payload_header->real_info_offset]);
		for (
			; real_info->payload_offset != 0 && real_info->kernel_offset != 0
			; ++real_info)
		{
			WriteLog(LL_Debug, "hm: %p", real_info);

			WriteLog(LL_Debug, "%p offset: %p", payload_buffer, real_info->payload_offset);
			uint64_t* payload_target =
				(uint64_t*)(&payload_buffer[real_info->payload_offset]);
			void* kernel_target = &kernel_base[real_info->kernel_offset];
			*payload_target = (uint64_t)kernel_target;
			kernel_printf("  %x(%lx) = %x(%lx)\n",
				real_info->payload_offset, payload_target,
				real_info->kernel_offset, kernel_target);
		}
	}

	WriteLog(LL_Debug, "here");
	flags = intr_disable();

	WriteLog(LL_Debug, "here");

	kernel_printf("payload_installer: patching calls\n");
	if (payload_header->disp_info_offset != 0 &&
		payload_header->disp_info_offset + sizeof(struct disp_info) <= payload_size)
	{
		WriteLog(LL_Debug, "here");
		struct disp_info* disp_info =
			(struct disp_info*)(&payload_data[payload_header->disp_info_offset]);
		for (
			; disp_info->call_offset != 0 && disp_info->payload_offset != 0
			; ++disp_info)
		{
			uint8_t* call_target = &kernel_base[disp_info->call_offset];
			uint8_t* payload_target = &payload_buffer[disp_info->payload_offset];

			int32_t new_disp = (int32_t)(payload_target - &call_target[5]);
			WriteLog(LL_Debug, "here");
			kernel_printf("  %lx(%lx)\n",
				disp_info->call_offset + 1, &call_target[1]);
			kernel_printf("    %lx(%lx) -> %lx(%lx) = %d\n",
				disp_info->call_offset + 5, &call_target[5],
				disp_info->payload_offset, payload_target,
				new_disp);

			*((int32_t*)&call_target[1]) = new_disp;
		}
	}

	// debug settings patches 5.01 & 5.05
	*(char *)(kernel_base + 0x1CD0686) |= 0x14;
	*(char *)(kernel_base + 0x1CD06A9) |= 3;
	*(char *)(kernel_base + 0x1CD06AA) |= 1;
	*(char *)(kernel_base + 0x1CD06C8) |= 1;

	// debug menu error patches 5.05
	*(uint32_t *)(kernel_base + 0x4F9048) = 0;
	*(uint32_t *)(kernel_base + 0x4FA15C) = 0;

	// target_id patches 5.01 & 5.05
	*(uint16_t *)(kernel_base + 0x1CD068C) = 0x8101;
	*(uint16_t *)(kernel_base + 0x236B7FC) = 0x8101;

	// flatz disable pfs signature check 5.05
	*(uint32_t *)(kernel_base + 0x6A2700) = 0x90C3C031;

	// flatz enable debug RIFs 5.05
	*(uint32_t *)(kernel_base + 0x64B2B0) = 0x90C301B0;
	*(uint32_t *)(kernel_base + 0x64B2D0) = 0x90C301B0;

	intr_restore(flags);
	cpu_enable_wp();
	critical_exit();

	WriteLog(LL_Debug, "here");

	if (payload_header->entrypoint_offset != 0 &&
		payload_header->entrypoint_offset < payload_size)
	{
		kernel_printf("payload_installer: entrypoint\n");
		void(*payload_entrypoint)();
		*((void**)&payload_entrypoint) =
			(void*)(&payload_buffer[payload_header->entrypoint_offset]);
		payload_entrypoint();
	}

	curthread->td_ucred->cr_sceAuthID = 0x3800000000000007ULL;

	// make system credentials
	curthread->td_ucred->cr_sceCaps[0] = 0xFFFFFFFFFFFFFFFFULL;
	curthread->td_ucred->cr_sceCaps[1] = 0xFFFFFFFFFFFFFFFFULL;

	void(*_mtx_unlock_flags)(struct mtx *m, int opts, const char *file, int line) = kdlsym(_mtx_unlock_flags);
	struct  proc* (*pfind)(pid_t) = kdlsym(pfind);

	struct proc* scProc = proc_find_by_name("SceShellCore");
	if (!scProc)
	{
		WriteLog(LL_Error, "uh couldn't find shellcor bruh");
		return false;
	}
	WriteLog(LL_Debug, "shellcore proc: %p", scProc);

	struct vmspace* vm = vmspace_acquire_ref(scProc);
	WriteLog(LL_Debug, "vm: %p", vm);
	vm_map_t map = &scProc->p_vmspace->vm_map;
	WriteLog(LL_Debug, "map: %p", map);

	vm_map_lock_read(map);
	struct vm_map_entry* entry = map->header.next;

	int32_t scPid = scProc->p_pid;
	uint8_t* scBaseAddress = (uint8_t*)entry->start;
	WriteLog(LL_Debug, "shellcore pid: %d %p", scPid, scBaseAddress);
	//uint64_t scSize = (uint64_t)entry->end - entry->start;
	vmspace_free(vm);
	vm_map_unlock_read(map);

	scProc = pfind(scPid);
	if (!scProc)
	{
		WriteLog(LL_Error, "could not find shellcore.");
		return false;
	}

#    define SHELLCORE_ENABLE_DEBUG_PKG_PATCH_1_1_OFFSET 0x16D05B // call sceKernelIsGenuineCEX
#    define SHELLCORE_ENABLE_DEBUG_PKG_PATCH_1_2_OFFSET 0x79980B // call sceKernelIsGenuineCEX
#    define SHELLCORE_ENABLE_DEBUG_PKG_PATCH_1_3_OFFSET 0x7E5A13 // call sceKernelIsGenuineCEX
#    define SHELLCORE_ENABLE_DEBUG_PKG_PATCH_1_4_OFFSET 0x94715B // call sceKernelIsGenuineCEX
#    define SHELLCORE_ENABLE_DEBUG_PKG_PATCH_2_1_OFFSET 0x16D087 // call nidf_libSceDipsw_0xD21CE9E2F639A83C
#    define SHELLCORE_ENABLE_DEBUG_PKG_PATCH_2_2_OFFSET 0x23747B // call nidf_libSceDipsw_0xD21CE9E2F639A83C
#    define SHELLCORE_ENABLE_DEBUG_PKG_PATCH_2_3_OFFSET 0x799837 // call nidf_libSceDipsw_0xD21CE9E2F639A83C
#    define SHELLCORE_ENABLE_DEBUG_PKG_PATCH_2_4_OFFSET 0x947187 // call nidf_libSceDipsw_0xD21CE9E2F639A83C
# define SHELLCORE_USE_FREE_PREFIX_INSTEAD_OF_FAKE_OFFSET 0xEA96A7 // fake -> free



	uint8_t xor__eax_eax[5] = { 0x31, 0xC0, 0x90, 0x90, 0x90 };
	uint8_t jmp__nop_nop_nop[] = { 0xE9, 0x96, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90 };


	size_t n = 0;
	WriteLog(LL_Debug, "proc_rw_mem: %d", proc_rw_mem(scProc, (void*)scBaseAddress + SHELLCORE_ENABLE_DEBUG_PKG_PATCH_1_1_OFFSET, sizeof(xor__eax_eax), xor__eax_eax, &n, true));
	WriteLog(LL_Debug, "proc_rw_mem: %d", proc_rw_mem(scProc, (void*)scBaseAddress + SHELLCORE_ENABLE_DEBUG_PKG_PATCH_1_2_OFFSET, sizeof(xor__eax_eax), xor__eax_eax, &n, true));
	WriteLog(LL_Debug, "proc_rw_mem: %d", proc_rw_mem(scProc, (void*)scBaseAddress + SHELLCORE_ENABLE_DEBUG_PKG_PATCH_1_3_OFFSET, sizeof(xor__eax_eax), xor__eax_eax, &n, true));
	WriteLog(LL_Debug, "proc_rw_mem: %d", proc_rw_mem(scProc, (void*)scBaseAddress + SHELLCORE_ENABLE_DEBUG_PKG_PATCH_1_4_OFFSET, sizeof(xor__eax_eax), xor__eax_eax, &n, true));
	WriteLog(LL_Debug, "proc_rw_mem: %d", proc_rw_mem(scProc, (void*)scBaseAddress + SHELLCORE_ENABLE_DEBUG_PKG_PATCH_2_1_OFFSET, sizeof(xor__eax_eax), xor__eax_eax, &n, true));
	WriteLog(LL_Debug, "proc_rw_mem: %d", proc_rw_mem(scProc, (void*)scBaseAddress + SHELLCORE_ENABLE_DEBUG_PKG_PATCH_2_2_OFFSET, sizeof(xor__eax_eax), xor__eax_eax, &n, true));
	WriteLog(LL_Debug, "proc_rw_mem: %d", proc_rw_mem(scProc, (void*)scBaseAddress + SHELLCORE_ENABLE_DEBUG_PKG_PATCH_2_3_OFFSET, sizeof(xor__eax_eax), xor__eax_eax, &n, true));
	WriteLog(LL_Debug, "proc_rw_mem: %d", proc_rw_mem(scProc, (void*)scBaseAddress + SHELLCORE_ENABLE_DEBUG_PKG_PATCH_2_4_OFFSET, sizeof(xor__eax_eax), xor__eax_eax, &n, true));

	WriteLog(LL_Debug, "proc_rw_mem: %d", proc_rw_mem(scProc, (void*)scBaseAddress + SHELLCORE_USE_FREE_PREFIX_INSTEAD_OF_FAKE_OFFSET, 4, "free", &n, true));
	WriteLog(LL_Debug, "proc_rw_mem: %d", proc_rw_mem(scProc, (void*)scBaseAddress + 0x3E0602, sizeof(jmp__nop_nop_nop), jmp__nop_nop_nop, &n, true));

	PROC_UNLOCK(scProc);
	WriteLog(LL_Error, "kendick lamar - alright");
	
	return true;
}

uint8_t hen_unload(struct hen_plugin_t* plugin)
{
	return true;
}