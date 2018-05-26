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
#include <sys/wait.h>

struct wait4_args {
	int	pid;
	int *status;
	int options;
	struct rusage *rusage;
};

void    wakeup(void *chan) __nonnull(1);

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

//static inline __attribute__((always_inline)) uint64_t intr_disable(void)
//{
//	uint64_t flags = read_flags();
//	disable_interrupts();
//	return flags;
//}
//
//static inline __attribute__((always_inline)) void intr_restore(uint64_t flags)
//{
//	__asm__ volatile("push %0; popf;" : : "rm" (flags) : "memory");
//}

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

static const patch_info shellcore_patches[] =
{
	// call sceKernelIsGenuineCEX 5.05
	{ NULL, 0x16D05B, "\x31\xC0\x90\x90\x90", 5 },
{ NULL, 0x79980B, "\x31\xC0\x90\x90\x90", 5 },
{ NULL, 0x7E5A13, "\x31\xC0\x90\x90\x90", 5 },
{ NULL, 0x94715B, "\x31\xC0\x90\x90\x90", 5 },

// call nidf_libSceDipsw_0xD21CE9E2F639A83C 5.05
{ NULL, 0x16D087, "\x31\xC0\x90\x90\x90", 5 },
{ NULL, 0x23747B, "\x31\xC0\x90\x90\x90", 5 },
{ NULL, 0x799837, "\x31\xC0\x90\x90\x90", 5 },
{ NULL, 0x947187, "\x31\xC0\x90\x90\x90", 5 },

// enable fpkg for patches 5.05
{ NULL, 0x3E0602, "\xE9\x96\x00\x00\x00\x90\x90\x90", 8 },

// debug pkg free string 5.05
{ NULL, 0xEA96A7, "free\0", 5 },

{ NULL, 0, NULL, 0 },
};

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

// flatz
#define PROT_CPU_READ 1
#define PROT_CPU_WRITE 2
#define PROT_CPU_EXEC 4
#define PROT_GPU_EXEC 8
#define PROT_GPU_READ 16
#define PROT_GPU_WRITE 32
struct proc_vm_map_entry {
	uint64_t start;
	uint64_t end;
	uint64_t offset;
	int prot;
	int pad;
};

// flatz

int proc_get_vm_map(struct proc* p, struct proc_vm_map_entry** entries, size_t* num_entries) {
	struct vmspace* vm;
	struct proc_vm_map_entry* info = NULL;
	vm_map_t map;
	vm_map_entry_t entry;
	size_t n, i;
	int ret;

	void(*vmspace_free)(struct vmspace *) = kdlsym(vmspace_free);
	struct vmspace* (*vmspace_acquire_ref)(struct proc *) = kdlsym(vmspace_acquire_ref);
	void(*_mtx_lock_flags)(struct mtx *m, int opts, const char *file, int line) = kdlsym(_mtx_lock_flags);
	void(*_vm_map_lock_read)(vm_map_t map, const char *file, int line) = kdlsym(_vm_map_lock_read);
	void(*_vm_map_unlock_read)(vm_map_t map, const char *file, int line) = kdlsym(_vm_map_unlock_read);
	void(*_mtx_unlock_flags)(struct mtx *m, int opts, const char *file, int line) = kdlsym(_mtx_unlock_flags);

	WriteLog(LL_Debug, "%p %p %p %p", _mtx_lock_flags, _mtx_unlock_flags, _vm_map_unlock_read, _vm_map_lock_read);

	void    (*faultin)(struct proc *p) = (void*)(gKernelBase + 0x00006DD0);
	void(*wakeup)(void *chan) = (void*)(gKernelBase + 0x003FB940);

	if (!p) {
		ret = EINVAL;
		goto error;
	}
	if (!entries) {
		ret = EINVAL;
		goto error;
	}
	if (!num_entries) {
		ret = EINVAL;
		goto error;
	}

	PROC_LOCK(p);
	if (p->p_flag & P_WEXIT) {
		PROC_UNLOCK(p);
		ret = ESRCH;
		goto error;
	}
	_PHOLD(p);
	PROC_UNLOCK(p);

	vm = vmspace_acquire_ref(p);
	if (!vm) {
		PRELE(p);
		ret = ESRCH;
		goto error;
	}
	map = &vm->vm_map;

	vm_map_lock_read(map);
	for (entry = map->header.next, n = 0; entry != &map->header; entry = entry->next) {
		if (entry->eflags & MAP_ENTRY_IS_SUB_MAP)
			continue;
		++n;
	}
	if (n == 0)
		goto done;
	size_t allocSize = n * sizeof(*info);
	info = (struct proc_vm_map_entry*)kmalloc(allocSize);
	if (!info) {
		vm_map_unlock_read(map);
		vmspace_free(vm);

		PRELE(p);

		ret = ENOMEM;
		goto error;
	}
	kmemset(info, 0, n * sizeof(*info));
	for (entry = map->header.next, i = 0; entry != &map->header; entry = entry->next) {
		if (entry->eflags & MAP_ENTRY_IS_SUB_MAP)
			continue;

		info[i].start = entry->start;
		info[i].end = entry->end;
		info[i].offset = entry->offset;

		info[i].prot = 0;
		if (entry->protection & VM_PROT_READ)
			info[i].prot |= PROT_CPU_READ;
		if (entry->protection & VM_PROT_WRITE)
			info[i].prot |= PROT_CPU_WRITE;
		if (entry->protection & VM_PROT_EXECUTE)
			info[i].prot |= PROT_CPU_EXEC;
		//if (entry->protection & VM_PROT_GPU_READ)
		//	info[i].prot |= PROT_GPU_READ;
		//if (entry->protection & VM_PROT_GPU_WRITE)
		//	info[i].prot |= PROT_GPU_WRITE;

		++i;
	}

done:
	vm_map_unlock_read(map);
	vmspace_free(vm);

	PRELE(p);

	*num_entries = n;
	*entries = info;

	info = NULL;
	ret = 0;

error:
	if (info)
		kfree(info, allocSize);

	return ret;
}


int do_syscore_patches(void) {
	struct proc* p = NULL;
	struct proc_vm_map_entry* entries = NULL;
	uint8_t* text_seg_base = NULL;
	size_t i, n;
	int ret = 0;

	void(*_mtx_lock_flags)(struct mtx *m, int opts, const char *file, int line) = kdlsym(_mtx_lock_flags);
	void(*_vm_map_lock_read)(vm_map_t map, const char *file, int line) = kdlsym(_vm_map_lock_read);
	void(*_vm_map_unlock_read)(vm_map_t map, const char *file, int line) = kdlsym(_vm_map_unlock_read);
	void(*_mtx_unlock_flags)(struct mtx *m, int opts, const char *file, int line) = kdlsym(_mtx_unlock_flags);

	WriteLog(LL_Debug, "%p %p %p %p", _mtx_lock_flags, _mtx_unlock_flags, _vm_map_unlock_read, _vm_map_lock_read);

	WriteLog(LL_Error, "run dem shellcore patches fam");

	p = proc_find_by_name("SceShellCore");
	if (!p) {
		WriteLog(LL_Error, "Unable to find syscore process.\n");
		ret = ENOENT;
		goto error;
	}

	ret = proc_get_vm_map(p, &entries, &n);
	if (ret) {
		WriteLog(LL_Error, "proc_get_vm_map(%p) failed.\n", p);
		goto error;
	}

	for (i = 0; i < n; ++i) {
		if (entries[i].prot == (PROT_CPU_READ | PROT_CPU_EXEC)) {
			text_seg_base = (uint8_t*)entries[i].start;
			break;
		}
	}
	if (!text_seg_base) {
		//printf("Unable to find text segment base of syscore process.\n");
		ret = ESRCH;
		goto error;
	}

//	size_t console_redir_offsets[] = {
//#      if FW_VER == 501
//		0x93DD7, 0x94C1B, 0x9C968, /* /dev/deci_stdout */
//		0x93DE8, 0x94C2C, 0x9C979, /* /dev/deci_stderr */
//#      endif
//	};
	for (i = 0; i < ARRAYSIZE(shellcore_patches) - 1; ++i) {
		ret = proc_rw_mem(p, text_seg_base + shellcore_patches[i].address, shellcore_patches[i].size, (void*)shellcore_patches[i].data, &n, true);

		if (ret) {
			//printf("proc_write_mem(%p) failed.\n", p);
			goto error;
		}
	}

	//printf("Syscore process has been patched.\n");

error:
	PROC_UNLOCK(p);

	if (entries)
		kfree(entries, sizeof(*entries));

	return ret;
}

//struct ptrace_io_desc {
//	int	   piod_op;	   /* I/O operation */
//	void	   *piod_offs;	   /* child offset */
//	void	   *piod_addr;	   /* parent offset */
//	size_t  piod_len;	   /* request length */
//};

/*
* Operations in piod_op.
*/
#define PIOD_READ_D	   1	   /* Read from	D space	*/
#define PIOD_WRITE_D	   2	   /* Write to D space */
#define PIOD_READ_I	   3	   /* Read from	I space	*/
#define PIOD_WRITE_I	   4	   /* Write to I space */


uint64_t ptrace_io(int pid, int op, void *off, void *addr, unsigned long long len)
{
	struct ptrace_io_desc io_desc;
	unsigned long long ret;

	io_desc.piod_op = op;
	io_desc.piod_offs = off;
	io_desc.piod_addr = addr;
	io_desc.piod_len = len;
	ret = kptrace(PT_IO, pid, (caddr_t)&io_desc, 0);

	if (ret != 0)
		return ret;
	else
		return (uint64_t)io_desc.piod_len;
}
#include <sys/sysproto.h>

int kmount(char *type, char *path, int flags, caddr_t data)
{
	int(*sys_mount)(struct thread *, struct mount_args *) = (void*)(gKernelBase + 0x001DF910);

	int error;
	struct mount_args uap;
	struct thread *td = curthread;

	// clear errors
	td->td_retval[0] = 0;

	// call syscall
	uap.type = type;
	uap.path = path;
	uap.flags = flags;
	uap.data = data;

	error = sys_mount(td, &uap);
	if (error)
		return -error;

	// success
	return td->td_retval[0];
}

int mount_procfs()
{
	int result = kmkdir("/mnt/proc", 0777);
	if (result < 0)
	{
		WriteLog(LL_Error, "Failed to create /mnt/proc\n");
		return -1;
	}

	result = kmount("procfs", "/mnt/proc", 0, NULL);
	if (result < 0)
	{
		WriteLog(LL_Error, "Failed to mount procfs: %d\n", result);
		return -2;
	}

	return 0;
}

#include <sys/fcntl.h>
int find_process(const char* target)
{
	int pid;
	int mib[3] = { 1, 14, 0 };
	size_t size, count;
	char* data;
	char* proc;
	WriteLog(LL_Debug, "here");
	if (k__sysctl(mib, 3, NULL, &size, NULL, 0) < 0)
	{
		return -1;
	}

	WriteLog(LL_Debug, "here");
	if (size == 0)
	{
		return -2;
	}

	WriteLog(LL_Debug, "here");
	size_t origSize = size;
	data = (char*)kmalloc(size);
	WriteLog(LL_Debug, "here");
	if (data == NULL)
	{
		return -3;
	}

	WriteLog(LL_Debug, "here");
	if (k__sysctl(mib, 3, data, &size, NULL, 0) < 0)
	{
		kfree(data, origSize);
		return -4;
	}

	WriteLog(LL_Debug, "here");
	count = size / 0x448;
	proc = data;
	pid = -1;
	WriteLog(LL_Debug, "here");
	while (count != 0)
	{
		WriteLog(LL_Debug, "here");
		char* name = &proc[0x1BF];
		if (__strncmp(name, target, strlen(target)) == 0)
		{
			WriteLog(LL_Debug, "here");
			pid = *(int*)(&proc[0x48]);
			break;
		}
		WriteLog(LL_Debug, "here");
		proc += 0x448;
		count--;
	}

	WriteLog(LL_Debug, "here");
	kfree(data, origSize);
	return pid;
}

int get_code_info(int pid, uint64_t* paddress, uint64_t* psize, uint64_t known_size)
{
	WriteLog(LL_Debug, "here");
	int mib[4] = { 1, 14, 32, pid };
	size_t size, count;
	char* data;
	char* entry;

	WriteLog(LL_Debug, "here");

	WriteLog(LL_Debug, "here");
	if (k__sysctl(mib, 4, NULL, &size, NULL, 0) < 0)
	{
		return -1;
	}
	WriteLog(LL_Debug, "here");
	if (size == 0)
	{
		return -2;
	}
	WriteLog(LL_Debug, "here");
	size_t origSize = size;
	data = (char*)kmalloc(size);
	WriteLog(LL_Debug, "here");
	if (data == NULL)
	{
		return -3;
	}
	WriteLog(LL_Debug, "here");
	if (k__sysctl(mib, 4, data, &size, NULL, 0) < 0)
	{
		kfree(data, origSize);
		return -4;
	}
	WriteLog(LL_Debug, "here");
	int struct_size = *(int*)data;
	count = size / struct_size;
	entry = data;

	int found = 0;
	while (count != 0)
	{
		int type = *(int*)(&entry[0x4]);
		uint64_t start_addr = *(uint64_t*)(&entry[0x8]);
		uint64_t end_addr = *(uint64_t*)(&entry[0x10]);
		uint64_t code_size = end_addr - start_addr;
		uint32_t prot = *(uint32_t*)(&entry[0x38]);

		WriteLog(LL_Info, "%d 0x%llx 0x%llx (0x%llx) %x\n", type, start_addr, end_addr, code_size, prot);

		if (type == 9 && prot == 5 && code_size == known_size)
		{
			*paddress = start_addr;
			*psize = (end_addr - start_addr);
			found = 1;
			break;
		}

		entry += struct_size;
		count--;
	}

	kfree(data, origSize);
	return !found ? -5 : 0;
}

#include <sys/unistd.h>

int apply_patches(int pid, uint64_t known_size, const patch_info* patches)
{
	uint64_t code_address, code_size;
	int result = get_code_info(pid, &code_address, &code_size, known_size);
	if (result < 0)
	{
		WriteLog(LL_Info, "Failed to get code info for %d: %d\n", pid, result);
		return -1;
	}
	int(*snprintf)(char *str, size_t size, const char *format, ...) = kdlsym(snprintf);
	char proc_path[64];
	snprintf(proc_path, sizeof(proc_path), "/mnt/proc/%d/mem", pid);

	int fd = kopen(proc_path, O_RDWR, 0);
	if (fd < 0)
	{
		WriteLog(LL_Info, "Failed to open %s!\n", proc_path);
		return -2;
	}

	WriteLog(LL_Info, "Opened process memory...\n");
	for (int i = 0; patches[i].data != NULL; i++)
	{
		klseek(fd, code_address + patches[i].address, SEEK_SET);
		result = kwrite(fd, patches[i].data, patches[i].size);
		WriteLog(LL_Info, "patch %s: %d %d\n", patches[i].name, result, result );
	}

	kclose(fd);
	return (result < 0 ? result : 0);
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
	//void(*_mtx_unlock_flags)(struct mtx *m, int opts, const char *file, int line) = kdlsym(_mtx_unlock_flags);
	void(*_vm_map_lock_read)(vm_map_t map, const char *file, int line) = kdlsym(_vm_map_lock_read);
	void(*_vm_map_unlock_read)(vm_map_t map, const char *file, int line) = kdlsym(_vm_map_unlock_read);
	//void(*_mtx_lock_flags)(struct mtx *m, int opts, const char *file, int line) = kdlsym(_mtx_lock_flags);
	void(*vmspace_free)(struct vmspace *) = kdlsym(vmspace_free);
	struct vmspace* (*vmspace_acquire_ref)(struct proc *) = kdlsym(vmspace_acquire_ref);
	//void(*faultin)(struct proc *p) = (void*)(gKernelBase + 0x00006DD0);
	//void(*wakeup)(void *chan) = (void*)(gKernelBase + 0x003FB940);


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

	const patch_info shellcore_patches[] =
	{
		// call sceKernelIsGenuineCEX 5.05
		{ NULL, 0x16D05B, "\x31\xC0\x90\x90\x90", 5 },
	{ NULL, 0x79980B, "\x31\xC0\x90\x90\x90", 5 },
	{ NULL, 0x7E5A13, "\x31\xC0\x90\x90\x90", 5 },
	{ NULL, 0x94715B, "\x31\xC0\x90\x90\x90", 5 },

	// call nidf_libSceDipsw_0xD21CE9E2F639A83C 5.05
	{ NULL, 0x16D087, "\x31\xC0\x90\x90\x90", 5 },
	{ NULL, 0x23747B, "\x31\xC0\x90\x90\x90", 5 },
	{ NULL, 0x799837, "\x31\xC0\x90\x90\x90", 5 },
	{ NULL, 0x947187, "\x31\xC0\x90\x90\x90", 5 },

	// enable fpkg for patches 5.05
	{ NULL, 0x3E0602, "\xE9\x96\x00\x00\x00\x90\x90\x90", 8 },

	// debug pkg free string 5.05
	{ NULL, 0xEA96A7, "free\0", 5 },

	{ NULL, 0, NULL, 0 },
	};

	int result;

	WriteLog(LL_Debug, "here");
	int shell_pid = find_process("SceShellCore");

	WriteLog(LL_Debug, "here");
	if (shell_pid < 0)
	{
		WriteLog(LL_Error, "Failed to find SceShellCore: %d\n", shell_pid);
		return -1;
	}
	WriteLog(LL_Info, "Found SceShellCore at pid %d!\n", shell_pid);

	result = mount_procfs();
	WriteLog(LL_Debug, "here");
	if (result)
	{
		return -2;
	}

	WriteLog(LL_Info, "Patching SceShellCore...\n");
	result = apply_patches(shell_pid, 0x1170000, shellcore_patches);
	WriteLog(LL_Debug, "here");
	return true;

	struct proc* scProc = proc_find_by_name("SceShellCore");
	if (!scProc)
	{
		WriteLog(LL_Error, "uh couldn't find shellcor bruh");
		return false;
	}
	WriteLog(LL_Error, "kendick lamar - alright");

	// according to flatz code we need to acquire both
	//PROC_LOCK(scProc);
	

	struct vmspace* vm = vmspace_acquire_ref(scProc);
	vm_map_t map = &scProc->p_vmspace->vm_map;
	vm_map_lock_read(map);
	struct vm_map_entry* entry = map->header.next;

	int32_t scPid = scProc->p_pid;
	uint8_t* scBaseAddress = (uint8_t*)entry->start;
	uint64_t scSize = (uint64_t)entry->end - entry->start;

	WriteLog(LL_Debug, "here");
	// Free the vmmap
	vm_map_unlock_read(map);

	WriteLog(LL_Debug, "here");
	vmspace_free(vm);

	WriteLog(LL_Info, "SceShellCore - pid: %d baseAddress: %p size: %llx", scPid, scBaseAddress, scSize);

	// DO U SUX DIX?
	//// set diag auth ID flags
	curthread->td_ucred->cr_sceAuthID = 0x3800000000000007ULL;

	//// make system credentials
	curthread->td_ucred->cr_sceCaps[0] = 0xFFFFFFFFFFFFFFFFULL;
	curthread->td_ucred->cr_sceCaps[1] = 0xFFFFFFFFFFFFFFFFULL;

	WriteLog(LL_Debug, "here");

	WriteLog(LL_Debug, "here");
	int32_t ptErr = 0; kptrace(PT_ATTACH, scPid, 0, 0);
	if (ptErr == -1)
	{
		WriteLog(LL_Error, "shellcore attach fucked up: %d", ptErr);
		return false;
	}
	WriteLog(LL_Debug, "here");

	int stat = 0;
	kwait4(scPid, &stat, WUNTRACED, NULL);
	WriteLog(LL_Debug, "here");

	kkill(scPid, SIGSTOP);

	struct ptrace_vm_entry vm_entry;
	kmemset(&vm_entry, 0, sizeof(vm_entry));

	while (true) 
	{
		int32_t ret = kptrace(PT_VM_ENTRY, scPid, (void*)&vm_entry, 0);
		if (ret)
		{
			if (ret == ENOENT)
				break;

			WriteLog(LL_Error, "fetching vm map entries failed: %d", ret);
			goto yeet;
		}

		WriteLog(LL_Info, "vm entry %p %p", vm_entry.pve_start, vm_entry.pve_end);
		if (!(vm_entry.pve_prot & (VM_PROT_READ | VM_PROT_EXECUTE)))
			continue;

		WriteLog(LL_Info, "found r-x segment: %p", vm_entry.pve_start);

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
		

		WriteLog(LL_Debug, "here");
		WriteLog(LL_Debug, "pt_io: %lld", ptrace_io(scPid, PIOD_WRITE_I, (void *)scBaseAddress + 0x3E0602, jmp__nop_nop_nop, sizeof(jmp__nop_nop_nop)));

		WriteLog(LL_Debug, "pt_io: %lld", ptrace_io(scPid, PIOD_WRITE_I, (void *)scBaseAddress + SHELLCORE_ENABLE_DEBUG_PKG_PATCH_1_1_OFFSET, xor__eax_eax, sizeof(xor__eax_eax)));
		WriteLog(LL_Debug, "pt_io: %lld", ptrace_io(scPid, PIOD_WRITE_I, (void *)scBaseAddress + SHELLCORE_ENABLE_DEBUG_PKG_PATCH_1_2_OFFSET, xor__eax_eax, sizeof(xor__eax_eax)));
		WriteLog(LL_Debug, "pt_io: %lld", ptrace_io(scPid, PIOD_WRITE_I, (void *)scBaseAddress + SHELLCORE_ENABLE_DEBUG_PKG_PATCH_1_3_OFFSET, xor__eax_eax, sizeof(xor__eax_eax)));
		WriteLog(LL_Debug, "pt_io: %lld", ptrace_io(scPid, PIOD_WRITE_I, (void *)scBaseAddress + SHELLCORE_ENABLE_DEBUG_PKG_PATCH_1_4_OFFSET, xor__eax_eax, sizeof(xor__eax_eax)));
		WriteLog(LL_Debug, "pt_io: %lld", ptrace_io(scPid, PIOD_WRITE_I, (void *)scBaseAddress + SHELLCORE_ENABLE_DEBUG_PKG_PATCH_2_1_OFFSET, xor__eax_eax, sizeof(xor__eax_eax)));
		WriteLog(LL_Debug, "pt_io: %lld", ptrace_io(scPid, PIOD_WRITE_I, (void *)scBaseAddress + SHELLCORE_ENABLE_DEBUG_PKG_PATCH_2_2_OFFSET, xor__eax_eax, sizeof(xor__eax_eax)));
		WriteLog(LL_Debug, "pt_io: %lld", ptrace_io(scPid, PIOD_WRITE_I, (void *)scBaseAddress + SHELLCORE_ENABLE_DEBUG_PKG_PATCH_2_3_OFFSET, xor__eax_eax, sizeof(xor__eax_eax)));
		WriteLog(LL_Debug, "pt_io: %lld", ptrace_io(scPid, PIOD_WRITE_I, (void *)scBaseAddress + SHELLCORE_ENABLE_DEBUG_PKG_PATCH_2_4_OFFSET, xor__eax_eax, sizeof(xor__eax_eax)));
		WriteLog(LL_Debug, "pt_io: %lld", ptrace_io(scPid, PIOD_WRITE_I, (void *)scBaseAddress + SHELLCORE_USE_FREE_PREFIX_INSTEAD_OF_FAKE_OFFSET, "free", 4));
		break;
	}

	kkill(scPid, SIGCONT);

	yeet:
	WriteLog(LL_Debug, "ptrace detach: %d", kptrace(PT_DETACH, scPid, (caddr_t)SIGCONT, 0));

	WriteLog(LL_Debug, "we gon' be alright");
	
	return true;
}

uint8_t hen_unload(struct hen_plugin_t* plugin)
{
	return true;
}