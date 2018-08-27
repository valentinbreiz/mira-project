#include "linuxloader_plugin.h"
#include <oni/framework.h>
#include <oni/utils/kdlsym.h>
#include <oni/messaging/messagemanager.h>
#include <oni/messaging/message.h>
#include <oni/utils/sys_wrappers.h>
#include <sys/dirent.h>
#include <sys/stat.h>
#include <oni/utils/memory/allocator.h>
#include <oni/utils/logger.h>

#ifndef MIN
#define MIN ( x, y ) ( (x) < (y) ? : (x) : (y) )
#endif

enum { FileTransfer_MaxPath = 255 };
enum LinuxLoaderCmds
{
	Linux_LoaderStart = 0x01,
};

void linuxloader_start_callback(struct allocation_t* ref);

extern struct logger_t* gLogger;

void linuxloader_plugin_init(struct linuxloader_plugin_t* plugin)
{
	if (!plugin)
		return;

	plugin->plugin.name = "LinuxLoader";
	plugin->plugin.description = "Load Linux on your PS4";

	plugin->plugin.plugin_load = (uint8_t(*)(void*)) linuxloader_load;
	plugin->plugin.plugin_unload = (uint8_t(*)(void*)) linuxloader_unload;
}

uint8_t linuxloader_load(struct linuxloader_plugin_t* plugin)
{
	// Register all of the callbacks
	messagemanager_registerCallback(gFramework->messageManager, RPCCAT_FILE, FileTransfer_Open, linuxloader_start_callback);

	return true;
}

uint8_t linuxloader_unload(struct linuxloader_plugin_t* plugin)
{
	messagemanager_unregisterCallback(gFramework->messageManager, RPCCAT_FILE, FileTransfer_Open, linuxloader_start_callback);

	return true;
}

extern char kexec[];
extern unsigned kexec_size;

void linuxloader_start_callback(struct allocation_t* ref)
{
	void* (*memset)(void *s, int c, size_t n) = kdlsym(memset);

	if (!ref)
		return;

	struct message_t* message = __get(ref);
	if (!message)
		return;

	if (message->header.request != 1)
		goto cleanup;


	if (!message->payload)
	{
		messagemanager_sendErrorMessage(gFramework->messageManager, ref, ENOMEM);
		goto cleanup;
	}

	void *DT_HASH_SEGMENT = (void *)(kernel_base + 0xB1D820); // I know it's for 4.55 but I think it will works
	memcpy(DT_HASH_SEGMENT, kexec, kexec_size);

	void(*kexec_init)(void *, void *) = DT_HASH_SEGMENT;

	kexec_init((void *)(kernel_base + 0x436040), NULL);

	// Say hello and put the kernel base in userland to we can use later
	printfkernel("PS4 Linux Loader for 5.05 by valentinbreiz\n");

	printfkernel("kernel base is:0x%016llx\n", kernel_base);

	uint64_t uaddr;
	memcpy(&uaddr, &args[2], 8);

	printfkernel("uaddr is:0x%016llx\n", uaddr);

	copyout(&kernel_base, uaddr, 8);

	//USB
	printfsocket("Open bzImage file from USB\n");
	FILE *fkernel = fopen("/mnt/usb0/bzImage", "r");
	fseek(fkernel, 0L, SEEK_END);
	int kernelsize = ftell(fkernel);
	fseek(fkernel, 0L, SEEK_SET);

	printfsocket("Open initramfs file from USB\n");
	FILE *finitramfs = fopen("/mnt/usb0/initramfs.cpio.gz", "r");
	fseek(finitramfs, 0L, SEEK_END);
	int initramfssize = ftell(finitramfs);
	fseek(finitramfs, 0L, SEEK_SET);

	printfsocket("kernelsize = %d\n", kernelsize);
	printfsocket("initramfssize = %d\n", initramfssize);

	printfsocket("Checks if the files are here\n");
	if (kernelsize == 0 || initramfssize == 0) {
		printfsocket("no file error im dead");
		fclose(fkernel);
		fclose(finitramfs);
		return;
	}

	void *kernel, *initramfs;
	char *cmd_line = "panic=0 clocksource=tsc radeon.dpm=0 console=tty0 console=ttyS0,115200n8 "
		"console=uart8250,mmio32,0xd0340000 video=HDMI-A-1:1920x1080-24@60 "
		"consoleblank=0 net.ifnames=0 drm.debug=0";

	kernel = malloc(kernelsize);
	initramfs = malloc(initramfssize);

	printfsocket("kernel = %llp\n", kernel);
	printfsocket("initramfs = %llp\n", initramfs);

	fread(kernel, kernelsize, 1, fkernel);
	fread(initramfs, initramfssize, 1, finitramfs);

	fclose(fkernel);
	fclose(finitramfs);

	//Call sys_kexec (153 syscall)
	syscall(153, kernel, kernelsize, initramfs, initramfssize, cmd_line);

	free(kernel);
	free(initramfs);

	//Reboot PS4
	int evf = syscall(540, "SceSysCoreReboot");
	syscall(546, evf, 0x4000, 0);
	syscall(541, evf);
	syscall(37, 1, 30);


cleanup:
	__dec(ref);
}

}
