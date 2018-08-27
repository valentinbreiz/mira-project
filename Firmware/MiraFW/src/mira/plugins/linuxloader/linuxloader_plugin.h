#pragma once
#include <oni/plugins/plugin.h>

struct linux_loader_plugin_t
{
	struct plugin_t plugin;
};

struct linux_loader_t
{
	uint64_t position;
	uint64_t length;
};

uint8_t linuxloader_load(struct filetransfer_plugin_t* plugin);
uint8_t linuxloader_unload(struct filetransfer_plugin_t* plugin);

void linux_loader_plugin_init(struct filetransfer_plugin_t* plugin);