#pragma once
#include <oni/plugins/plugin.h>

struct hen_plugin_t
{
	struct plugin_t plugin;
};

void hen_init(struct hen_plugin_t* plugin);