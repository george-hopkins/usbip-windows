/*
 * command structure borrowed from udev
 * (git://git.kernel.org/pub/scm/linux/hotplug/udev.git)
 *
 * Copyright (C) 2011 matt mooney <mfm@muteddisk.com>
 *               2005-2007 Takahiro Hirofuchi
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>

#include <getopt.h>

#include "usbip_common.h"
#include "usbip.h"
#ifndef __linux__
#include "usbip_windows.h"
#endif

static int usbip_help(int argc, char *argv[]);
static int usbip_version(int argc, char *argv[]);

static const char usbip_version_string[] = PACKAGE_STRING;

static const char usbip_usage_string[] =
	"usbip [--debug] [version]\n"
	"             [help] <command> <args>\n";

static void usbip_usage(void)
{
	printf("usage: %s", usbip_usage_string);
}

struct command {
	const char *name;
	int (*fn)(int argc, char *argv[]);
	const char *help;
	void (*usage)(void);
};

static const struct command cmds[] = {
	{
		"help",
		usbip_help,
		NULL,
		NULL
	},
	{
		"version",
		usbip_version,
		NULL,
		NULL
	},
	{
		"attach",
		usbip_attach,
		"Attach a remote USB device",
		usbip_attach_usage
	},
	{
		"detach",
		usbip_detach,
		"Detach a remote USB device",
		usbip_detach_usage
	},
	{
		"list",
		usbip_list,
		"List exported or local USB devices",
		usbip_list_usage
	},
#ifdef __linux__
	{
		"bind",
		usbip_bind,
		"Bind device to " USBIP_HOST_DRV_NAME ".ko",
		usbip_bind_usage
	},
	{
		"unbind",
		usbip_unbind,
		"Unbind device from " USBIP_HOST_DRV_NAME ".ko",
		usbip_unbind_usage
	},
#endif
	{ NULL, NULL, NULL, NULL }
};

static int usbip_help(int argc, char *argv[])
{
	const struct command *cmd;
	int i;
	int ret = 0;

	if (argc > 1 && argv++) {
		for (i = 0; cmds[i].name != NULL; i++)
			if (!strcmp(cmds[i].name, argv[0]) && cmds[i].usage) {
				cmds[i].usage();
				goto done;
			}
		ret = -1;
	}

	usbip_usage();
	printf("\n");
	for (cmd = cmds; cmd->name != NULL; cmd++)
		if (cmd->help != NULL)
			printf("  %-10s %s\n", cmd->name, cmd->help);
	printf("\n");
done:
	return ret;
}

static int usbip_version(int argc, char *argv[])
{
	(void) argc;
	(void) argv;

	printf("%s\n", usbip_version_string);
	return 0;
}

static int run_command(const struct command *cmd, int argc, char *argv[])
{
	dbg("running command: `%s'\n", cmd->name);
	return cmd->fn(argc, argv);
}

int main(int argc, char *argv[])
{
	static const struct option opts[] = {
		{ "debug", no_argument, NULL, 'd' },
		{ NULL, 0, NULL, 0 }
	};
	char *cmd;
	int opt;
	int i, rc = -1;

#ifndef __linux__
	if (init_socket())
		return EXIT_FAILURE;
#endif

	opterr = 0;
	for (;;) {
		opt = getopt_long(argc, argv, "+d", opts, NULL);

		if (opt == -1)
			break;

		switch (opt) {
		case 'd':
			usbip_use_debug = 1;
			usbip_use_stderr = 1;
			break;
		default:
			goto err_out;
		}
	}

	cmd = argv[optind];
	if (cmd) {
		for (i = 0; cmds[i].name != NULL; i++)
			if (!strcmp(cmds[i].name, cmd)) {
				argc -= optind;
				argv += optind;
				optind = 0;
				rc = run_command(&cmds[i], argc, argv);
				goto out;
			}
	}

err_out:
	usbip_usage();
out:
#ifndef __linux__
	cleanup_socket();
#endif
	return (rc > -1 ? EXIT_SUCCESS : EXIT_FAILURE);
}
