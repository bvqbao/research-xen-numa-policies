#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xenctrl.h>
#include <xenguest.h>
#include "../libxc/xc_private.h"

void usage(FILE *stream)
{
	fprintf(stream, "Usage: xen-trigger CMD ARGS...\nPerform the Xen "
		"Version Hypercall giving the specified list of arguments "
		"and\nreturning the result of the hypercall.\nThis hypercall "
		"is used in the development of Bigos as an ioctl-like "
		"syscall:\nperform many operations a unique hypercall.\n\n");
	fprintf(stream, "The command must be a signed integer in the decimal "
		"form.\n\n");
	fprintf(stream, "The arguments may be in the following form:\n"
		"  xVAL   where VAL is an hexadecimal number\n"
		"  uVAL   where VAL is a decimal number\n");
}

void error(const char *reason, ...)
{
	va_list ap;

	va_start(ap, reason);
	fprintf(stderr, "xen-trigger: ");
	vfprintf(stderr, reason, ap);
	fprintf(stderr, "\nplease type 'xen-trigger --help' for more "
		"informations\n");
	va_end(ap);

	exit(EXIT_FAILURE);
}

int hypercall(int command, unsigned long *args)
{
	int ret = -1;
    xc_interface *xch = xc_interface_open(NULL, NULL, 0);

    if (xch == NULL)
		return ret;

	ret = xencall2(xch->xcall, __HYPERVISOR_xen_version, 
		command, (unsigned long) args);

    xc_interface_close(xch);

    return ret;
}

int main(int argc, const char **argv)
{
	int i, ret;
	char *err = NULL;
	int command;
	unsigned long *args = alloca(argc * sizeof(unsigned long));

	if (argc < 2)
		error("invalid operand count: missing CMD");

	for (i=1; i<argc; i++)
		if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
			usage(stdout);
			return EXIT_SUCCESS;
		}

	command = strtol(argv[1], &err, 10);
	if (*err)
		error("invalid operand: '%s'", argv[1]);

	for (i=2; i<argc; i++) {
		switch (argv[i][0]) {
		case 'x':
			args[i-2] = strtol(argv[i] + 1, &err, 16);
			break;
		case 'u':
			args[i-2] = strtol(argv[i] + 1, &err, 10);
			break;
		default:
			error("invalid operand: '%s'", argv[i]);
		}

		if (*err)
			error("invalid operand: '%s'", argv[i]);
	}

	ret = hypercall(command, args);
	if (ret)
		error("hypercall failure");

	printf("ret = x%x / u%d\n", ret, ret);

	for (i=2; i<argc; i++)
		switch (argv[i][0]) {
		case 'x':
			printf("x%lx\n", args[i-2]);
			break;
		case 'u':
			printf("u%lu\n", args[i-2]);
			break;
		}

	return EXIT_SUCCESS;
}
