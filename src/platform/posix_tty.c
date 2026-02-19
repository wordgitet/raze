#ifndef _WIN32

#include "tty.h"

#include <unistd.h>

int raze_platform_stdin_is_tty(void)
{
	return isatty(STDIN_FILENO);
}

int raze_platform_stdout_is_tty(void)
{
	return isatty(STDOUT_FILENO);
}

#endif
