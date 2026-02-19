#ifndef _WIN32

#include "tty.h"

#include <unistd.h>

int raze_platform_stdin_is_tty(void)
{
	return isatty(STDIN_FILENO);
}

#endif
