#ifdef _WIN32

#include "tty.h"

#include <io.h>

int raze_platform_stdin_is_tty(void)
{
	return _isatty(0);
}

int raze_platform_stdout_is_tty(void)
{
	return _isatty(1);
}

#else
typedef int raze_win_tty_unused_t;
#endif
