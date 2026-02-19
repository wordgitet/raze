#ifdef _WIN32

#include "fs.h"

#include <direct.h>

int raze_platform_fs_mkdir(const char *path)
{
	return _mkdir(path);
}

#else
typedef int raze_win_fs_unused_t;
#endif
