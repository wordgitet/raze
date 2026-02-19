#ifndef _WIN32

#include "fs.h"

#include <sys/stat.h>

int raze_platform_fs_mkdir(const char *path)
{
	return mkdir(path, 0777);
}

#endif
