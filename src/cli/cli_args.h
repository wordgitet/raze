#ifndef RAZE_CLI_ARGS_H
#define RAZE_CLI_ARGS_H

#include <stddef.h>

#include "raze/raze.h"

typedef enum RazeCliCommand {
	RAZE_CLI_CMD_NONE = 0,
	RAZE_CLI_CMD_X,
	RAZE_CLI_CMD_E,
	RAZE_CLI_CMD_L,
	RAZE_CLI_CMD_LT,
	RAZE_CLI_CMD_T,
	RAZE_CLI_CMD_P
} RazeCliCommand;

typedef struct RazeCliStringVec {
	char **items;
	size_t count;
	size_t capacity;
} RazeCliStringVec;

typedef struct RazeCliSwitches {
	RazeOverwriteMode overwrite_mode;
	int quiet;
	int stop_switch_scan;
	int recurse;
	int strip_paths;
	int ad_mode;
	int stderr_only;
	int idp;
	int idn;
	int cfg_noop;
	const char *password;
	int password_present;
	const char *output_dir;
	const char *ap_prefix;
	RazeCliStringVec includes;
	RazeCliStringVec excludes;
} RazeCliSwitches;

typedef struct RazeCliArgs {
	RazeCliCommand command;
	const char *archive_path;
	RazeCliSwitches sw;
} RazeCliArgs;

void raze_cli_args_init(RazeCliArgs *args);
void raze_cli_args_free(RazeCliArgs *args);
RazeStatus raze_cli_parse_args(
	int argc,
	char **argv,
	RazeCliArgs *out,
	char *errbuf,
	size_t errbuf_size
);
const char *raze_cli_command_name(RazeCliCommand command);
int raze_cli_command_is_extract_like(RazeCliCommand command);

#endif
