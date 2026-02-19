#include "cli_args.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define RAZE_ERRBUF_MIN 2U

static void set_err(char *errbuf, size_t errbuf_size, const char *msg)
{
	if (errbuf == 0 || errbuf_size < RAZE_ERRBUF_MIN) {
		return;
	}
	snprintf(errbuf, errbuf_size, "%s", msg != 0 ? msg : "error");
}

static int is_switch(const char *arg)
{
	return arg != 0 && arg[0] == '-' && arg[1] != '\0';
}

static int vec_push_dup(RazeCliStringVec *vec, const char *value)
{
	char **expanded;
	char *dup;
	size_t n;

	if (vec == 0 || value == 0) {
		return 0;
	}

	if (vec->count == vec->capacity) {
		size_t new_cap;

		new_cap = vec->capacity == 0U ? 8U : vec->capacity * 2U;
		expanded = (char **)realloc(vec->items,
					   new_cap * sizeof(vec->items[0]));
		if (expanded == 0) {
			return 0;
		}
		vec->items = expanded;
		vec->capacity = new_cap;
	}

	n = strlen(value) + 1U;
	dup = (char *)malloc(n);
	if (dup == 0) {
		return 0;
	}
	memcpy(dup, value, n);
	vec->items[vec->count++] = dup;
	return 1;
}

static void vec_free(RazeCliStringVec *vec)
{
	size_t i;

	if (vec == 0) {
		return;
	}
	for (i = 0; i < vec->count; ++i) {
		free(vec->items[i]);
	}
	free(vec->items);
	vec->items = 0;
	vec->count = 0;
	vec->capacity = 0;
}

static int vec_load_file(RazeCliStringVec *vec, const char *path)
{
	FILE *fp;
	char line[4096];

	fp = fopen(path, "rb");
	if (fp == 0) {
		return 0;
	}

	while (fgets(line, sizeof(line), fp) != 0) {
		char *start;
		char *end;

		start = line;
		while (*start != '\0' && isspace((unsigned char)*start)) {
			start++;
		}
		if (*start == '\0' || *start == '#') {
			continue;
		}
		end = start + strlen(start);
		while (end > start &&
		       (end[-1] == '\n' || end[-1] == '\r' ||
			isspace((unsigned char)end[-1]))) {
			end--;
		}
		*end = '\0';
		if (*start == '\0') {
			continue;
		}
		if (!vec_push_dup(vec, start)) {
			fclose(fp);
			return 0;
		}
	}

	fclose(fp);
	return 1;
}

static RazeCliCommand parse_command(const char *cmd)
{
	if (cmd == 0) {
		return RAZE_CLI_CMD_NONE;
	}
	if (strcmp(cmd, "x") == 0) {
		return RAZE_CLI_CMD_X;
	}
	if (strcmp(cmd, "e") == 0) {
		return RAZE_CLI_CMD_E;
	}
	if (strcmp(cmd, "l") == 0) {
		return RAZE_CLI_CMD_L;
	}
	if (strcmp(cmd, "lt") == 0) {
		return RAZE_CLI_CMD_LT;
	}
	if (strcmp(cmd, "t") == 0) {
		return RAZE_CLI_CMD_T;
	}
	if (strcmp(cmd, "p") == 0) {
		return RAZE_CLI_CMD_P;
	}
	return RAZE_CLI_CMD_NONE;
}

const char *raze_cli_command_name(RazeCliCommand command)
{
	switch (command) {
	case RAZE_CLI_CMD_X:
		return "x";
	case RAZE_CLI_CMD_E:
		return "e";
	case RAZE_CLI_CMD_L:
		return "l";
	case RAZE_CLI_CMD_LT:
		return "lt";
	case RAZE_CLI_CMD_T:
		return "t";
	case RAZE_CLI_CMD_P:
		return "p";
	default:
		return "<none>";
	}
}

int raze_cli_command_is_extract_like(RazeCliCommand command)
{
	return command == RAZE_CLI_CMD_X || command == RAZE_CLI_CMD_E;
}

void raze_cli_args_init(RazeCliArgs *args)
{
	if (args == 0) {
		return;
	}
	memset(args, 0, sizeof(*args));
	args->sw.overwrite_mode = RAZE_OVERWRITE_DEFAULT;
	args->sw.output_dir = ".";
}

void raze_cli_args_free(RazeCliArgs *args)
{
	if (args == 0) {
		return;
	}
	vec_free(&args->sw.includes);
	vec_free(&args->sw.excludes);
}

static int switch_allowed(
	RazeCliCommand command,
	const char *name,
	char *errbuf,
	size_t errbuf_size
)
{
	int extract_like;

	extract_like = raze_cli_command_is_extract_like(command);
	if (strcmp(name, "op") == 0 || strcmp(name, "o") == 0 ||
	    strcmp(name, "ep") == 0 || strcmp(name, "ad") == 0) {
		if (!extract_like) {
			set_err(errbuf, errbuf_size,
				"switch only allowed for x/e commands");
			return 0;
		}
	}
	return 1;
}

static int parse_switch(
	int argc,
	char **argv,
	int *index,
	RazeCliArgs *out,
	char *errbuf,
	size_t errbuf_size
)
{
	const char *arg;

	arg = argv[*index];
	if (strcmp(arg, "-") == 0) {
		out->sw.stop_switch_scan = 1;
		return 1;
	}
	if (strcmp(arg, "-y") == 0 || strcmp(arg, "-o+") == 0) {
		if (!switch_allowed(out->command, "o", errbuf, errbuf_size)) {
			return 0;
		}
		out->sw.overwrite_mode = RAZE_OVERWRITE_ALWAYS;
		return 1;
	}
	if (strcmp(arg, "-o-") == 0) {
		if (!switch_allowed(out->command, "o", errbuf, errbuf_size)) {
			return 0;
		}
		out->sw.overwrite_mode = RAZE_OVERWRITE_NEVER;
		return 1;
	}
	if (strncmp(arg, "-op", 3) == 0) {
		if (!switch_allowed(out->command, "op", errbuf, errbuf_size)) {
			return 0;
		}
		if (arg[3] != '\0') {
			out->sw.output_dir = arg + 3;
			return 1;
		}
		if (*index + 1 >= argc) {
			set_err(errbuf, errbuf_size, "missing path for -op");
			return 0;
		}
		*index += 1;
		out->sw.output_dir = argv[*index];
		return 1;
	}
	if (strcmp(arg, "-ep") == 0) {
		if (!switch_allowed(out->command, "ep", errbuf, errbuf_size)) {
			return 0;
		}
		out->sw.strip_paths = 1;
		return 1;
	}
	if (strcmp(arg, "-ad1") == 0 || strcmp(arg, "-ad2") == 0) {
		if (!switch_allowed(out->command, "ad", errbuf, errbuf_size)) {
			return 0;
		}
		out->sw.ad_mode = arg[3] - '0';
		return 1;
	}
	if (strcmp(arg, "-r") == 0) {
		out->sw.recurse = 1;
		return 1;
	}
	if (strcmp(arg, "-cfg-") == 0) {
		out->sw.cfg_noop = 1;
		return 1;
	}
	if (strcmp(arg, "-idq") == 0 || strcmp(arg, "-inul") == 0) {
		out->sw.quiet = 1;
		return 1;
	}
	if (strcmp(arg, "-idp") == 0) {
		out->sw.idp = 1;
		return 1;
	}
	if (strcmp(arg, "-idn") == 0) {
		out->sw.idn = 1;
		return 1;
	}
	if (strcmp(arg, "-ierr") == 0) {
		out->sw.stderr_only = 1;
		return 1;
	}
	if (strncmp(arg, "-ap", 3) == 0) {
		if (arg[3] == '\0') {
			set_err(errbuf, errbuf_size, "missing path for -ap");
			return 0;
		}
		out->sw.ap_prefix = arg + 3;
		return 1;
	}
	if (strncmp(arg, "-p", 2) == 0) {
		if (arg[2] != '\0') {
			out->sw.password = arg + 2;
			out->sw.password_present = 1;
		} else {
			out->sw.password = "";
			out->sw.password_present = 0;
		}
		return 1;
	}
	if (strncmp(arg, "-n@", 3) == 0) {
		if (arg[3] == '\0') {
			set_err(errbuf, errbuf_size, "missing file list path for -n@");
			return 0;
		}
		if (!vec_load_file(&out->sw.includes, arg + 3)) {
			set_err(errbuf, errbuf_size,
				"failed to read include list file");
			return 0;
		}
		return 1;
	}
	if (strncmp(arg, "-x@", 3) == 0) {
		if (arg[3] == '\0') {
			set_err(errbuf, errbuf_size, "missing file list path for -x@");
			return 0;
		}
		if (!vec_load_file(&out->sw.excludes, arg + 3)) {
			set_err(errbuf, errbuf_size,
				"failed to read exclude list file");
			return 0;
		}
		return 1;
	}
	if (strncmp(arg, "-n", 2) == 0) {
		if (arg[2] == '\0') {
			set_err(errbuf, errbuf_size, "missing mask for -n");
			return 0;
		}
		if (!vec_push_dup(&out->sw.includes, arg + 2)) {
			set_err(errbuf, errbuf_size, "out of memory");
			return 0;
		}
		return 1;
	}
	if (strncmp(arg, "-x", 2) == 0) {
		if (arg[2] == '\0') {
			set_err(errbuf, errbuf_size, "missing mask for -x");
			return 0;
		}
		if (!vec_push_dup(&out->sw.excludes, arg + 2)) {
			set_err(errbuf, errbuf_size, "out of memory");
			return 0;
		}
		return 1;
	}

	set_err(errbuf, errbuf_size, "unsupported or invalid switch");
	return 0;
}

static int looks_like_output_dir(const char *path)
{
	struct stat st;
	size_t n;

	if (path == 0 || path[0] == '\0') {
		return 0;
	}
	if (strcmp(path, ".") == 0 || strcmp(path, "..") == 0) {
		return 1;
	}
	if (strchr(path, '*') != 0 || strchr(path, '?') != 0) {
		return 0;
	}
	n = strlen(path);
	if (n > 0U && (path[n - 1U] == '/' || path[n - 1U] == '\\')) {
		return 1;
	}
	if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
		return 1;
	}
	return 0;
}

RazeStatus raze_cli_parse_args(
	int argc,
	char **argv,
	RazeCliArgs *out,
	char *errbuf,
	size_t errbuf_size
)
{
	int i;
	int positional_start;
	int positional_count;
	int explicit_output;

	if (out == 0) {
		set_err(errbuf, errbuf_size, "internal null args");
		return RAZE_STATUS_BAD_ARGUMENT;
	}

	raze_cli_args_init(out);

	if (argc < 2) {
		set_err(errbuf, errbuf_size, "missing command");
		return RAZE_STATUS_BAD_ARGUMENT;
	}

	out->command = parse_command(argv[1]);
	if (out->command == RAZE_CLI_CMD_NONE) {
		set_err(errbuf, errbuf_size, "unsupported command");
		return RAZE_STATUS_BAD_ARGUMENT;
	}
	if (out->command == RAZE_CLI_CMD_E) {
		out->sw.strip_paths = 1;
	}

	explicit_output = 0;
	for (i = 2; i < argc; ++i) {
		if (!out->sw.stop_switch_scan && is_switch(argv[i])) {
			if (!parse_switch(argc, argv, &i, out, errbuf,
					  errbuf_size)) {
				return RAZE_STATUS_BAD_ARGUMENT;
			}
			if (strncmp(argv[i], "-op", 3) == 0) {
				explicit_output = 1;
			}
			continue;
		}
		break;
	}

	positional_start = i;
	positional_count = argc - positional_start;
	if (positional_count < 1) {
		set_err(errbuf, errbuf_size, "missing archive path");
		return RAZE_STATUS_BAD_ARGUMENT;
	}

	out->archive_path = argv[positional_start++];
	positional_count--;

	if (raze_cli_command_is_extract_like(out->command) &&
	    !explicit_output && positional_count > 0) {
		int j;
		int last_is_mask;

		last_is_mask = 0;
		for (j = positional_start; j < argc - 1; ++j) {
			if (!vec_push_dup(&out->sw.includes, argv[j])) {
				set_err(errbuf, errbuf_size, "out of memory");
				return RAZE_STATUS_IO;
			}
		}
		if (argc - positional_start > 1) {
			last_is_mask = 0;
		} else {
			last_is_mask = !looks_like_output_dir(argv[argc - 1]);
		}
		if (last_is_mask) {
			if (!vec_push_dup(&out->sw.includes, argv[argc - 1])) {
				set_err(errbuf, errbuf_size, "out of memory");
				return RAZE_STATUS_IO;
			}
		} else {
			out->sw.output_dir = argv[argc - 1];
		}
	} else {
		for (i = positional_start; i < argc; ++i) {
			if (!vec_push_dup(&out->sw.includes, argv[i])) {
				set_err(errbuf, errbuf_size, "out of memory");
				return RAZE_STATUS_IO;
			}
		}
	}

	return RAZE_STATUS_OK;
}
