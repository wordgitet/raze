#ifndef RAZE_CLI_MATCH_H
#define RAZE_CLI_MATCH_H

#include <stddef.h>

typedef struct RazeMatchRules {
	const char *ap_prefix;
	int recurse;
	const char *const *includes;
	size_t include_count;
	const char *const *excludes;
	size_t exclude_count;
} RazeMatchRules;

int raze_match_entry_path(const char *entry_name, const RazeMatchRules *rules);

#endif
