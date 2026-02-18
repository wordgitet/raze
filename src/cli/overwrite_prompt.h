#ifndef RAZE_CLI_OVERWRITE_PROMPT_H
#define RAZE_CLI_OVERWRITE_PROMPT_H

#include <stdint.h>
#include <time.h>

#include "raze/raze.h"

typedef enum RazeOverwriteDecision {
    RAZE_OVERWRITE_DECISION_REPLACE = 0,
    RAZE_OVERWRITE_DECISION_SKIP = 1,
    RAZE_OVERWRITE_DECISION_ABORT = 2,
    RAZE_OVERWRITE_DECISION_ERROR = 3
} RazeOverwriteDecision;

typedef struct RazeOverwritePrompt {
    RazeOverwriteMode mode;
    int replace_all;
    int skip_all;
    int interactive;
} RazeOverwritePrompt;

typedef struct RazeOverwriteStats {
    uint64_t existing_size;
    time_t existing_mtime;
    int existing_mtime_present;
    uint64_t archive_size;
    time_t archive_mtime;
    int archive_mtime_present;
} RazeOverwriteStats;

void raze_overwrite_prompt_init(RazeOverwritePrompt *prompt, RazeOverwriteMode mode);
RazeOverwriteDecision raze_overwrite_prompt_decide(
    RazeOverwritePrompt *prompt,
    const char *path,
    const RazeOverwriteStats *stats
);

#endif
