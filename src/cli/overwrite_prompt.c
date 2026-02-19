#include "overwrite_prompt.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../platform/tty.h"

static void format_time_value(time_t value, int present, char *out, size_t out_len) {
    struct tm tm_value;
    struct tm *tm_ptr;

    if (out == 0 || out_len == 0) {
        return;
    }

    if (!present) {
        snprintf(out, out_len, "n/a");
        return;
    }

    tm_ptr = localtime(&value);
    if (tm_ptr == 0) {
        snprintf(out, out_len, "n/a");
        return;
    }
    tm_value = *tm_ptr;

    if (strftime(out, out_len, "%Y-%m-%d %H:%M:%S", &tm_value) == 0) {
        snprintf(out, out_len, "n/a");
    }
}

static void trim_line(char *line) {
    size_t i;

    if (line == 0) {
        return;
    }

    for (i = 0; line[i] != '\0'; ++i) {
        line[i] = (char)tolower((unsigned char)line[i]);
        if (line[i] == '\n' || line[i] == '\r') {
            line[i] = '\0';
            break;
        }
    }
}

void raze_overwrite_prompt_init(RazeOverwritePrompt *prompt, RazeOverwriteMode mode) {
    if (prompt == 0) {
        return;
    }
    prompt->mode = mode;
    prompt->replace_all = 0;
    prompt->skip_all = 0;
    prompt->interactive = raze_platform_stdin_is_tty() &&
                          raze_platform_stdout_is_tty();
}

RazeOverwriteDecision raze_overwrite_prompt_decide(
    RazeOverwritePrompt *prompt,
    const char *path,
    const RazeOverwriteStats *stats
) {
    char existing_time[32];
    char archive_time[32];
    char line[64];

    if (prompt == 0 || path == 0 || stats == 0) {
        return RAZE_OVERWRITE_DECISION_ERROR;
    }

    if (prompt->mode == RAZE_OVERWRITE_ALWAYS || prompt->replace_all) {
        return RAZE_OVERWRITE_DECISION_REPLACE;
    }
    if (prompt->mode == RAZE_OVERWRITE_NEVER || prompt->skip_all) {
        return RAZE_OVERWRITE_DECISION_SKIP;
    }
    if (!prompt->interactive) {
        return RAZE_OVERWRITE_DECISION_ERROR;
    }

    format_time_value(stats->existing_mtime, stats->existing_mtime_present, existing_time, sizeof(existing_time));
    format_time_value(stats->archive_mtime, stats->archive_mtime_present, archive_time, sizeof(archive_time));

    fprintf(stderr, "raze: file exists: %s\n", path);
    fprintf(stderr, "  existing: size=%llu mtime=%s\n", (unsigned long long)stats->existing_size, existing_time);
    fprintf(stderr, "  archive:  size=%llu mtime=%s\n", (unsigned long long)stats->archive_size, archive_time);

    for (;;) {
        fprintf(stderr, "Overwrite? [yes/no/all/no-all]: ");
        if (fgets(line, sizeof(line), stdin) == 0) {
            /*
             * EOF on stdin (for example redirected /dev/null in CI)
             * is treated as non-interactive collision handling.
             */
            return RAZE_OVERWRITE_DECISION_ERROR;
        }
        trim_line(line);
        if (strcmp(line, "yes") == 0 || strcmp(line, "y") == 0) {
            return RAZE_OVERWRITE_DECISION_REPLACE;
        }
        if (strcmp(line, "no") == 0 || strcmp(line, "n") == 0) {
            return RAZE_OVERWRITE_DECISION_SKIP;
        }
        if (strcmp(line, "all") == 0) {
            prompt->replace_all = 1;
            return RAZE_OVERWRITE_DECISION_REPLACE;
        }
        if (strcmp(line, "no-all") == 0 || strcmp(line, "na") == 0) {
            prompt->skip_all = 1;
            return RAZE_OVERWRITE_DECISION_SKIP;
        }
        if (strcmp(line, "cancel") == 0 || strcmp(line, "c") == 0) {
            return RAZE_OVERWRITE_DECISION_ABORT;
        }
        fprintf(stderr, "Please type: yes, no, all, or no-all.\n");
    }
}
