#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "raze/raze.h"

static void print_usage(const char *prog) {
    printf("Raze V1 (RAR5 single-volume extractor)\n");
    printf("Usage: %s x [switches] <archive.rar> [path_to_extract/]\n", prog);
    printf("       %s l[t] <archive.rar>\n", prog);
    printf("       %s --help\n", prog);
    printf("\nSupported switches:\n");
    printf("  -op<path>   set output path\n");
    printf("  -o[+|-]     set overwrite mode (+ always, - never)\n");
    printf("  -p[pass]    set password (-p prompts on tty)\n");
    printf("  -y          assume yes on all queries (same as -o+)\n");
    printf("  -idq        quiet messages\n");
    printf("  -inul       disable all messages\n");
    printf("\nCommands: x (extract), l (list), lt (technical list)\n");
}

static int status_to_exit_code(RazeStatus status) {
    switch (status) {
        case RAZE_STATUS_OK:
            return 0;
        case RAZE_STATUS_BAD_ARGUMENT:
            return 2;
        case RAZE_STATUS_UNSUPPORTED:
        case RAZE_STATUS_UNSUPPORTED_FEATURE:
            return 3;
        case RAZE_STATUS_BAD_ARCHIVE:
            return 4;
        case RAZE_STATUS_PATH_VIOLATION:
            return 5;
        case RAZE_STATUS_CRC_MISMATCH:
            return 6;
        case RAZE_STATUS_EXISTS:
            return 7;
        case RAZE_STATUS_IO:
            return 8;
        case RAZE_STATUS_ABORTED:
            return 130;
        default:
            return 1;
    }
}

static int parse_switch(
    int argc,
    char **argv,
    int *index,
    RazeExtractOptions *options,
    const char **output_dir,
    int *password_prompt
) {
    const char *arg = argv[*index];

    if (strcmp(arg, "-y") == 0 || strcmp(arg, "-o+") == 0) {
        options->overwrite_mode = RAZE_OVERWRITE_ALWAYS;
        return 1;
    }

    if (strcmp(arg, "-inul") == 0 || strcmp(arg, "-idq") == 0) {
        options->quiet = 1;
        return 1;
    }

    if (strcmp(arg, "-o-") == 0) {
        options->overwrite_mode = RAZE_OVERWRITE_NEVER;
        return 1;
    }

    if (strncmp(arg, "-op", 3) == 0) {
        if (arg[3] != '\0') {
            *output_dir = arg + 3;
            return 1;
        }
        if (*index + 1 >= argc) {
            return 0;
        }
        *index += 1;
        *output_dir = argv[*index];
        return 1;
    }

    if (strncmp(arg, "-p", 2) == 0) {
        if (arg[2] != '\0') {
            options->password = arg + 2;
            options->password_present = 1;
            return 1;
        }
        if (password_prompt != 0) {
            *password_prompt = 1;
        }
        return 1;
    }

    return 0;
}

static int prompt_password(char *buf, size_t buf_size) {
    size_t len;

    if (buf == 0 || buf_size < 2) {
        return 0;
    }
    if (!isatty(STDIN_FILENO)) {
        return 0;
    }

    fprintf(stderr, "Enter password: ");
    fflush(stderr);
    if (fgets(buf, (int)buf_size, stdin) == 0) {
        return 0;
    }

    len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        buf[len - 1] = '\0';
        len--;
    }
    return 1;
}

int main(int argc, char **argv) {
    RazeDecoder decoder;
    RazeExtractOptions options;
    RazeStatus status;
    const char *command = 0;
    const char *archive = 0;
    const char *output_dir = ".";
    int i;
    int scan_switches = 1;
    int have_explicit_output = 0;
    int is_extract = 0;
    int list_technical = 0;
    int password_prompt = 0;
    char password_buf[1024];

    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    if (argc < 3) {
        print_usage(argv[0]);
        return 2;
    }

    command = argv[1];
    if (strcmp(command, "x") == 0) {
        is_extract = 1;
    } else if (strcmp(command, "l") == 0) {
    } else if (strcmp(command, "lt") == 0) {
        list_technical = 1;
    } else {
        fprintf(stderr, "raze: unsupported command: %s\n", command);
        return 2;
    }

    options = raze_extract_options_default();

    for (i = 2; i < argc; ++i) {
        const char *arg = argv[i];
        if (scan_switches && strcmp(arg, "-") == 0) {
            scan_switches = 0;
            continue;
        }

        if (scan_switches && arg[0] == '-' && arg[1] != '\0') {
            if (!is_extract) {
                fprintf(stderr, "raze: unsupported or invalid switch: %s\n", arg);
                return 2;
            }
            if (!parse_switch(argc, argv, &i, &options, &output_dir, &password_prompt)) {
                fprintf(stderr, "raze: unsupported or invalid switch: %s\n", arg);
                return 2;
            }
            have_explicit_output = have_explicit_output || strncmp(arg, "-op", 3) == 0;
            continue;
        }

        if (archive == 0) {
            archive = arg;
            continue;
        }

        if (is_extract && !have_explicit_output) {
            output_dir = arg;
            have_explicit_output = 1;
            continue;
        }

        fprintf(stderr, "raze: too many positional arguments\n");
        return 2;
    }

    if (archive == 0) {
        fprintf(stderr, "raze: missing archive path\n");
        return 2;
    }

    if (is_extract && password_prompt && !options.password_present) {
        if (prompt_password(password_buf, sizeof(password_buf))) {
            options.password = password_buf;
            options.password_present = 1;
        }
    }

	status = raze_decoder_init(&decoder);
	if (status != RAZE_STATUS_OK) {
		const char *detail = raze_last_error_detail();
		if (detail != 0 && detail[0] != '\0') {
			fprintf(stderr, "raze: %s: %s\n", raze_status_string(status), detail);
		} else {
			fprintf(stderr, "raze: decoder initialization failed\n");
		}
		return status_to_exit_code(status);
	}

    if (is_extract) {
        status = raze_decode_archive_with_options(&decoder, archive, output_dir, &options);
    } else {
        status = raze_list_archive(&decoder, archive, list_technical);
    }
	if (status != RAZE_STATUS_OK) {
		if (!options.quiet) {
			const char *detail = raze_last_error_detail();
			if (detail != 0 && detail[0] != '\0') {
				fprintf(stderr, "raze: %s: %s\n", raze_status_string(status), detail);
			} else {
				fprintf(stderr, "raze: %s\n", raze_status_string(status));
			}
		}
		return status_to_exit_code(status);
	}

    if (is_extract && options.verbose && !options.quiet) {
        printf("raze: extract complete\n");
    }

    return 0;
}
