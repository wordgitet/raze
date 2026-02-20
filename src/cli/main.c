#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "raze/raze.h"

#include "cli_args.h"
#include "../decode/test_archive.h"
#include "../decode/print_archive.h"
#include "../platform/tty.h"

static void print_usage(const char *prog)
{
	printf("Raze Beta-prep CLI (RAR5 extractor)\n");
	printf("Usage: %s <command> [switches] <archive> [masks...] [outdir]\n",
	       prog);
	printf("       %s --help\n", prog);
	printf("\n");
	printf("Commands:\n");
	printf("  x   extract with paths\n");
	printf("  e   extract without archived paths\n");
	printf("  l   list archive contents\n");
	printf("  lt  technical list\n");
	printf("  t   test archive integrity\n");
	printf("  p   print matched files to stdout\n");
	printf("\n");
	printf("Supported switches (subset):\n");
	printf("  -op<path> / -op <path>  output path (x/e)\n");
	printf("  -o+, -o-, -y            overwrite mode\n");
	printf("  -ep                     exclude archived paths (x/e)\n");
	printf("  -ad1, -ad2              destination variants (x/e)\n");
	printf("  -r                      recurse masks\n");
	printf("  -n<mask>, -x<mask>      include/exclude mask\n");
	printf("  -n@<list>/-n@ <list>    include masks from file\n");
	printf("  -x@<list>/-x@ <list>    exclude masks from file\n");
	printf("  -ap<path>               internal archive prefix filter\n");
	printf("  -p[password]            password (-p prompts on tty)\n");
	printf("  -cfg-                   compatibility no-op\n");
	printf("  -idq, -idp, -idn, -inul, -ierr\n");
	printf("  -                       stop switch parsing\n");
}

static int status_to_exit_code(RazeStatus status)
{
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

static int prompt_password(char *buf, size_t buf_size)
{
	size_t len;

	if (buf == 0 || buf_size < 2U) {
		return 0;
	}
	if (!raze_platform_stdin_is_tty()) {
		return 0;
	}

	fprintf(stderr, "Enter password: ");
	fflush(stderr);
	if (fgets(buf, (int)buf_size, stdin) == 0) {
		return 0;
	}

	len = strlen(buf);
	while (len > 0U && (buf[len - 1U] == '\n' || buf[len - 1U] == '\r')) {
		buf[len - 1U] = '\0';
		len--;
	}
	return len > 0U;
}

int main(int argc, char **argv)
{
	RazeDecoder decoder;
	RazeCliArgs cli;
	RazeExtractOptions options;
	RazeStatus status;
	char errbuf[256];
	char password_buf[1024];
	const char *detail;

	if (argc == 2 && strcmp(argv[1], "--help") == 0) {
		print_usage(argv[0]);
		return 0;
	}

	if (argc < 2) {
		print_usage(argv[0]);
		return 2;
	}

	raze_cli_args_init(&cli);
	status = raze_cli_parse_args(argc, argv, &cli, errbuf, sizeof(errbuf));
	if (status != RAZE_STATUS_OK) {
		fprintf(stderr, "raze: %s\n", errbuf[0] != '\0' ? errbuf :
			"usage error");
		raze_cli_args_free(&cli);
		return 2;
	}

	options = raze_extract_options_default();
	options.overwrite_mode = cli.sw.overwrite_mode;
	options.quiet = cli.sw.quiet;
	options.strip_paths = cli.sw.strip_paths;
	options.ad_mode = cli.sw.ad_mode;
	options.recurse = cli.sw.recurse;
	options.ap_prefix = cli.sw.ap_prefix;
	options.include_masks = (const char *const *)cli.sw.includes.items;
	options.include_mask_count = cli.sw.includes.count;
	options.exclude_masks = (const char *const *)cli.sw.excludes.items;
	options.exclude_mask_count = cli.sw.excludes.count;

	if (cli.sw.password != 0 && cli.sw.password[0] != '\0') {
		options.password = cli.sw.password;
		options.password_present = 1;
	} else if (cli.sw.password != 0 && cli.sw.password[0] == '\0') {
		if (prompt_password(password_buf, sizeof(password_buf))) {
			options.password = password_buf;
			options.password_present = 1;
		}
	}

	status = raze_decoder_init(&decoder);
	if (status != RAZE_STATUS_OK) {
		detail = raze_last_error_detail();
		if (detail != 0 && detail[0] != '\0') {
			fprintf(stderr, "raze: %s: %s\n", raze_status_string(status),
				detail);
		} else {
			fprintf(stderr, "raze: decoder initialization failed\n");
		}
		raze_cli_args_free(&cli);
		return status_to_exit_code(status);
	}

	switch (cli.command) {
	case RAZE_CLI_CMD_X:
	case RAZE_CLI_CMD_E:
		if (cli.command == RAZE_CLI_CMD_E) {
			options.strip_paths = 1;
		}
		status = raze_decode_archive_with_options(
			&decoder,
			cli.archive_path,
			cli.sw.output_dir != 0 ? cli.sw.output_dir : ".",
			&options
		);
		break;
	case RAZE_CLI_CMD_T:
		options.test_only = 1;
		status = raze_test_archive(cli.archive_path, &options);
		break;
	case RAZE_CLI_CMD_P:
		options.print_stdout = 1;
		status = raze_print_archive(cli.archive_path, &options);
		break;
	case RAZE_CLI_CMD_L:
		status = raze_list_archive_with_options(&decoder, cli.archive_path,
						       0, &options);
		break;
	case RAZE_CLI_CMD_LT:
		status = raze_list_archive_with_options(&decoder, cli.archive_path,
						       1, &options);
		break;
	default:
		status = RAZE_STATUS_BAD_ARGUMENT;
		break;
	}

	if (status != RAZE_STATUS_OK) {
		detail = raze_last_error_detail();
		if (!options.quiet) {
			if (detail != 0 && detail[0] != '\0') {
				fprintf(stderr, "raze: %s: %s\n",
					raze_status_string(status), detail);
			} else {
				fprintf(stderr, "raze: %s\n",
					raze_status_string(status));
			}
		}
		raze_cli_args_free(&cli);
		return status_to_exit_code(status);
	}

	raze_cli_args_free(&cli);
	return 0;
}
