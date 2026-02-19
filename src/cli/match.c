#include "match.h"

#include <string.h>

static const char *basename_ptr(const char *s)
{
	const char *last;

	if (s == 0) {
		return "";
	}
	last = s;
	while (*s != '\0') {
		if (*s == '/' || *s == '\\') {
			last = s + 1;
		}
		s++;
	}
	return last;
}

static void normalize(const char *in, char *out, size_t out_size)
{
	size_t i;

	if (out == 0 || out_size == 0U) {
		return;
	}
	if (in == 0) {
		out[0] = '\0';
		return;
	}

	for (i = 0; i + 1U < out_size && in[i] != '\0'; ++i) {
		char c;

		c = in[i];
		if (c == '\\') {
			c = '/';
		}
		out[i] = c;
	}
	out[i] = '\0';
}

static int has_path_sep(const char *s)
{
	if (s == 0) {
		return 0;
	}
	return strchr(s, '/') != 0 || strchr(s, '\\') != 0;
}

static int prefix_ok(const char *entry, const char *prefix)
{
	size_t n;

	if (prefix == 0 || prefix[0] == '\0') {
		return 1;
	}
	n = strlen(prefix);
	if (strncmp(entry, prefix, n) != 0) {
		return 0;
	}
	return entry[n] == '\0' || entry[n] == '/';
}

static int wildcard_match(const char *pattern, const char *text)
{
	const char *pat;
	const char *str;
	const char *star;
	const char *retry;

	if (pattern == 0 || text == 0) {
		return 0;
	}

	pat = pattern;
	str = text;
	star = 0;
	retry = 0;

	while (*str != '\0') {
		if (*pat == '*') {
			star = pat++;
			retry = str;
			continue;
		}
		if (*pat == '?' || *pat == *str) {
			pat++;
			str++;
			continue;
		}
		if (star != 0) {
			pat = star + 1;
			str = ++retry;
			continue;
		}
		return 0;
	}

	while (*pat == '*') {
		pat++;
	}
	return *pat == '\0';
}

static int match_any(
	const char *entry,
	const char *basename,
	int recurse,
	const char *const *patterns,
	size_t count
)
{
	size_t i;

	for (i = 0; i < count; ++i) {
		const char *pat;
		const char *target;

		pat = patterns[i];
		if (pat == 0 || pat[0] == '\0') {
			continue;
		}
		target = (!recurse && !has_path_sep(pat)) ? basename : entry;
		if (wildcard_match(pat, target)) {
			return 1;
		}
	}
	return 0;
}

int raze_match_entry_path(const char *entry_name, const RazeMatchRules *rules)
{
	char entry_norm[4096];
	char prefix_norm[4096];
	const char *base;
	int recurse;

	if (entry_name == 0) {
		return 0;
	}

	normalize(entry_name, entry_norm, sizeof(entry_norm));
	base = basename_ptr(entry_norm);
	recurse = rules != 0 ? rules->recurse : 0;

	if (rules != 0 && rules->ap_prefix != 0 && rules->ap_prefix[0] != '\0') {
		normalize(rules->ap_prefix, prefix_norm, sizeof(prefix_norm));
		if (!prefix_ok(entry_norm, prefix_norm)) {
			return 0;
		}
	}

	if (rules != 0 && rules->include_count > 0U) {
		if (!match_any(entry_norm, base, recurse,
			      rules->includes, rules->include_count)) {
			return 0;
		}
	}

	if (rules != 0 && rules->exclude_count > 0U) {
		if (match_any(entry_norm, base, recurse,
		      rules->excludes, rules->exclude_count)) {
			return 0;
		}
	}

	return 1;
}
