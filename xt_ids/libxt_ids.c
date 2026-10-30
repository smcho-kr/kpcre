// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <xtables.h>
#include "xt_ids.h"

static void ids_help(void)
{
	printf("ids match options:\n"
	       "  --regex pattern   PCRE2 byte pattern (1-255 bytes, no / delimiters)\n"
	       "Inspects adjacent TCP payloads; module parameter window_packets defaults to 2.\n");
}

static const struct xt_option_entry ids_options[] = {
	{ .name = "regex", .id = 0, .type = XTTYPE_STRING,
	  .flags = XTOPT_MAND | XTOPT_PUT,
	  XTOPT_POINTER(struct xt_ids_info, regex), .min = 1, .max = IDS_PATTERN_SIZE - 1 },
	XTOPT_TABLEEND,
};

static void ids_print(const void *ip, const struct xt_entry_match *match,
		      int numeric)
{
	const struct xt_ids_info *info = (const void *)match->data;
	(void)ip;
	(void)numeric;
	printf(" ids regex");
	xtables_save_string(info->regex);
}

static void ids_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_ids_info *info = (const void *)match->data;
	(void)ip;
	printf(" --regex");
	xtables_save_string(info->regex);
}

static struct xtables_match ids_match = {
	.name = "ids",
	.version = XTABLES_VERSION,
	.family = NFPROTO_UNSPEC,
	.size = XT_ALIGN(sizeof(struct xt_ids_info)),
	.userspacesize = offsetof(struct xt_ids_info, state),
	.help = ids_help,
	.print = ids_print,
	.save = ids_save,
	.x6_parse = xtables_option_parse,
	.x6_options = ids_options,
};

void _init(void)
{
	xtables_register_match(&ids_match);
}
