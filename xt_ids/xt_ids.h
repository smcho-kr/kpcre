/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KPCRE_XT_IDS_H
#define KPCRE_XT_IDS_H

#include <linux/types.h>

#define IDS_PATTERN_SIZE 256

struct xt_ids_info {
	char regex[IDS_PATTERN_SIZE];
	__aligned_u64 state;
};

#endif
