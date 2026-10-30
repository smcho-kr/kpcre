/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NFT_REGEX_H
#define NFT_REGEX_H

enum nft_regex_attributes {
	NFTA_REGEX_UNSPEC,
	NFTA_REGEX_PATTERN,
	__NFTA_REGEX_MAX,
};
#define NFTA_REGEX_MAX (__NFTA_REGEX_MAX - 1)
#define NFT_REGEX_PATTERN_MAX 255
#define NFT_REGEX_PAYLOAD_MAX 16384
#define NFT_REGEX_WORK_MAX 10000

#endif
