/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause) */
/*
 * canplayer.c - replay a compact CAN frame logfile to CAN devices
 *
 * Copyright (c) 2002-2007 Volkswagen Group Electronic Research
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Volkswagen nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
 *
 * The provided data structures and external interfaces from this code
 * are not restricted to be used by modules with a GPL compatible license.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * Send feedback to <linux-can@vger.kernel.org>
 *
 */

//! Inizio mio codice
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <linux/can.h>
#include <linux/can/raw.h>

#include <sys/time.h>   /* gettimeofday, timeval (for timestamp in microsecond) */

#define NAME_FILE "test.txt"
#define NAME_SOCKET "vcan0"

#define NANO_SECOND_MULTIPLIER  1000  // 1 microsecond = 1000 Nanoseconds
#define MICROSECONDS_TO_SYNCHRONIZE 1000000
#define MICROSECONDS_OF_MARGIN 2

#define STABILIZE 0
#define NUM_FRAMES_STABILIZE 10


void hexToASCII(char * hex, char *output);
void StringToHex(char *string, char * hex);
void printFrames(struct can_frame * frames,double * delta,int numFrame);
void printDelta(long long int * delta,int numFrame, char *output);
int  countFrames();
void readFrames(struct can_frame *frames, long long int * delta, int numFrame );
void sendEmptyFrame(int s,int numFrame);

long long int getMicroseconds();
//!Fine mio codice

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <libgen.h>

#include <unistd.h>

#include <linux/can.h>
#include <linux/can/error.h>
#include <sys/socket.h> /* for sa_family_t */

#include "lib.h"

#include <linux/can/raw.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#define CANID_DELIM '#'
#define CC_DLC_DELIM '_'
#define DATA_SEPERATOR '.'

const char hex_asc_upper[] = "0123456789ABCDEF";

#define hex_asc_upper_lo(x)	hex_asc_upper[((x) & 0x0F)]
#define hex_asc_upper_hi(x)	hex_asc_upper[((x) & 0xF0) >> 4]

static inline void put_hex_byte(char *buf, __u8 byte)
{
	buf[0] = hex_asc_upper_hi(byte);
	buf[1] = hex_asc_upper_lo(byte);
}

static inline void _put_id(char *buf, int end_offset, canid_t id)
{
	/* build 3 (SFF) or 8 (EFF) digit CAN identifier */
	while (end_offset >= 0) {
		buf[end_offset--] = hex_asc_upper_lo(id);
		id >>= 4;
	}
}

#define put_sff_id(buf, id) _put_id(buf, 2, id)
#define put_eff_id(buf, id) _put_id(buf, 7, id)

/* CAN DLC to real data length conversion helpers */

static const unsigned char dlc2len[] = {0, 1, 2, 3, 4, 5, 6, 7,
					8, 12, 16, 20, 24, 32, 48, 64};

/* get data length from raw data length code (DLC) */
unsigned char can_fd_dlc2len(unsigned char dlc)
{
	return dlc2len[dlc & 0x0F];
}

static const unsigned char len2dlc[] = {0, 1, 2, 3, 4, 5, 6, 7, 8,		/* 0 - 8 */
					9, 9, 9, 9,				/* 9 - 12 */
					10, 10, 10, 10,				/* 13 - 16 */
					11, 11, 11, 11,				/* 17 - 20 */
					12, 12, 12, 12,				/* 21 - 24 */
					13, 13, 13, 13, 13, 13, 13, 13,		/* 25 - 32 */
					14, 14, 14, 14, 14, 14, 14, 14,		/* 33 - 40 */
					14, 14, 14, 14, 14, 14, 14, 14,		/* 41 - 48 */
					15, 15, 15, 15, 15, 15, 15, 15,		/* 49 - 56 */
					15, 15, 15, 15, 15, 15, 15, 15};	/* 57 - 64 */

/* map the sanitized data length to an appropriate data length code */
unsigned char can_fd_len2dlc(unsigned char len)
{
	if (len > 64)
		return 0xF;

	return len2dlc[len];
}

unsigned char asc2nibble(char c) {

	if ((c >= '0') && (c <= '9'))
		return c - '0';

	if ((c >= 'A') && (c <= 'F'))
		return c - 'A' + 10;

	if ((c >= 'a') && (c <= 'f'))
		return c - 'a' + 10;

	return 16; /* error */
}

int hexstring2data(char *arg, unsigned char *data, int maxdlen) {

	int len = strlen(arg);
	int i;
	unsigned char tmp;

	if (!len || len%2 || len > maxdlen*2)
		return 1;

	memset(data, 0, maxdlen);

	for (i=0; i < len/2; i++) {

		tmp = asc2nibble(*(arg+(2*i)));
		if (tmp > 0x0F)
			return 1;

		data[i] = (tmp << 4);

		tmp = asc2nibble(*(arg+(2*i)+1));
		if (tmp > 0x0F)
			return 1;

		data[i] |= tmp;
	}

	return 0;
}

int parse_canframe(char *cs, struct canfd_frame *cf) {
	/* documentation see lib.h */

	int i, idx, dlen, len;
	int maxdlen = CAN_MAX_DLEN;
	int ret = CAN_MTU;
	canid_t tmp;

	len = strlen(cs);
	//printf("'%s' len %d\n", cs, len);

	memset(cf, 0, sizeof(*cf)); /* init CAN FD frame, e.g. LEN = 0 */

	if (len < 4)
		return 0;

	if (cs[3] == CANID_DELIM) { /* 3 digits */

		idx = 4;
		for (i=0; i<3; i++){
			if ((tmp = asc2nibble(cs[i])) > 0x0F)
				return 0;
			cf->can_id |= (tmp << (2-i)*4);
		}

	} else if (cs[8] == CANID_DELIM) { /* 8 digits */

		idx = 9;
		for (i=0; i<8; i++){
			if ((tmp = asc2nibble(cs[i])) > 0x0F)
				return 0;
			cf->can_id |= (tmp << (7-i)*4);
		}
		if (!(cf->can_id & CAN_ERR_FLAG)) /* 8 digits but no errorframe?  */
			cf->can_id |= CAN_EFF_FLAG;   /* then it is an extended frame */

	} else
		return 0;

	if((cs[idx] == 'R') || (cs[idx] == 'r')){ /* RTR frame */
		cf->can_id |= CAN_RTR_FLAG;

		/* check for optional DLC value for CAN 2.0B frames */
		if(cs[++idx] && (tmp = asc2nibble(cs[idx++])) <= CAN_MAX_DLEN) {
			cf->len = tmp;

			/* check for optional raw DLC value for CAN 2.0B frames */
			if ((tmp == CAN_MAX_DLEN) && (cs[idx++] == CC_DLC_DELIM)) {
				tmp = asc2nibble(cs[idx]);
				if ((tmp > CAN_MAX_DLEN) && (tmp <= CAN_MAX_DLC)) {
					struct can_frame *ccf = (struct can_frame *)cf;

					ccf->can_dlc = tmp;
				}
			}
		}
		return ret;
	}

	if (cs[idx] == CANID_DELIM) { /* CAN FD frame escape char '##' */

		maxdlen = CANFD_MAX_DLEN;
		ret = CANFD_MTU;

		/* CAN FD frame <canid>##<flags><data>* */
		if ((tmp = asc2nibble(cs[idx+1])) > 0x0F)
			return 0;

		cf->flags = tmp;
		idx += 2;
	}

	for (i=0, dlen=0; i < maxdlen; i++){

		if(cs[idx] == DATA_SEPERATOR) /* skip (optional) separator */
			idx++;

		if(idx >= len) /* end of string => end of data */
			break;

		if ((tmp = asc2nibble(cs[idx++])) > 0x0F)
			return 0;
		cf->data[i] = (tmp << 4);
		if ((tmp = asc2nibble(cs[idx++])) > 0x0F)
			return 0;
		cf->data[i] |= tmp;
		dlen++;
	}
	cf->len = dlen;

	/* check for extra DLC when having a Classic CAN with 8 bytes payload */
	if ((maxdlen == CAN_MAX_DLEN) && (dlen == CAN_MAX_DLEN) && (cs[idx++] == CC_DLC_DELIM)) {
		unsigned char dlc = asc2nibble(cs[idx]);

		if ((dlc > CAN_MAX_DLEN) && (dlc <= CAN_MAX_DLC)) {
			struct can_frame *ccf = (struct can_frame *)cf;

			ccf->can_dlc = dlc;
		}
	}

	return ret;
}

void fprint_canframe(FILE *stream , struct canfd_frame *cf, char *eol, int sep, int maxdlen) {
	/* documentation see lib.h */

	char buf[CL_CFSZ]; /* max length */

	sprint_canframe(buf, cf, sep, maxdlen);
	fprintf(stream, "%s", buf);
	if (eol)
		fprintf(stream, "%s", eol);
}

void sprint_canframe(char *buf , struct canfd_frame *cf, int sep, int maxdlen) {
	/* documentation see lib.h */

	int i,offset;
	int len = (cf->len > maxdlen) ? maxdlen : cf->len;

	if (cf->can_id & CAN_ERR_FLAG) {
		put_eff_id(buf, cf->can_id & (CAN_ERR_MASK|CAN_ERR_FLAG));
		buf[8] = '#';
		offset = 9;
	} else if (cf->can_id & CAN_EFF_FLAG) {
		put_eff_id(buf, cf->can_id & CAN_EFF_MASK);
		buf[8] = '#';
		offset = 9;
	} else {
		put_sff_id(buf, cf->can_id & CAN_SFF_MASK);
		buf[3] = '#';
		offset = 4;
	}

	/* standard CAN frames may have RTR enabled. There are no ERR frames with RTR */
	if (maxdlen == CAN_MAX_DLEN && cf->can_id & CAN_RTR_FLAG) {
		buf[offset++] = 'R';
		/* print a given CAN 2.0B DLC if it's not zero */
		if (cf->len && cf->len <= CAN_MAX_DLEN) {
			buf[offset++] = hex_asc_upper_lo(cf->len);

			/* check for optional raw DLC value for CAN 2.0B frames */
			if (cf->len == CAN_MAX_DLEN) {
				struct can_frame *ccf = (struct can_frame *)cf;

				if ((ccf->can_dlc > CAN_MAX_DLEN) && (ccf->can_dlc <= CAN_MAX_DLC)) {
					buf[offset++] = CC_DLC_DELIM;
					buf[offset++] = hex_asc_upper_lo(ccf->can_dlc);
				}
			}
		}

		buf[offset] = 0;
		return;
	}

	if (maxdlen == CANFD_MAX_DLEN) {
		/* add CAN FD specific escape char and flags */
		buf[offset++] = '#';
		buf[offset++] = hex_asc_upper_lo(cf->flags);
		if (sep && len)
			buf[offset++] = '.';
	}

	for (i = 0; i < len; i++) {
		put_hex_byte(buf + offset, cf->data[i]);
		offset += 2;
		if (sep && (i+1 < len))
			buf[offset++] = '.';
	}

	/* check for extra DLC when having a Classic CAN with 8 bytes payload */
	if ((maxdlen == CAN_MAX_DLEN) && (len == CAN_MAX_DLEN)) {
		struct can_frame *ccf = (struct can_frame *)cf;
		unsigned char dlc = ccf->can_dlc;

		if ((dlc > CAN_MAX_DLEN) && (dlc <= CAN_MAX_DLC)) {
			buf[offset++] = CC_DLC_DELIM;
			buf[offset++] = hex_asc_upper_lo(dlc);
		}
	}

	buf[offset] = 0;
}

void fprint_long_canframe(FILE *stream , struct canfd_frame *cf, char *eol, int view, int maxdlen) {
	/* documentation see lib.h */

	char buf[CL_LONGCFSZ];

	sprint_long_canframe(buf, cf, view, maxdlen);
	fprintf(stream, "%s", buf);
	if ((view & CANLIB_VIEW_ERROR) && (cf->can_id & CAN_ERR_FLAG)) {
		snprintf_can_error_frame(buf, sizeof(buf), cf, "\n\t");
		fprintf(stream, "\n\t%s", buf);
	}
	if (eol)
		fprintf(stream, "%s", eol);
}

void sprint_long_canframe(char *buf , struct canfd_frame *cf, int view, int maxdlen) {
	/* documentation see lib.h */

	int i, j, dlen, offset;
	int len = (cf->len > maxdlen)? maxdlen : cf->len;

	/* initialize space for CAN-ID and length information */
	memset(buf, ' ', 15);

	if (cf->can_id & CAN_ERR_FLAG) {
		put_eff_id(buf, cf->can_id & (CAN_ERR_MASK|CAN_ERR_FLAG));
		offset = 10;
	} else if (cf->can_id & CAN_EFF_FLAG) {
		put_eff_id(buf, cf->can_id & CAN_EFF_MASK);
		offset = 10;
	} else {
		if (view & CANLIB_VIEW_INDENT_SFF) {
			put_sff_id(buf + 5, cf->can_id & CAN_SFF_MASK);
			offset = 10;
		} else {
			put_sff_id(buf, cf->can_id & CAN_SFF_MASK);
			offset = 5;
		}
	}

	/* The len value is sanitized by maxdlen (see above) */
	if (maxdlen == CAN_MAX_DLEN) {
		if (view & CANLIB_VIEW_LEN8_DLC) {
			struct can_frame *ccf = (struct can_frame *)cf;
			unsigned char dlc = ccf->can_dlc;

			/* fall back to len if we don't have a valid DLC > 8 */
			if (!((len == CAN_MAX_DLEN) && (dlc > CAN_MAX_DLEN) &&
			      (dlc <= CAN_MAX_DLC)))
				dlc = len;

			buf[offset + 1] = '{';
			buf[offset + 2] = hex_asc_upper[dlc];
			buf[offset + 3] = '}';
		} else {
			buf[offset + 1] = '[';
			buf[offset + 2] = len + '0';
			buf[offset + 3] = ']';
		}

		/* standard CAN frames may have RTR enabled */
		if (cf->can_id & CAN_RTR_FLAG) {
			sprintf(buf+offset+5, " remote request");
			return;
		}
	} else {
		buf[offset] = '[';
		buf[offset + 1] = (len/10) + '0';
		buf[offset + 2] = (len%10) + '0';
		buf[offset + 3] = ']';
	}
	offset += 5;

	if (view & CANLIB_VIEW_BINARY) {
		dlen = 9; /* _10101010 */
		if (view & CANLIB_VIEW_SWAP) {
			for (i = len - 1; i >= 0; i--) {
				buf[offset++] = (i == len-1)?' ':SWAP_DELIMITER;
				for (j = 7; j >= 0; j--)
					buf[offset++] = (1<<j & cf->data[i])?'1':'0';
			}
		} else {
			for (i = 0; i < len; i++) {
				buf[offset++] = ' ';
				for (j = 7; j >= 0; j--)
					buf[offset++] = (1<<j & cf->data[i])?'1':'0';
			}
		}
	} else {
		dlen = 3; /* _AA */
		if (view & CANLIB_VIEW_SWAP) {
			for (i = len - 1; i >= 0; i--) {
				if (i == len-1)
					buf[offset++] = ' ';
				else
					buf[offset++] = SWAP_DELIMITER;

				put_hex_byte(buf + offset, cf->data[i]);
				offset += 2;
			}
		} else {
			for (i = 0; i < len; i++) {
				buf[offset++] = ' ';
				put_hex_byte(buf + offset, cf->data[i]);
				offset += 2;
			}
		}
	}

	buf[offset] = 0; /* terminate string */

	/*
	 * The ASCII & ERRORFRAME output is put at a fixed len behind the data.
	 * For now we support ASCII output only for payload length up to 8 bytes.
	 * Does it make sense to write 64 ASCII byte behind 64 ASCII HEX data on the console?
	 */
	if (len > CAN_MAX_DLEN)
		return;

	if (cf->can_id & CAN_ERR_FLAG)
		sprintf(buf+offset, "%*s", dlen*(8-len)+13, "ERRORFRAME");
	else if (view & CANLIB_VIEW_ASCII) {
		j = dlen*(8-len)+4;
		if (view & CANLIB_VIEW_SWAP) {
			sprintf(buf+offset, "%*s", j, "`");
			offset += j;
			for (i = len - 1; i >= 0; i--)
				if ((cf->data[i] > 0x1F) && (cf->data[i] < 0x7F))
					buf[offset++] = cf->data[i];
				else
					buf[offset++] = '.';

			sprintf(buf+offset, "`");
		} else {
			sprintf(buf+offset, "%*s", j, "'");
			offset += j;
			for (i = 0; i < len; i++)
				if ((cf->data[i] > 0x1F) && (cf->data[i] < 0x7F))
					buf[offset++] = cf->data[i];
				else
					buf[offset++] = '.';

			sprintf(buf+offset, "'");
		}
	}
}

static const char *error_classes[] = {
	"tx-timeout",
	"lost-arbitration",
	"controller-problem",
	"protocol-violation",
	"transceiver-status",
	"no-acknowledgement-on-tx",
	"bus-off",
	"bus-error",
	"restarted-after-bus-off",
};

static const char *controller_problems[] = {
	"rx-overflow",
	"tx-overflow",
	"rx-error-warning",
	"tx-error-warning",
	"rx-error-passive",
	"tx-error-passive",
	"back-to-error-active",
};

static const char *protocol_violation_types[] = {
	"single-bit-error",
	"frame-format-error",
	"bit-stuffing-error",
	"tx-dominant-bit-error",
	"tx-recessive-bit-error",
	"bus-overload",
	"active-error",
	"error-on-tx",
};

static const char *protocol_violation_locations[] = {
	"unspecified",
	"unspecified",
	"id.28-to-id.21",
	"start-of-frame",
	"bit-srtr",
	"bit-ide",
	"id.20-to-id.18",
	"id.17-to-id.13",
	"crc-sequence",
	"reserved-bit-0",
	"data-field",
	"data-length-code",
	"bit-rtr",
	"reserved-bit-1",
	"id.4-to-id.0",
	"id.12-to-id.5",
	"unspecified",
	"active-error-flag",
	"intermission",
	"tolerate-dominant-bits",
	"unspecified",
	"unspecified",
	"passive-error-flag",
	"error-delimiter",
	"crc-delimiter",
	"acknowledge-slot",
	"end-of-frame",
	"acknowledge-delimiter",
	"overload-flag",
	"unspecified",
	"unspecified",
	"unspecified",
};

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

static int snprintf_error_data(char *buf, size_t len, uint8_t err,
			       const char **arr, int arr_len)
{
	int i, n = 0, count = 0;

	if (!err || len <= 0)
		return 0;

	for (i = 0; i < arr_len; i++) {
		if (err & (1 << i)) {
			int tmp_n = 0;
			if (count){
				/* Fix for potential buffer overflow https://lgtm.com/rules/1505913226124/ */
				tmp_n = snprintf(buf + n, len - n, ",");
				if (tmp_n < 0 || (size_t)tmp_n >= len - n){
					return n;
				}
				n += tmp_n;
			}
			tmp_n = snprintf(buf + n, len - n, "%s", arr[i]);
			if (tmp_n < 0 || (size_t)tmp_n >= len - n){
				return n;
			}
			n += tmp_n;
			count++;
		}
	}

	return n;
}

static int snprintf_error_lostarb(char *buf, size_t len, const struct canfd_frame *cf)
{
	if (len <= 0)
		return 0;
	return snprintf(buf, len, "{at bit %d}", cf->data[0]);
}

static int snprintf_error_ctrl(char *buf, size_t len, const struct canfd_frame *cf)
{
	int n = 0;

	if (len <= 0)
		return 0;

	n += snprintf(buf + n, len - n, "{");
	n += snprintf_error_data(buf + n, len - n, cf->data[1],
				controller_problems,
				ARRAY_SIZE(controller_problems));
	n += snprintf(buf + n, len - n, "}");

	return n;
}

static int snprintf_error_prot(char *buf, size_t len, const struct canfd_frame *cf)
{
	int n = 0;

	if (len <= 0)
		return 0;

	n += snprintf(buf + n, len - n, "{{");
	n += snprintf_error_data(buf + n, len - n, cf->data[2],
				protocol_violation_types,
				ARRAY_SIZE(protocol_violation_types));
	n += snprintf(buf + n, len - n, "}{");
	if (cf->data[3] > 0 &&
	    cf->data[3] < ARRAY_SIZE(protocol_violation_locations))
		n += snprintf(buf + n, len - n, "%s",
			      protocol_violation_locations[cf->data[3]]);
	n += snprintf(buf + n, len - n, "}}");

	return n;
}

void snprintf_can_error_frame(char *buf, size_t len, const struct canfd_frame *cf,
                  const char* sep)
{
	canid_t class, mask;
	int i, n = 0, classes = 0;
	char *defsep = ",";

	if (!(cf->can_id & CAN_ERR_FLAG))
		return;

	class = cf->can_id & CAN_EFF_MASK;
	if (class > (1 << ARRAY_SIZE(error_classes))) {
		fprintf(stderr, "Error class %#x is invalid\n", class);
		return;
	}

	if (!sep)
		sep = defsep;

	for (i = 0; i < (int)ARRAY_SIZE(error_classes); i++) {
		mask = 1 << i;
		if (class & mask) {
			int tmp_n = 0;
			if (classes){
				/* Fix for potential buffer overflow https://lgtm.com/rules/1505913226124/ */
				tmp_n = snprintf(buf + n, len - n, "%s", sep);
				if (tmp_n < 0 || (size_t)tmp_n >= len - n){
					return;
				}
				n += tmp_n;
			}
			tmp_n = snprintf(buf + n, len - n, "%s", error_classes[i]);
			if (tmp_n < 0 || (size_t)tmp_n >= len - n){
				return;
			}
			n += tmp_n;
			if (mask == CAN_ERR_LOSTARB)
				n += snprintf_error_lostarb(buf + n, len - n,
							   cf);
			if (mask == CAN_ERR_CRTL)
				n += snprintf_error_ctrl(buf + n, len - n, cf);
			if (mask == CAN_ERR_PROT)
				n += snprintf_error_prot(buf + n, len - n, cf);
			classes++;
		}
	}

	if (cf->data[6] || cf->data[7]) {
		n += snprintf(buf + n, len - n, "%s", sep);
		n += snprintf(buf + n, len - n, "error-counter-tx-rx{{%d}{%d}}",
			      cf->data[6], cf->data[7]);
	}
}


#define DEFAULT_GAP	1	/* ms */
#define DEFAULT_LOOPS	1	/* only one replay */
#define CHANNELS	20	/* anyone using more than 20 CAN interfaces at a time? */
#define COMMENTSZ 200
#define BUFSZ (sizeof("(1345212884.318850)") + IFNAMSIZ + 4 + CL_CFSZ + COMMENTSZ) /* for one line in the logfile */
#define STDOUTIDX	65536	/* interface index for printing on stdout - bigger than max uint16 */

struct assignment {
	char txif[IFNAMSIZ];
	int  txifidx;
	char rxif[IFNAMSIZ];
};
static struct assignment asgn[CHANNELS];
const int canfd_on = 1;

extern int optind, opterr, optopt;

void print_usage(char *prg)
{
	fprintf(stderr, "%s - replay a compact CAN frame logfile to CAN devices.\n", prg);
	fprintf(stderr, "\nUsage: %s <options> [interface assignment]*\n\n", prg);
        fprintf(stderr, "Options:\n");
        fprintf(stderr, "         -I <infile>  (default stdin)\n");
        fprintf(stderr, "         -l <num>     "
                "(process input file <num> times)\n"
                "                      "
                "(Use 'i' for infinite loop - default: %d)\n", DEFAULT_LOOPS);
        fprintf(stderr, "         -t           (ignore timestamps: "
                "send frames immediately)\n");
        fprintf(stderr, "         -i           (interactive - wait "
                "for ENTER key to process next frame)\n");
	fprintf(stderr, "         -n <count>   (terminate after "
		"processing <count> CAN frames)\n");
        fprintf(stderr, "         -g <ms>      (gap in milli "
                "seconds - default: %d ms)\n", DEFAULT_GAP);
        fprintf(stderr, "         -s <s>       (skip gaps in "
                "timestamps > 's' seconds)\n");
        fprintf(stderr, "         -x           (disable local "
                "loopback of sent CAN frames)\n");
        fprintf(stderr, "         -v           (verbose: print "
                "sent CAN frames)\n\n");
		fprintf(stderr, "         -r           (real-time: process frames in real-time mode (using timestamps)\n\n");
		
        fprintf(stderr, "Interface assignment:\n");
	fprintf(stderr, " 0..n assignments like <write-if>=<log-if>\n\n");
	fprintf(stderr, " e.g. vcan2=can0  (send frames received from can0 on "
		"vcan2)\n");
	fprintf(stderr, " extra hook: stdout=can0  (print logfile line marked with can0 on "
		"stdout)\n");
	fprintf(stderr, " No assignments  => send frames to the interface(s) they "
		"had been received from\n\n");
	fprintf(stderr, "Lines in the logfile not beginning with '(' (start of "
		"timestamp) are ignored.\n\n");
}

/* copied from /usr/src/linux/include/linux/time.h ...
 * lhs < rhs:  return <0
 * lhs == rhs: return 0
 * lhs > rhs:  return >0
 */
static inline int timeval_compare(struct timeval *lhs, struct timeval *rhs)
{
	if (lhs->tv_sec < rhs->tv_sec)
		return -1;
	if (lhs->tv_sec > rhs->tv_sec)
		return 1;
	return lhs->tv_usec - rhs->tv_usec;
}

static inline void create_diff_tv(struct timeval *today, struct timeval *diff,
				  struct timeval *log) {

	/* create diff_tv so that log_tv + diff_tv = today_tv */
	diff->tv_sec  = today->tv_sec  - log->tv_sec;
	diff->tv_usec = today->tv_usec - log->tv_usec;
}

static inline int frames_to_send(struct timeval *today, struct timeval *diff,
				 struct timeval *log)
{
	/* return value <0 when log + diff < today */

	struct timeval cmp;

	cmp.tv_sec  = log->tv_sec  + diff->tv_sec;
	cmp.tv_usec = log->tv_usec + diff->tv_usec;

	if (cmp.tv_usec >= 1000000) {
		cmp.tv_usec -= 1000000;
		cmp.tv_sec++;
	}

	if (cmp.tv_usec < 0) {
		cmp.tv_usec += 1000000;
		cmp.tv_sec--;
	}

	return timeval_compare(&cmp, today);
}

int get_txidx(char *logif_name) {

	int i;

	for (i=0; i<CHANNELS; i++) {
		if (asgn[i].rxif[0] == 0) /* end of table content */
			break;
		if (strcmp(asgn[i].rxif, logif_name) == 0) /* found device name */
			break;
	}

	if ((i == CHANNELS) || (asgn[i].rxif[0] == 0))
		return 0; /* not found */

	return asgn[i].txifidx; /* return interface index */
}

char *get_txname(char *logif_name) {

	int i;

	for (i=0; i<CHANNELS; i++) {
		if (asgn[i].rxif[0] == 0) /* end of table content */
			break;
		if (strcmp(asgn[i].rxif, logif_name) == 0) /* found device name */
			break;
	}

	if ((i == CHANNELS) || (asgn[i].rxif[0] == 0))
		return 0; /* not found */

	return asgn[i].txif; /* return interface name */
}

int add_assignment(char *mode, int socket, char *txname, char *rxname,
		   int verbose) {

	struct ifreq ifr;
	int i;

	/* find free entry */
	for (i=0; i<CHANNELS; i++) {
		if (asgn[i].txif[0] == 0)
			break;
	}

	if (i == CHANNELS) {
		fprintf(stderr, "Assignment table exceeded!\n");
		return 1;
	}

	if (strlen(txname) >= IFNAMSIZ) {
		fprintf(stderr, "write-if interface name '%s' too long!", txname);
		return 1;
	}
	strcpy(asgn[i].txif, txname);

	if (strlen(rxname) >= IFNAMSIZ) {
		fprintf(stderr, "log-if interface name '%s' too long!", rxname);
		return 1;
	}
	strcpy(asgn[i].rxif, rxname);

	if (strcmp(txname, "stdout") != 0) {
		strcpy(ifr.ifr_name, txname);
		if (ioctl(socket, SIOCGIFINDEX, &ifr) < 0) {
			perror("SIOCGIFINDEX");
			fprintf(stderr, "write-if interface name '%s' is wrong!\n", txname);
			return 1;
		}
		asgn[i].txifidx = ifr.ifr_ifindex;
	} else
		asgn[i].txifidx = STDOUTIDX;

	if (verbose > 1) /* use -v -v to see this */
		printf("added %s assignment: log-if=%s write-if=%s write-if-idx=%d\n",
		       mode, asgn[i].rxif, asgn[i].txif, asgn[i].txifidx);

	return 0;
}

int main(int argc, char **argv)
{
	static char buf[BUFSZ], device[BUFSZ], ascframe[BUFSZ];
	struct sockaddr_can addr;
	static struct canfd_frame frame;
	static struct timeval today_tv, log_tv, last_log_tv, diff_tv; 
	struct timespec sleep_ts;
	int s; /* CAN_RAW socket */
	FILE *infile = stdin;
	unsigned long gap = DEFAULT_GAP; 
	int use_timestamps = 1;
	int realtime = 0;
	int interactive = 0; /* wait for ENTER keypress to process next frame */
	int count = 0; /* end replay after sending count frames. 0 = disabled */
	static int verbose, opt, delay_loops;
	static unsigned long skipgap;
	static int loopback_disable = 0;
	static int infinite_loops = 0;
	static int loops = DEFAULT_LOOPS;
	int assignments; /* assignments defined on the commandline */
	int txidx;       /* sendto() interface index */
	int eof, txmtu, i, j;
	char *fret;

	while ((opt = getopt(argc, argv, "I:l:tin:g:s:xvr?")) != -1) {
		switch (opt) {
		case 'I':
			infile = fopen(optarg, "r");
			if (!infile) {
				perror("infile");
				return 1;
			}
			break;

		case 'l':
			if (optarg[0] == 'i')
				infinite_loops = 1;
			else
				if (!(loops = atoi(optarg))) {
					fprintf(stderr, "Invalid argument for option -l !\n");
					return 1;
				}
			break;

		case 't':
			use_timestamps = 0;
			break;

		case 'i':
			interactive = 1;
			break;

		case 'n':
			count = atoi(optarg);
			if (count < 1) {
				print_usage(basename(argv[0]));
				exit(1);
			}
			break;

		case 'g':
			gap = strtoul(optarg, NULL, 10);
			break;

		case 's':
			skipgap = strtoul(optarg, NULL, 10);
			if (skipgap < 1) {
				fprintf(stderr, "Invalid argument for option -s !\n");
				return 1;
			}
			break;

		case 'x':
			loopback_disable = 1;
			break;

		case 'v':
			verbose++;
			break;
		
		case 'r':
			realtime=1;
			break;

		case '?':
		default:
			print_usage(basename(argv[0]));
			return 1;
			break;
		}
	}

	assignments = argc - optind; /* find real number of user assignments */

	if (infile == stdin) { /* no jokes with stdin */
		infinite_loops = 0;
		loops = 1;
	}

	if (verbose > 1) { /* use -v -v to see this */
		if (infinite_loops)
			printf("infinite_loops\n");
		else
			printf("%d loops\n", loops);
	}

	/* ignore timestamps from logfile when in single step keypress mode */
	if (interactive) {
		use_timestamps = 0;
		printf("interactive mode: press ENTER to process next CAN frame ...\n");
	}

	if(realtime){
		use_timestamps = 0;
		interactive = 0;
		printf("REAL-TIME MODE");
	}

	sleep_ts.tv_sec  =  gap / 1000;
	sleep_ts.tv_nsec = (gap % 1000) * 1000000;

	/* open socket */
	if ((s = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
		perror("socket");
		return 1;
	}

	addr.can_family  = AF_CAN;
	addr.can_ifindex = 0;

	/* disable unneeded default receive filter on this RAW socket */
	setsockopt(s, SOL_CAN_RAW, CAN_RAW_FILTER, NULL, 0);

	/* try to switch the socket into CAN FD mode */
	setsockopt(s, SOL_CAN_RAW, CAN_RAW_FD_FRAMES, &canfd_on, sizeof(canfd_on));

	if (loopback_disable) {
		int loopback = 0;

		setsockopt(s, SOL_CAN_RAW, CAN_RAW_LOOPBACK,
			   &loopback, sizeof(loopback));
	}

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		return 1;
	}

	if (assignments) {
		/* add & check user assignments from commandline */
		for (i=0; i<assignments; i++) {
			if (strlen(argv[optind+i]) >= BUFSZ) {
				fprintf(stderr, "Assignment too long!\n");
				print_usage(basename(argv[0]));
				return 1;
			}
			strcpy(buf, argv[optind+i]);
			for (j=0; j<(int)BUFSZ; j++) { /* find '=' in assignment */
				if (buf[j] == '=')
					break;
			}
			if ((j == BUFSZ) || (buf[j] != '=')) {
				fprintf(stderr, "'=' missing in assignment!\n");
				print_usage(basename(argv[0]));
				return 1;
			}
			buf[j] = 0; /* cut string in two pieces */
			if (add_assignment("user", s, &buf[0], &buf[j+1], verbose))
				return 1;
		}
	}

	//! Inizio mio codice
		if(realtime){
			//Initialize data structure
			int numFrame=countFrames();

			printf("Num Frames: %d\n\n",numFrame);

			long long int delta[numFrame];
			struct can_frame frames[numFrame];

			readFrames(frames,delta,numFrame);

			//Make socket CAN
			int s; 
			struct sockaddr_can addr;
			struct ifreq ifr;
			struct can_frame frame;

			if ((s = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
				perror("Socket");
				return 1;
			}

			strcpy(ifr.ifr_name, NAME_SOCKET );
			ioctl(s, SIOCGIFINDEX, &ifr);

			memset(&addr, 0, sizeof(addr));
			addr.can_family = AF_CAN;
			addr.can_ifindex = ifr.ifr_ifindex;

			if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
				perror("Bind");
				return 1;
			}

			//Send CAN frame on the CAN socket

			long long int currentTime;
			
			long long int initialTime=getMicroseconds();
			long long int startTime=initialTime + MICROSECONDS_TO_SYNCHRONIZE;   //Parto dopo 1 secondi
			
			long long int frameTime[numFrame];
			frameTime[0]=startTime;						//Il primo frame parte allo start time
			for(int i=1;i<numFrame;i++)
				frameTime[i]=frameTime[i-1]+delta[i];


			FILE *fp;
			fp = fopen("frametimeToSend.txt", "w");
			for(int i=0;i<numFrame;i++)
				fprintf(fp, "%lld\n",frameTime[i]);
			fclose(fp);


			//send empty frames to enter in the steady state
			if(STABILIZE){
				sendEmptyFrame(s,NUM_FRAMES_STABILIZE);
			}

			for(int i=0;i<numFrame;i++){
				currentTime=getMicroseconds();
				//Active sleep
				while(currentTime<frameTime[i]-MICROSECONDS_OF_MARGIN){
					currentTime=getMicroseconds();
				}
				write(s, &frames[i], sizeof(struct can_frame));
			}

			if (close(s) < 0) {
				perror("Close");
				return 1;
			}else{
				printf("\nSocket chiusa\n");
			}
			
			return 0;


		}else{
			//! Fine mio codice

			while (infinite_loops || loops--) {

				if (infile != stdin)
					rewind(infile); /* for each loop */

				if (verbose > 1) /* use -v -v to see this */
					printf (">>>>>>>>> start reading file. remaining loops = %d\n", loops);

				/* read first non-comment frame from logfile */
				while ((fret = fgets(buf, BUFSZ-1, infile)) != NULL && buf[0] != '(') {
					if (strlen(buf) >= BUFSZ-2) {
						fprintf(stderr, "comment line too long for input buffer\n");
						return 1;
					}
				}

				if (!fret)
					goto out; /* nothing to read */

				eof = 0;

				if (sscanf(buf, "(%lu.%lu) %s %s", &log_tv.tv_sec, &log_tv.tv_usec,
					device, ascframe) != 4) {
					fprintf(stderr, "incorrect line format in logfile\n");
					return 1;
				}

				if (use_timestamps) { /* throttle sending due to logfile timestamps */

					gettimeofday(&today_tv, NULL);
					create_diff_tv(&today_tv, &diff_tv, &log_tv);
					last_log_tv = log_tv;
				}

			
				while (!eof) {

						while ((!use_timestamps) ||
							(frames_to_send(&today_tv, &diff_tv, &log_tv) < 0)) {

							/* wait for keypress to process next frame */
							if (interactive)
								getchar();

							/* log_tv/device/ascframe are valid here */

							if (strlen(device) >= IFNAMSIZ) {
								fprintf(stderr, "log interface name '%s' too long!", device);
								return 1;
							}

							txidx = get_txidx(device); /* get ifindex for sending the frame */
			
							if ((!txidx) && (!assignments)) {
								/* ifindex not found and no user assignments */
								/* => assign this device automatically       */
								if (add_assignment("auto", s, device, device, verbose))
									return 1;
								txidx = get_txidx(device);
							}

							if (txidx == STDOUTIDX) { /* hook to print logfile lines on stdout */

								printf("%s", buf); /* print the line AS-IS without extra \n */
								fflush(stdout);

							} else if (txidx > 0) { /* only send to valid CAN devices */

								txmtu = parse_canframe(ascframe, &frame);
								if (!txmtu) {
									fprintf(stderr, "wrong CAN frame format: '%s'!", ascframe);
									return 1;
								}

								addr.can_family  = AF_CAN;
								addr.can_ifindex = txidx; /* send via this interface */
			
								if (sendto(s, &frame, txmtu, 0,	(struct sockaddr*)&addr, sizeof(addr)) != txmtu) {
									perror("sendto");
									return 1;
								}

								if (verbose) {
									printf("%s (%s) ", get_txname(device), device);

									if (txmtu == CAN_MTU)
										fprint_long_canframe(stdout, &frame, "\n", CANLIB_VIEW_INDENT_SFF, CAN_MAX_DLEN);
									else
										fprint_long_canframe(stdout, &frame, "\n", CANLIB_VIEW_INDENT_SFF, CANFD_MAX_DLEN);
								}

								if (count && (--count == 0))
									goto out;
							}

							/* read next non-comment frame from logfile */
							while ((fret = fgets(buf, BUFSZ-1, infile)) != NULL && buf[0] != '(') {
								if (strlen(buf) >= BUFSZ-2) {
									fprintf(stderr, "comment line too long for input buffer\n");
									return 1;
								}
							}

							if (!fret) {
								eof = 1; /* this file is completely processed */
								break;
							}

							if (sscanf(buf, "(%lu.%lu) %s %s", &log_tv.tv_sec, &log_tv.tv_usec,
								device, ascframe) != 4) {
								fprintf(stderr, "incorrect line format in logfile\n");
								return 1;
							}

							/*
							* ensure the fractions of seconds are 6 decimal places long to catch
							* 3rd party or handcrafted logfiles that treat the timestamp as float
							*/
							if (strchr(buf, ')') - strchr(buf, '.') != 7) {
								fprintf(stderr, "timestamp format in logfile requires 6 decimal places\n");
								return 1;
							}

							if (use_timestamps) {
								gettimeofday(&today_tv, NULL);

								/* test for logfile timestamps jumping backwards OR      */
								/* if the user likes to skip long gaps in the timestamps */
								if ((last_log_tv.tv_sec > log_tv.tv_sec) ||
									(skipgap && labs(last_log_tv.tv_sec - log_tv.tv_sec) > (long)skipgap))
									create_diff_tv(&today_tv, &diff_tv, &log_tv);

								last_log_tv = log_tv;
							}

						} /* while frames_to_send ... */

						delay_loops++; /* private statistics */
						gettimeofday(&today_tv, NULL);

					} /* while (!eof) */

				} /* while (infinite_loops || loops--) */
		}

		
out:

	close(s);
	fclose(infile);

	if (verbose > 1) /* use -v -v to see this */
		printf("%d delay_loops\n", delay_loops);

	return 0;
}

//! Inizio mio codice
void hexToASCII(char * hex, char *output){
	char substring[3];
	
	memcpy(substring,&hex[14],2);
    substring[2] = '\0';
	output[7]=(int)strtol(substring, NULL, 16);

	memcpy(substring,&hex[12],2);
    substring[2] = '\0';
	output[6]=(int)strtol(substring, NULL, 16);

	memcpy(substring,&hex[10],2);
    substring[2] = '\0';
	output[5]=(int)strtol(substring, NULL, 16);

	memcpy(substring,&hex[8],2);
    substring[2] = '\0';
	output[4]=(int)strtol(substring, NULL, 16);

	memcpy(substring,&hex[6],2);
    substring[2] = '\0';
	output[3]=(int)strtol(substring, NULL, 16);
	
	memcpy(substring,&hex[4],2);
    substring[2] = '\0';
	output[2]=(int)strtol(substring, NULL, 16);

	memcpy(substring,&hex[2],2);
    substring[2] = '\0';
	output[1]=(int)strtol(substring, NULL, 16);

	memcpy(substring,&hex[0],2);
    substring[2] = '\0';
	output[0]=(int)strtol(substring, NULL, 16);

	output[8]='\0';

}
void printFrames(struct can_frame * frames,double * delta,int numFrame){
	char hex[16+1];
	for(int i=0;i<numFrame;i++){
		printf("Frame %d:\n",i);
		printf("Can_ID: %d \t\t%x\n",frames[i].can_id,frames[i].can_id);
		printf("DLC: %d\n",frames[i].can_dlc);
		printf("Delta: %f \n",delta[i]);
		printf("Payload: %s\n",frames[i].data);
	}
	printf("\n\n");
}
void printDelta(long long int * delta,int numFrame, char *output){
	if(strcmp(output,"stdout")==0){
		for(int i=0;i<numFrame;i++){
			printf("Frame %d \t delta\t %lld\n",i,delta[i]);
		}
	}else{
		char buffer[1000+1];
		FILE *fp;
		fp=fopen(output,"w");
		for(int i=0;i<numFrame;i++){
			sprintf(buffer,"%lld",delta[i]);
			fprintf(fp,"%s\n",buffer);
		}
		fclose(fp);
	}
}
int  countFrames(){
	FILE *fp;
	char buf[200];
	char *res;

	if((fp=fopen(NAME_FILE, "rt"))==NULL) {
		printf("Errore nell'apertura del file'");
		exit(1);
	}

	//Stabilisco quanti frame contiene il file
	
	int numFrame=0;

	//Scarto la prima riga che sono i nomi delle colonne
	res=fgets(buf, 200, fp);
	
	while(1){
		res=fgets(buf, 200, fp);
		
		if( res==NULL )
		break; 
		
		numFrame+=1;
	}

	fclose(fp);

	return numFrame;
}
void readFrames(struct can_frame *frames, long long int * delta, int numFrame ){

	long long int temp2=0;

	//Leggo File riga per riga
	int i=0;
	int j=0;
	
	FILE *fp;
	char buf[200];
	char *res;
	const char temp[2] = ",";
    char *token;

	if((fp=fopen(NAME_FILE, "rt"))==NULL) {
		printf("Errore nell'apertura del file'");
		exit(1);
	}
	
	//Scarto la prima riga che sono i nomi delle colonne
	res=fgets(buf, 200, fp);

	//Inizio a leggere file riga per riga
	while(1) {
		j=0;
		res=fgets(buf, 200, fp);
		
		if( res==NULL )
		break; 
		
		//Lavoro sulla riga letta

		token = strtok(buf, temp);
	
		while( token != NULL ) {
			
			if(j==0){
				delta[i]=(long long int)(atof(token)*1000000)-temp2;
				temp2=(long long int)(atof(token)*1000000);
			}else if(j==1){
				frames[i].can_id=(int)strtol(token, NULL, 16);
			}else if(j==2){
				frames[i].can_dlc=atoi(token)/8;
			}else if(j==3){
				hexToASCII(token,frames[i].data);
			}
			
			token = strtok(NULL, temp);
			
			j=j+1;
		}
		i=i+1;
    }
	
	fclose(fp);

}
void sendEmptyFrame(int s,int numFrame){
	struct can_frame emptyFrame;

	emptyFrame.can_id = 0x000;
	emptyFrame.can_dlc = 8;
	hexToASCII("0000000000000000",emptyFrame.data);

	for(int i=0;i<numFrame;i++){
		if (write(s, &emptyFrame, sizeof(struct can_frame)) != sizeof(struct can_frame)) {
			perror("Write");
			return;
		}else{
			printf("Inviato frame vuoto\n");
		}
	}
}
long long int getMicroseconds(){
    struct timeval timer_usec; 
	long long int timestamp_usec; 
    
    //get timestamp in microseconds
    if (!gettimeofday(&timer_usec, NULL)) {
        timestamp_usec = ((long long int) timer_usec.tv_sec) * 1000000ll + 
                            (long long int) timer_usec.tv_usec;
    }else{
            timestamp_usec = -1;
    }
    
    return timestamp_usec; 
}
//!Fine mio codice