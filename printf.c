/*
 * This file is part of ltrace.
 * Copyright (C) 2011,2012,2013 Petr Machata, Red Hat Inc.
 * Copyright (C) 1998,2004,2007,2008,2009 Juan Cespedes
 * Copyright (C) 2006 Steve Fink
 * Copyright (C) 2006 Ian Wienand
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "printf.h"
#include "type.h"
#include "value.h"
#include "expr.h"
#include "zero.h"
#include "param.h"
#include "lens_default.h"

struct param_enum {
	struct value array;
	int percent;
	bool have_future_precision;
	unsigned long long future_precision;
	char *format;
	char const *ptr;
	char const *end;
	size_t width;
};

static struct param_enum *
param_printf_init(struct value *cb_args, size_t nargs,
		  struct value_dict *arguments)
{
	assert(nargs == 1);

	struct process *proc = cb_args[0].inferior;
	assert(proc != NULL);

	/* We expect a pointer to array.  */
	if (cb_args->type->type != ARGTYPE_POINTER
	    || cb_args->type->u.ptr_info.info->type != ARGTYPE_ARRAY)
		return NULL;

	/* The element type should be either character (for narrow
	 * strings) or an integral type (for wide strings).  */
	struct arg_type_info *et
		= cb_args->type->u.ptr_info.info->u.array_info.elt_type;
	switch (et->type) {
	case ARGTYPE_CHAR:
	case ARGTYPE_SHORT:
	case ARGTYPE_USHORT:
	case ARGTYPE_INT:
	case ARGTYPE_UINT:
	case ARGTYPE_LONG:
	case ARGTYPE_ULONG:
	case ARGTYPE_LLONG:
	case ARGTYPE_ULLONG:
		break;
	default:
		return NULL;
	}

	struct param_enum *self = malloc(sizeof(*self));
	if (self == NULL) {
	fail:
		free(self);
		return NULL;
	}
	self->width = type_sizeof(proc, et);
	if (self->width == (size_t) -1)
		goto fail;

	if (value_init_deref(&self->array, cb_args) < 0)
		goto fail;
	assert(self->array.type->type == ARGTYPE_ARRAY);

	/* We want to print *all* arguments relevant to the format string, and
	 * thus we need to have the full format string to inspect - and an
	 * array's zero() is limited by -s and -A, which are for display limits.
	 * We thus need to do this, which is somewhat hack-ish :| */
	size_t length = zero_array_length_raw(&self->array, arguments, SIZE_MAX);
	if (length == (size_t)-1) {
		value_destroy(&self->array);
		goto fail;
	}

	self->array.size = length * self->width; /* A bit rude, but oh well. */

	self->format = (char *)value_get_data(&self->array, arguments);
	if (self->format == NULL) {
		value_destroy(&self->array);
		goto fail;
	}

	self->percent = 0;
	self->ptr = self->format;
	self->end = self->format + self->array.size;
	self->have_future_precision = false;
	return self;
}

static int
form_next_param(struct param_enum *self,
		enum arg_type format_type, enum arg_type elt_type,
		unsigned hlf, unsigned lng, char *prec_buf, size_t prec_buf_len,
		struct arg_type_info *infop)
{
	/* XXX note: Some types are wrong because we lack
	   ARGTYPE_UCHAR and ARGTYPE_SCHAR.  */
	assert(lng <= 2);
	assert(hlf <= 2);
	static enum arg_type ints[] =
		{ ARGTYPE_CHAR, ARGTYPE_SHORT, ARGTYPE_INT,
		  ARGTYPE_LONG, ARGTYPE_LLONG };
	static enum arg_type uints[] =
		{ ARGTYPE_CHAR, ARGTYPE_USHORT, ARGTYPE_UINT,
		  ARGTYPE_ULONG, ARGTYPE_ULLONG };

	struct arg_type_info *elt_info = NULL;
	if (format_type == ARGTYPE_ARRAY || format_type == ARGTYPE_POINTER)
		elt_info = type_get_simple(elt_type);
	else if (format_type == ARGTYPE_INT)
		format_type = ints[2 + lng - hlf];
	else if (format_type == ARGTYPE_UINT)
		format_type = uints[2 + lng - hlf];


	if (format_type == ARGTYPE_ARRAY) {
		struct arg_type_info *array = malloc(sizeof(*array));
		if (array == NULL)
			return -1;

		struct expr_node *node = NULL;
		int own_node;
		if (prec_buf_len != 0
		    || self->have_future_precision) {
			struct tmp {
				struct expr_node node;
				struct arg_type_info type;
			};
			struct tmp *len = malloc(sizeof(*len));
			if (len == NULL) {
			fail:
				free(len);
				free(array);
				return -1;
			}

			len->type = *type_get_simple(ARGTYPE_LONG);

			long l;
			if (self->have_future_precision) {
				l = self->future_precision;
				self->have_future_precision = false;
			} else {
				l = atol(prec_buf);
			}

			expr_init_const_word(&len->node, l, &len->type, 0);

			node = build_zero_w_arg(&len->node, 1);
			if (node == NULL)
				goto fail;
			own_node = 1;

		} else {
			node = expr_node_zero();
			own_node = 0;
		}
		assert(node != NULL);

		type_init_array(array, elt_info, 0, node, own_node);
		type_init_pointer(infop, array, 1);

	} else if (format_type == ARGTYPE_POINTER) {
		type_init_pointer(infop, elt_info, 0);

	} else {
		*infop = *type_get_simple(format_type);
	}

	return 0;
}

static int
param_printf_next(struct param_enum *self, struct arg_type_info *infop,
		  int *insert_stop)
{
	unsigned hlf = 0;
	unsigned lng = 0;
	enum arg_type format_type = ARGTYPE_VOID;
	enum arg_type elt_type = ARGTYPE_VOID;
	char prec_buf[25] = {};
	size_t prec_buf_len = 0;
	struct lens *lens = NULL;
	bool digital_width = false, digital_width_fast = false, in_precision = false;

	for (; self->ptr < self->end; self->ptr += self->width) {
		union {
			uint8_t u8;
			uint16_t u16;
			uint32_t u32;
			uint64_t u64;
			char buf[0];
		} u;
		memcpy(u.buf, self->ptr, self->width);
		switch (self->width) {
		case 1: u.u64 = u.u8; break;
		case 2: u.u64 = u.u16; break;
		case 4: u.u64 = u.u32; break;
		}
		uint64_t c = u.u64;

		if (!self->percent) {
			if (c == '%')
				self->percent = 1;
			continue;
		}

		switch (c) {
		case '#': case ' ': case '-':
		case '+': case 'I': case '\'':
			/* These are only important for formatting,
			 * not for interpreting the type.  */
			continue;

		case '.':
			/* Digits and * we see now apply to precision, not width.
			 * This mostly matters for %s. */
			in_precision = true;
			continue;

		case '*':
			/* Length parameter given in the next
			 * argument.  */
			if (in_precision)
				self->have_future_precision = true;
			self->ptr += self->width;
			format_type = ARGTYPE_INT;
			break;

		case '0':
		case '1': case '2': case '3':
		case '4': case '5': case '6':
		case '7': case '8': case '9':
			if(!digital_width) {
				/* Field length likewise, but we need to parse
				 * this to attach the appropriate string
				 * length expression.
				 * We don't care about width. */
				if (in_precision && prec_buf_len < sizeof(prec_buf) - 1)
					prec_buf[prec_buf_len++] = c;
			} else {
				/* %w32d */
				digital_width = false;
				int b;
				switch(strtoul(self->ptr, (char **)&self->ptr, 10)) {
#define W_OR_WF(bits)                                               \
	case bits:                                                  \
		--self->ptr;                                        \
		b = digital_width_fast ? sizeof(int_fast##bits##_t) \
				       : sizeof(int##bits##_t);     \
		break
				W_OR_WF(8);
				W_OR_WF(16);
				W_OR_WF(32);
				W_OR_WF(64);
				default:
					goto err;
				}
				switch(b) {
					case 1:
						hlf = 2;
						lng = 0;
						break;
					case 2:
						hlf = 1;
						lng = 0;
						break;
					case 4:
						hlf = 0;
						lng = 0;
						break;
					case 8:
						hlf = 0;
						lng = 2;
						break;
				}
			}
			continue;

		case 'h':
			if (hlf < 2)
				hlf++;
			continue;

		case 'l':
			if (lng < 2)
				lng++;
			continue;

		case 'q':
			lng = 2;
			continue;

		case 'L': /* long double */
			lng = 1;
			continue;

		case 'j': /* intmax_t */
			/*   XXX ABI should know */
			lng = 2;
			continue;

		case 't': /* ptrdiff_t */
		case 'Z': case 'z': /* size_t */
			lng = 1; /* XXX ABI should tell */
			continue;

		case 'w':
			++self->ptr;
			digital_width = 1;
			if(self->ptr >= self->end || *self->ptr != 'f') {
				--self->ptr;
				digital_width_fast = false;
			} else
				digital_width_fast = true;
			continue;

		case 'd':
		case 'i':
			format_type = ARGTYPE_INT;
			self->percent = 0;
			break;

		case 'b':
			lens = &binary_lens;
			goto uint;

		case 'o':
			lens = &octal_lens;
			goto uint;

		case 'x': case 'X':
			lens = &hex_lens;
			/* Fall through.  */
		case 'u':
		uint:
			format_type = ARGTYPE_UINT;
			self->percent = 0;
			break;

		case 'e': case 'E':
		case 'f': case 'F':
		case 'g': case 'G':
		case 'a': case 'A':
			format_type = ARGTYPE_DOUBLE;
			self->percent = 0;
			break;

		case 'C': /* like "lc" */
			if (lng == 0)
				lng++;
		case 'c':
			/* XXX "lc" means wchar_t string.  */
			format_type = ARGTYPE_CHAR;
			self->percent = 0;
			break;

		case 'S': /* like "ls" */
			if (lng == 0)
				lng++;
		case 's':
			format_type = ARGTYPE_ARRAY;
			elt_type = lng == 0 ? ARGTYPE_CHAR : ARGTYPE_INT;
			self->percent = 0;
			lens = &string_lens;
			break;

		case 'p':
		case 'n': /* int* where to store no. of printed chars.  */
			format_type = ARGTYPE_POINTER;
			elt_type = ARGTYPE_VOID;
			self->percent = 0;
			break;

		case 'm': /* (glibc) print argument of errno */
		case '%':
			lng = 0;
			hlf = 0;
			self->percent = 0;
			continue;

		default:
			continue;
		}

		/* If we got here, the type must have been set.  */
		assert(format_type != ARGTYPE_VOID);

		if (form_next_param(self, format_type, elt_type, hlf, lng,
				    prec_buf, prec_buf_len, infop) < 0)
			return -1;

		infop->lens = lens;
		infop->own_lens = 0;

		return 0;
	}

err:
	*infop = *type_get_simple(ARGTYPE_VOID);
	return 0;
}

static enum param_status
param_printf_stop(struct param_enum *self, struct value *value)
{
	if (self->have_future_precision
	    && value_extract_word(value, (long long *)&self->future_precision, NULL) < 0)
		self->have_future_precision = false;

	return PPCB_CONT;
}

static void
param_printf_done(struct param_enum *context)
{
	value_destroy(&context->array);
	free(context);
}

void
param_pack_init_printf(struct param *param, struct expr_node *arg, int own_arg)
{
	param_init_pack(param, PARAM_PACK_VARARGS, arg, 1, own_arg,
			&param_printf_init, &param_printf_next,
			&param_printf_stop, &param_printf_done);
}
