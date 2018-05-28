/**
* Copyright (c) 2016 rxi
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

#include <sys/unistd.h>
#include <sys/fcntl.h>
#include <oni/utils/kdlsym.h>
#include <oni/utils/memory/allocator.h>
#include <oni/utils/types.h>
#include <oni/utils/sys_wrappers.h>

#include "ini.h"

struct ini_t {
	char *data;
	char *end;
};

int tolower(char ch)
{
	if (ch >= 'A' && ch <= 'Z')
		return ('a' + ch - 'A');
	else
		return ch;
}

size_t
__strlen(const char *str)
{
	const char *s;

	for (s = str; *s; ++s)
		;
	return (s - str);
}

char *strchr(const char *s, int c)
{
	while (*s != (char)c)
		if (!*s++)
			return 0;
	return (char *)s;
}

/* Case insensitive string compare */
static int strcmpci(const char *a, const char *b) {
	for (;;) {
		int d = tolower(*a) - tolower(*b);
		if (d != 0 || !*a) {
			return d;
		}
		a++, b++;
	}
}

size_t strcspn(const char *s1, const char *s2)
{
	size_t ret = 0;
	while (*s1)
		if (strchr(s2, *s1))
			return ret;
		else
			s1++, ret++;
	return ret;
}

/* Returns the next string in the split data */
static char* next(ini_t *ini, char *p) {
	p += __strlen(p);
	while (p < ini->end && *p == '\0') {
		p++;
	}
	return p;
}

static void trim_back(ini_t *ini, char *p) {
	while (p >= ini->data && (*p == ' ' || *p == '\t' || *p == '\r')) {
		*p-- = '\0';
	}
}

static char* discard_line(ini_t *ini, char *p) {
	while (p < ini->end && *p != '\n') {
		*p++ = '\0';
	}
	return p;
}


static char *unescape_quoted_value(ini_t *ini, char *p) {
	/* Use `q` as write-head and `p` as read-head, `p` is always ahead of `q`
	* as escape sequences are always larger than their resultant data */
	char *q = p;
	p++;
	while (p < ini->end && *p != '"' && *p != '\r' && *p != '\n') {
		if (*p == '\\') {
			/* Handle escaped char */
			p++;
			switch (*p) {
			default: *q = *p;    break;
			case 'r': *q = '\r';  break;
			case 'n': *q = '\n';  break;
			case 't': *q = '\t';  break;
			case '\r':
			case '\n':
			case '\0': goto end;
			}

		}
		else {
			/* Handle normal char */
			*q = *p;
		}
		q++, p++;
	}
end:
	return q;
}


/* Splits data in place into strings containing section-headers, keys and
* values using one or more '\0' as a delimiter. Unescapes quoted values */
static void split_data(ini_t *ini) {
	char *value_start, *line_start;
	char *p = ini->data;

	while (p < ini->end) {
		switch (*p) {
		case '\r':
		case '\n':
		case '\t':
		case ' ':
			*p = '\0';
			/* Fall through */

		case '\0':
			p++;
			break;

		case '[':
			p += strcspn(p, "]\n");
			*p = '\0';
			break;

		case ';':
			p = discard_line(ini, p);
			break;

		default:
			line_start = p;
			p += strcspn(p, "=\n");

			/* Is line missing a '='? */
			if (*p != '=') {
				p = discard_line(ini, line_start);
				break;
			}
			trim_back(ini, p - 1);

			/* Replace '=' and whitespace after it with '\0' */
			do {
				*p++ = '\0';
			} while (*p == ' ' || *p == '\r' || *p == '\t');

			/* Is a value after '=' missing? */
			if (*p == '\n' || *p == '\0') {
				p = discard_line(ini, line_start);
				break;
			}

			if (*p == '"') {
				/* Handle quoted string value */
				value_start = p;
				p = unescape_quoted_value(ini, p);

				/* Was the string empty? */
				if (p == value_start) {
					p = discard_line(ini, line_start);
					break;
				}

				/* Discard the rest of the line after the string value */
				p = discard_line(ini, p);

			}
			else {
				/* Handle normal value */
				p += strcspn(p, "\n");
				trim_back(ini, p - 1);
			}
			break;
		}
	}
}



ini_t* ini_load(const char *filename) {
	ini_t *ini = NULL;
	int fp = NULL;
	int n, sz;

	/* Init ini struct */
	ini = kmalloc(sizeof(*ini));
	if (!ini) {
		goto fail;
	}
	kmemset(ini, 0, sizeof(*ini));

	/* Open file */
	fp = kopen((char*)filename, O_RDONLY, 0);
	if (!fp) {
		goto fail;
	}

	/* Get file size */
	sz = klseek(fp, 0, SEEK_END);
	klseek(fp, 0, SEEK_SET);

	/* Load file content into memory, null terminate, init end var */
	ini->data = kmalloc(sz + 1);
	ini->data[sz] = '\0';
	ini->end = ini->data + sz;
	n = kread(fp, ini->data, sz);
	if (n != sz) {
		goto fail;
	}

	/* Prepare data */
	split_data(ini);

	/* Clean up and return */
	kclose(fp);
	return ini;

fail:
	if (fp) kclose(fp);
	if (ini) ini_free(ini);
	return NULL;
}


void ini_free(ini_t *ini) {
	size_t len = ini->end - ini->data;
	kfree(ini->data, len);
	kfree(ini, sizeof(*ini));
}


const char* ini_get(ini_t *ini, const char *section, const char *key) {
	char *current_section = "";
	char *val;
	char *p = ini->data;

	if (*p == '\0') {
		p = next(ini, p);
	}

	while (p < ini->end) {
		if (*p == '[') {
			/* Handle section */
			current_section = p + 1;

		}
		else {
			/* Handle key */
			val = next(ini, p);
			if (!section || !strcmpci(section, current_section)) {
				if (!strcmpci(p, key)) {
					return val;
				}
			}
			p = val;
		}

		p = next(ini, p);
	}

	return NULL;
}


int ini_sget(
	ini_t *ini, const char *section, const char *key,
	const char *scanfmt, void *dst
) {
	int(*sscanf)(const char *, char const *, ...) = kdlsym(sscanf);

	const char *val = ini_get(ini, section, key);
	if (!val) {
		return 0;
	}
	if (scanfmt) {
		sscanf(val, scanfmt, dst);
	}
	else {
		*((const char**)dst) = val;
	}
	return 1;
}