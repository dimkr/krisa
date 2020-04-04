/*
 * This file is part of krisa.
 *
 * Copyright (c) 2019, 2020 Dima Krasner
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _GNU_SOURCE
#   define _GNU_SOURCE
#endif

#include <unwind.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "krisa.h"

#define MAX_TRACE_DEPTH 128
#define MAX_MAPPED_REGIONS 64

static int (*on_crash)(void) = NULL;

struct krisa_data {
	void *ip[MAX_TRACE_DEPTH];
	unsigned int n;
};

static _Unwind_Reason_Code on_frame(struct _Unwind_Context *ctx,
                                    void *arg)
{
	struct krisa_data *data = (struct krisa_data *)arg;

	data->ip[data->n] = (void *)_Unwind_GetIP(ctx);

	++data->n;
	if (data->n == MAX_TRACE_DEPTH)
		return 1;

	return 0;
}

void krisa_backtrace_fd(const int fd)
{
	static char maps[16 * 1024];
	static char buf[512];
	static struct krisa_data data;
	struct {
		char path[128];
		unsigned long start;
		unsigned long end;
		unsigned long off;
	} regions[MAX_MAPPED_REGIONS];
	char *pos, *l;
	const char *path;
	ssize_t out;
	unsigned long off;
	unsigned int i, nregions = 0, j;
	int len, maps_fd;

	data.n = 0;
	_Unwind_Backtrace(on_frame, &data);
	if (data.n == 0)
		return;

	maps_fd = open("/proc/self/maps", O_RDONLY);
	if (maps_fd < 0)
		return;

	out = read(maps_fd, maps, sizeof(maps) - 1);
	close(maps_fd);
	if (out <= 0)
		return;
	maps[out] = '\0';

	l = strtok_r(maps, "\n", &pos);
	while (l) {
		if (sscanf(l,
		           "%lx-%lx %*s %lx %*u:%*u %*u %127s",
		           &regions[nregions].start,
		           &regions[nregions].end,
		           &regions[nregions].off,
		           regions[nregions].path) == 4) {
			if (++nregions == (sizeof(regions) / sizeof(regions[0])))
				break;
		}
		l = strtok_r(NULL, "\n", &pos);
	}

	if (nregions == 0)
		return;

	for (i = 0; (i < data.n) && data.ip[i]; ++i) {
		path = "?";
		off = 0;

		for (j = 0; j < nregions; ++j) {
			if ((data.ip[i] >= (void *)regions[j].start) &&
			    (data.ip[i] < (void *)regions[j].end)) {
				path = regions[j].path;
				off = regions[j].off +
				      (unsigned long)((char *)data.ip[i] -
				                      (char *)regions[j].start);
				break;
			}
		}

		len = snprintf(buf, sizeof(buf), "%s@%lx\n", path, off);
		if ((len < 0) || (len >= sizeof(buf)))
			break;

		if (write(fd, buf, (size_t)len) != (ssize_t)len)
			break;
	}
}

void krisa_backtrace(void)
{
	int fd;

	if (on_crash) {
		fd = on_crash();
		if (fd < 0)
			return;

		krisa_backtrace_fd(fd);
		close(fd);
	} else
		krisa_backtrace_fd(STDERR_FILENO);
}

static void on_sig(int sig)
{
	krisa_backtrace();
	raise(SIGKILL);
}

void krisa_init(int (*get_fd)(void))
{
	const int sigs[] = {SIGILL, SIGABRT, SIGFPE, SIGSEGV, SIGBUS, SIGSYS};
	struct sigaction sa;
	unsigned int i;

	if (get_fd)
		on_crash = get_fd;

	sigemptyset(&sa.sa_mask);
	sa.sa_handler = on_sig;
	sa.sa_flags = SA_RESTART | SA_ONSTACK;

	for (i = 0; i < sizeof(sigs) / sizeof(sigs[0]); ++i) {
		signal(sigs[i], SIG_DFL);
		sigaction(sigs[i], &sa, NULL);
	}
}
