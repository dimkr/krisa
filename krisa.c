/*
 * This file is part of krisa.
 *
 * Copyright (c) 2019 Dima Krasner
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
#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "krisa.h"

#define MAX_TRACE_DEPTH 128

static char maps[16 * 1024];
static ssize_t maps_len = 0;
static int backtrace_fd = STDERR_FILENO;

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
	static char buf[512];
	static struct krisa_data data;
	Dl_info info;
	unsigned int i;
	int len;

	data.n = 0;
	_Unwind_Backtrace(on_frame, &data);
	if (data.n == 0)
		return;

	if ((maps_len > 0) && (write(fd, maps, (size_t)maps_len) != maps_len))
		return;

	for (i = 0; (i < data.n) && data.ip[i]; ++i) {
		info.dli_saddr = data.ip[i];
		info.dli_fbase = data.ip[i];

		dladdr(data.ip[i], &info);

		len = snprintf(
			buf,
			sizeof(buf),
			"%s|%p|%p\n",
			info.dli_fname,
			data.ip[i],
			(void *)((char *)data.ip[i] - (char *)info.dli_fbase)
		);
		if ((len < 0) || (len >= sizeof(buf)))
			break;

		if (write(fd, buf, (size_t)len) != (ssize_t)len)
			break;
	}
}

void krisa_backtrace(void)
{
	krisa_backtrace_fd(backtrace_fd);
}

static void on_sig(int sig)
{
	krisa_backtrace();
	raise(SIGKILL);
}

void krisa_init(const int fd)
{
	const int sigs[] = {SIGILL, SIGABRT, SIGFPE, SIGSEGV, SIGBUS, SIGSYS};
	struct sigaction sa;
	int maps_fd;
	unsigned int i;

	maps_fd = open("/proc/self/maps", O_RDONLY);
	if (maps_fd >= 0) {
		maps_len = read(maps_fd, maps, sizeof(maps) - 1);
		if (maps_len > 0)
			maps[maps_len] = '\0';
		close(maps_fd);
	}

	if (fd >= 0)
		backtrace_fd = fd;

	sigemptyset(&sa.sa_mask);
	sa.sa_handler = on_sig;
	sa.sa_flags = SA_RESTART | SA_ONSTACK;

	for (i = 0; i < sizeof(sigs) / sizeof(sigs[0]); ++i)
		sigaction(sigs[i], &sa, NULL);
}
