# This file is part of krisa.
#
# Copyright (c) 2019 Dima Krasner
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

project('krisa', 'c', version: '0.1', license: 'MIT')

add_global_arguments('-fno-omit-frame-pointer', '-rdynamic', language: 'c')

cc = meson.get_compiler('c')
libdl = cc.find_library('dl')
libgcc = cc.find_library('gcc')

libkrisa_includes = include_directories('.')

libkrisa = static_library('krisa',
                          'krisa.c',
                          include_directories: libkrisa_includes,
                          install: true,
                          dependencies: [libdl, libgcc])

install_headers('krisa.h')

if get_option('ci')
	null_deref = executable('null-deref',
	                        'null-deref.c',
	                        include_directories: libkrisa_includes,
	                        c_args: ['-g'],
	                        link_with: libkrisa)
endif
