# Copyright (C) 2013  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
#
# THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
# OR IMPLIED. ANY USE IS AT YOUR OWN RISK.
#
# Permission is hereby granted to use or copy this program for any
# purpose, provided the above notices are retained on all copies.
# Permission to modify the code and to distribute modified code is
# granted, provided the above notices are retained, and a notice that
# the code was modified is included with the above copyright notice.

# This Makefile is not using automake so that users may see how to build
# a program with tracepoint provider probes as stand-alone shared objects.

CC = gcc
LDFLAGS=-Wl,--no-as-needed -ldl
#CFLAGS=-g -O2 -Wall
CFLAGS=-g -Wall

all: memleak-finder.so malloc-stats.so fdleak-finder.so

memleak-finder.o: memleak-finder.c jhash.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -fpic -c -o $@ $<

memleak-finder.so: memleak-finder.o
	$(CC) -shared -o $@ $(LDFLAGS) $^

malloc-stats.o: malloc-stats.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -fpic -c -o $@ $<

malloc-stats.so: malloc-stats.o
	$(CC) -shared -o $@ $(LDFLAGS) $^

fdleak-finder.o: fdleak-finder.c jhash.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -fpic -c -o $@ $<

fdleak-finder.so: fdleak-finder.o
	$(CC) -shared -o $@ $(LDFLAGS) $^

.PHONY: clean
clean:
	rm -f *.o *.so
