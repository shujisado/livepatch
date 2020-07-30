# 
# Makefile for livepatch
# $Id: Makefile 330 2004-11-03 11:38:02Z ukai $
# Copyright (C) 2004 Fumitoshi UKAI <ukai@debian.or.jp>
# All rights reserved.
# This is free software with ABSOLUTELY NO WARRANTY.
#
# You can redistribute it and/or modify it under the terms of 
# the GNU General Public License version 2.
#
CFLAGS=-Wall -O2 -g
all: livepatch

livepatch: livepatch.o
	$(CC) -o $@ $< -lbfd

fixup: fixup.o
	$(CC) -o $@ $< -lbfd

bfd: bfd.o
	$(CC) -o $@ $< -lbfd

clean:
	-rm -f *.o
	-rm -f livepatch fixup bfd

# EOF
