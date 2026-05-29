ARCH ?= x86_64-pc-linux-gnu

CFLAGS =  -g  -O0 #-fprofile-instr-generate -fcoverage-mapping -fcoverage-mcdc

ifeq ($(ARCH), aarch64)
CFLAGS += " -I /usr/aarch64-linux-gnu/include"
endif


#test: test2.c test2_helpers.c Makefile
#	clang -static $(CFLAGS) test2.c test2_helpers.c -o test

test2.o: test2.c Makefile
	clang -target $(ARCH) $(CFLAGS) -c test2.c -o test2.o

test2_helpers.o: test2_helpers.c Makefile
	clang -target $(ARCH) $(CFLAGS)  -c test2_helpers.c -o test2_helpers.o

test: test2.o test2_helpers.o Makefile
	clang -target $(ARCH) $(CFLAGS) -static test2.o test2_helpers.o -o test

mcdc.pickle: test2.c test2_helpers.c mcdc_tool_parser.py mcdc_tool_definitions.py
	python mcdc_tool_parser.py

all: test mcdc.pickle

clean:
	rm -f test test2.o test2_helpers.o compile_commands.json
