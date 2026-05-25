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
#	ld -lc -o test test2.o test2_helpers.o "--hash-style=gnu" "--build-id" "--eh-frame-hdr" "-m" "elf_x86_64" "-pie" "-dynamic-linker" "/lib64/ld-linux-x86-64.so.2" "-o" "test" "/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/15.2.1/../../../../lib64/Scrt1.o" "/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/15.2.1/../../../../lib64/crti.o" "/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/15.2.1/crtbeginS.o" "-L/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/15.2.1" "-L/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/15.2.1/../../../../lib64" "-L/lib/../lib64" "-L/usr/lib64" "-L/lib" "-L/usr/lib" "-u__llvm_profile_runtime" "/usr/lib/clang/22/lib/linux/libclang_rt.profile-x86_64.a" "-lgcc" "--as-needed" "-lgcc_s" "--no-as-needed" "-lc" "-lgcc" "--as-needed" "-lgcc_s" "--no-as-needed" "/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/15.2.1/crtendS.o" "/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/15.2.1/../../../../lib64/crtn.o"

	/usr/aarch64-linux-gnu/bin/ld -g  "-EL" "--hash-style=gnu" "--eh-frame-hdr" "-m" "aarch64linux" "-pie" "--dynamic-linker=/usr/aarch64-linux-gnu/lib/ld-linux-aarch64.so.1" "-o" "test" "/usr/lib64/gcc/aarch64-linux-gnu/15.1.0/../../../../aarch64-linux-gnu/lib/../lib64/Scrt1.o" "/usr/lib64/gcc/aarch64-linux-gnu/15.1.0/../../../../aarch64-linux-gnu/lib/../lib64/crti.o" "/usr/lib64/gcc/aarch64-linux-gnu/15.1.0/crtbeginS.o" "-L/usr/lib64/gcc/aarch64-linux-gnu/15.1.0" "-L/usr/lib64/gcc/aarch64-linux-gnu/15.1.0/../../../../aarch64-linux-gnu/lib/../lib64" "-L/usr/lib64/gcc/aarch64-linux-gnu/15.1.0/../../../../lib64" "-L/lib/../lib64" "-L/usr/lib64" "-L/usr/lib64/gcc/aarch64-linux-gnu/15.1.0/../../../../aarch64-linux-gnu/lib" "-L/usr/aarch64-linux-gnu/lib/"  test2.o test2_helpers.o  "-lgcc" "--as-needed" "-lgcc_s" "--no-as-needed" "-lc" "-lgcc" "--as-needed" "-lgcc_s" "--no-as-needed" "/usr/lib64/gcc/aarch64-linux-gnu/15.1.0/crtendS.o" "/usr/lib64/gcc/aarch64-linux-gnu/15.1.0/../../../../aarch64-linux-gnu/lib/../lib64/crtn.o"

clean:
	rm -f test test2.o test2_helpers.o compile_commands.json
