TEST_SRCS = \
	tests/test_var_assign.c \
	tests/test_basics.c \
	tests/test_inlines.c
#	tests/test_func_calls.c
#	tests/test_ariphmetics.c \

TEST_BINS = $(TEST_SRCS:.c=)
TEST_ASMS = $(TEST_SRCS:.c=.s)

MCDC_PICKLES = $(TEST_BINS:%=%_mcdc.pickle)
COMMANDS_JSONS = $(TEST_BINS:%=%_compile_commands.json)
DWARF_PICKLES = $(TEST_BINS:%=%_mcdc-dwarf.pickle)
PLUGIN_CONFS = $(TEST_BINS:%=%_plugin.conf)

TRACE_BINS   = $(TEST_BINS:%=%_brtrace.dat)
LCOV_INFOS   = $(TEST_BINS:%=%_coverage.info)

REFERENCE_INFOS = $(TEST_BINS:%=%_reference.info)

QEMU         ?= qemu-aarch64
QEMU_PLUGIN  ?= libbrtrace.so
SYSROOT      ?= /usr/aarch64-linux-gnu

CFLAGS =  -g -O0
CFLAGS += -target aarch64-unknown-linux-gnu
CFLAGS += -I /usr/aarch64-linux-gnu/include

.PHONY: all clean report check

all: $(TEST_BINS) $(MCDC_PICKLES) $(DWARF_PICKLES) $(PLUGIN_CONFS)

tests/%.o tests/%_compile_commands.json: tests/%.c Makefile
	bear --output tests/$*_compile_commands.json -- clang $(CFLAGS) -c $< -o $@

tests/%: tests/%.o
	clang $(CFLAGS) -static $< -o $@

tests/%.s: tests/%.c
	clang $(CFLAGS) -static $< -S -o $@

tests/%_mcdc.pickle: tests/%.c tests/%.o mcdc_tool_parser.py mcdc_tool_definitions.py
	python mcdc_tool_parser.py $< $@ tests/$*_compile_commands.json

mcdc.pickle: test2.c test2_helpers.c mcdc_tool_parser.py mcdc_tool_definitions.py
	python mcdc_tool_parser.py

tests/%_mcdc-dwarf.pickle tests/%_plugin.conf: tests/% tests/%_mcdc.pickle tests/%.s mcdc_tool_dwarf.py
	python mcdc_tool_dwarf.py $< tests/$*_mcdc.pickle tests/$*_mcdc-dwarf.pickle tests/$*_plugin.conf

tests/%_brtrace.dat: tests/% tests/%_plugin.conf
	@echo ">> Running $< in QEMU..."
	$(QEMU) -plugin $(QEMU_PLUGIN),config=tests/$*_plugin.conf -L $(SYSROOT) $<
	mv brtrace.dat $@

tests/%_coverage.info: tests/%_brtrace.dat tests/%_mcdc-dwarf.pickle mcdc_coverage_gen.py
	@echo ">> Generating LCOV data for $*..."
	python3 mcdc_coverage_gen.py --dwarf tests/$*_mcdc-dwarf.pickle --lcov $@ $<

report: $(LCOV_INFOS)
	@echo ">> Generating HTML coverage report..."
	genhtml --branch-coverage --mcdc-coverage -o coverage-report $(LCOV_INFOS)
	@echo "Done! Open coverage-report/index.html in your browser."

check: $(LCOV_INFOS) mcdc_report_compare.py
	@fails=0; \
	for test in $(TEST_BINS); do \
		echo ">> Comparing $${test} against baseline..."; \
		python3 mcdc_report_compare.py $${test}_reference.info $${test}_coverage.info || fails=$$((fails+1)); \
	done; \
	if [ $$fails -gt 0 ]; then \
		echo "$$fails test(s) failed MC/DC coverage comparison!"; exit 1; \
	else \
		echo "All tests passed MC/DC coverage comparison!"; \
	fi

clean:
	rm -f tests/*.o $(TEST_BINS) $(TEST_ASMS) $(MCDC_PICKLES) $(DWARF_PICKLES) $(PLUGIN_CONFS) $(COMMANDS_JSONS)
	rm -f $(TRACE_BINS) $(LCOV_INFOS) brtrace.dat
	rm -rf coverage-report/
