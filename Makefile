OUT = build

TARGETS = \
	test \
	bench
TARGETS := $(addprefix $(OUT)/,$(TARGETS))

all: $(TARGETS)

test: all
	./build/bench
	./build/bench -s 32
	./build/bench -s 10:12345
	./build/test

CFLAGS = \
	-std=c11 -g -Wextra -Wconversion -Wc++-compat -Wall \
	-DTLSF_ASSERT -DTLSF_DEBUG -DTLSF_STATS
LDFLAGS = -lrt
CFLAGS_TEST = $(CFLAGS) -D_DEFAULT_SOURCE -D_XOPEN_SOURCE=700

OBJS = tlsf.o
OBJS := $(addprefix $(OUT)/,$(OBJS))
deps := $(OBJS:%.o=%.o.d)

$(OUT)/test: $(OBJS) test.c
	$(CC) $(CFLAGS_TEST) -o $@ $^ $(LDFLAGS)

$(OUT)/bench: $(OBJS) bench.c
	$(CC) $(CFLAGS_TEST) -o $@ -MMD -MF $@.d $^ $(LDFLAGS)

$(OUT)/%.o: %.c
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c -o $@ -MMD -MF $@.d $<

CMDSEP = ; echo "Please wait..." ;
check: $(TARGETS)
	MALLOC_CHECK_=3 $(foreach prog,$(TARGETS),./$(prog) $(CMDSEP))

clean:
	$(RM) $(TARGETS) $(OBJS) $(deps)

.PHONY: all check clean test

-include $(deps)
