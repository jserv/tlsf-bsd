OUT = build

TARGETS = \
	test-bits \
	test-alloc
TARGETS := $(addprefix $(OUT)/,$(TARGETS))

all: $(TARGETS)

CC = gcc
CFLAGS = \
	-std=c99 -Wall -g -I tlsf \
	-D TLSF_CONFIG_ASSERT

OBJS = tlsf.o
OBJS := $(addprefix $(OUT)/,$(OBJS))
deps := $(OBJS:%.o=%.o.d)

$(OUT)/test-%: $(OBJS) tests/test-%.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(OUT)/%.o: tlsf/%.c
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -c -o $@ -MMD -MF $@.d $<

CMDSEP = ;
check: $(TARGETS)
	MALLOC_CHECK_=3 $(foreach prog,$(TARGETS),./$(prog) $(CMDSEP))

clean:
	$(RM) $(TARGETS) $(OBJS) $(deps)

.PHONY: all check clean

-include $(deps)
