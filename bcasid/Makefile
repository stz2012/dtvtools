PROGRAM = bcasid
SRCS = bcasid.c b_cas_card.c
OBJS = $(subst .c,.o,$(SRCS))
DEPEND = Makefile.dep

RM := rm
CC := gcc

PCSC_LIBS ?= `pkg-config libpcsclite --libs`
PCSC_CFLAGS ?= `pkg-config libpcsclite --cflags`

CPPFLAGS = $(PCSC_CFLAGS)
CFLAGS = -O2 
LDFLAGS = $(PCSC_LIBS)

$(PROGRAM): $(OBJS)
	$(LINK.o) $^ $(LOADLIBES) -o $@

.PHONY: clean

clean:
	$(RM) $(OBJS) $(PROGRAM)
