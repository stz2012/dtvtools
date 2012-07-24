PREFIX = /usr/local
DEST_HEADER = $(PREFIX)/include/yakisoba

TARGET = libyakisoba.a
SRCS = Crypto.cpp  Decoder-ECM.cpp  Keys.cpp  Keyset.cpp
OBJS = $(subst .cpp,.o,$(SRCS))
HEADERS = Crypto.h  Decoder.h  Global.h  Keys.h Keyset.h

RM := rm
CXX := g++
CC := g++
AR := ar

CPPFLAGS = -g -fPIC -O2 
LDFLAGS = -g -fPIC
ARFLAGS = cr

$(TARGET): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^ $(LOADLIBES)

install: $(TARGET) $(HEADERS)
	install -m644 $(TARGET) $(PREFIX)/lib/$(TARGET)
	mkdir -p $(DEST_HEADER)
	install -m644 $(HEADERS) $(DEST_HEADER)
	
.PHONY: clean

clean:
	$(RM) $(OBJS) $(TARGET)

