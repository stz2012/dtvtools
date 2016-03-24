# options
B25	= -DB25
#HTTP    = -DHTTP
TSSL    = -DTSSL

ifdef B25
  B25_OBJS = B25Decoder.o
endif

ifdef TSSL
  TSSL_OBJS = tssplitter_lite.o
endif

PREFIX = /usr/local
TARGET = recfsusb2n
OBJS   = fsusb2n.o usbops.o em2874-core.o ktv.o IoThread.o $(B25_OBJS) $(TSSL_OBJS)
DEPEND = Makefile.dep

CC       = gcc
CXX      = g++
CXXFLAGS = -O2 -g -Wall -pthread -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 $(B25) $(TSSL)
LDFLAGS  = 
LIBS     = -lpthread -lboost_thread -lboost_system -lboost_filesystem -larib25

all: $(TARGET)

clean:
	rm -f $(OBJS) $(TARGET) $(DEPEND)

uninstall:
	rm -vf $(PREFIX)/bin/$(TARGET) /etc/udev/rules.d/99-fsusb2n.rules

install: uninstall
	if [ -d /etc/udev/rules.d -a ! -f /etc/udev/rules.d/99-fsusb2n.rules ] ; then \
		install -m 644 etc/99-fsusb2n.rules /etc/udev/rules.d ; \
	fi
	install -m 755 $(TARGET) $(PREFIX)/bin

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

$(DEPEND):
	$(CC) -MM $(OBJS:.o=.cpp) > Makefile.dep

-include $(DEPEND)
