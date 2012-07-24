# options
B25	= -DB25

ifdef B25
	B25_OBJS = B25Decoder.o
endif

DIST     = .
CC       = gcc
CXX	 = g++
CXXFLAGS = -O2 -g -Wall -pthread -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 $(B25) -I /usr/local/include/
LDFLAGS ?= -L /usr/local/lib/

OBJS	= fsusb2n.o usbops.o em2874-core.o ktv.o IoThread.o tssplitter_lite.o $(B25_OBJS)
LIBS	= -lpthread -lboost_thread-mt -lboost_filesystem -larib25
TARGET	= $(DIST)/recfsusb2n
DEPEND = Makefile.dep

all: $(TARGET)

clean:
	rm -f $(OBJS) $(TARGET) $(DEPEND)

$(TARGET): $(OBJS)
	$(CXX) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

$(DEPEND):
	$(CC) -MM $(OBJS:.o=.cpp) > Makefile.dep

-include $(DEPEND)
