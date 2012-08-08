#!/usr/bin/make -f
# $Id: Makefile 5663 2008-09-15 17:53:59Z clworld $

# options
B25      = -DB25
HDUS     = -DHDUS
UDP      = -DUDP
TSSL     = -DTSSL

ifdef B25
  B25_OBJS = B25Decoder.o
endif

ifdef HDUS
  HDUS_OBJS = Hdus.o Hdp.o
endif

ifdef UDP
  UDP_OBJS = Udp.o
endif

ifdef TSSL
  TSSL_OBJS = tssplitter_lite.o
endif

DIST     = .
CC       = gcc
CXX      = g++
CXXFLAGS = -O2 -march=native -g -Wall -pthread -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 $(B25) $(HDUS) $(UDP) $(TSSL) `pkg-config --cflags glib-2.0` -I /usr/local/include/
LDFLAGS ?= -L /usr/local/lib/

OBJS   = recfriio.o usbops.o error.o IoThread.o Recordable.o AbstractFriio.o FriioWhite.o FriioBlack.o FriioWhiteWrapper.o FriioExpress.o $(B25_OBJS) $(HDUS_OBJS) $(UDP_OBJS) $(TSSL_OBJS)
LIBS   = -lpthread -lboost_thread-mt -lboost_filesystem -larib25 `pkg-config --libs glib-2.0`
TARGET = $(DIST)/recfriio
DEPEND = Makefile.dep

all: $(TARGET)

clean:
	rm -f $(OBJS) $(TARGET) $(DEPEND)

$(TARGET):	$(OBJS)
	$(CXX) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

$(DEPEND):
	$(CC) -MM $(OBJS:.o=.cpp) > Makefile.dep

-include $(DEPEND)
