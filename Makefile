
GIT_VERSION := NANO-E0-$(shell git describe --abbrev=7 --dirty --always --tags)

OPTS = -DCHECK_NEXTDCW -DSID_FILTER -DNEWCACHE \
		-DCCCAM_CLI -DRADEGAST_CLI -DCAMD35_CLI -DCS378X_CLI \
		-DHTTP_SRV -DTELNET -DMGCAMD_SRV -DCCCAM_SRV -DCAMD35_SRV -DCS378X_SRV \
		-DEXPIREDATE -DDCWSWAP -DCACHEEX -DIPLIST -DTESTCHANNEL -DTHREAD_DCW \
		-DEPOLL_NEWCAMD -DEPOLL_CCCAM -DEPOLL_MGCAMD -DEPOLL_ECM -DPEERLIST \
        	-DECMLIST -DFREECCCAM_SRV -DEPOLL_FREECCCAM \
        	-DGIT_COMMIT=\"$(GIT_VERSION)\" -DSRV_CSCACHE
        ## -DEPOLL_CACHE 
		## -DTESTCHANNEL -DDEBUG_NETWORK -DDEBUG_NETWORK2 -DMONOTHREAD_ACCEPT  
		## -DRADEGAST_SRV  -DFREECCCAM_SRV -DEPOLL_CACHE
		## -DMULTICONNECT -DRECVMSG_BLOC -DIPLIST
        ## -DCLI_CSCACHE -DSRV_CSCACHE



ifeq ($(target),x32)
  CC        = gcc
  OUTPUT	= x32
  CFLAGS	= -s -ggdb3 -m32 -O3 -I. $(OPTS) -DEPOLL_NEWCAMD -DEPOLL_ECM -std=gnu90
  LFLAGS	= $(CFLAGS)
else
ifeq ($(target),x64)
  CC        = gcc
  OUTPUT	= x64
  CFLAGS	= -s -ggdb3 -m64 -O3 -I. -fpack-struct $(OPTS) -DEPOLL_NEWCAMD -DEPOLL_ECM
  LFLAGS	= $(CFLAGS)
else
ifeq ($(target),ppc-old)
  CC        = /root/Desktop/tuxbox-cvs/root/cdk/bin/powerpc-tuxbox-linux-gnu-gcc
  OUTPUT	= ppc-old
  CFLAGS	= -s -ggdb3 -O2 $(OPTS) -DINOTIFY -DSTB
  LFLAGS	= $(CFLAGS)
else
ifeq ($(target),ppc)
  CC        = /opt/powerpc-tuxbox-linux-gnu/bin/powerpc-linux-gcc
  OUTPUT	= ppc
  CFLAGS	= -s -ggdb3 -O2 $(OPTS) -DINOTIFY -DSTB
  LFLAGS	= $(CFLAGS)
else
ifeq ($(target),mipsel)
  CC        = /opt/mipsel-unknown-linux-gnu/bin/mipsel-unknown-linux-gnu-gcc
  OUTPUT	= mipsel
  CFLAGS	= -s -ggdb3 -O2 $(OPTS) -DSTB -EL -march=mips1
  LFLAGS	= $(CFLAGS)
else
ifeq ($(target),mipsel-pli4)
  CC        = /opt/mipsel-tuxbox-linux-gnu/bin/mipsel-tuxbox-linux-gnu-gcc
  OUTPUT	= mipsel-pli4
  CFLAGS	= -s -ggdb3 -O2 $(OPTS) -DSTB -DEPOLL_NEWCAMD -DEPOLL_ECM
  LFLAGS	= $(CFLAGS)
else
ifeq ($(target),sparc)
  CC        = sparc-linux-gnu-gcc-4.7
  OUTPUT	= sparc
  CFLAGS	= -s -ggdb3 -O2 $(OPTS) -DSTB
  LFLAGS	= $(CFLAGS)
else
ifeq ($(target),sparc64)
  CC        = sparc64-linux-gnu-gcc
  OUTPUT	= sparc64
  CFLAGS	= -s -ggdb3 -O2 $(OPTS) -DSTB
  LFLAGS	= $(CFLAGS)
else
ifeq ($(target),sh4)
  CC        = /opt/STM/STLinux-2.4/devkit/sh4/bin/sh4-linux-gcc
  OUTPUT	= sh4
  CFLAGS	= -s -ggdb3 -O2 $(OPTS) -DST_7201 -DST_OSLINUX  -DARCHITECTURE_ST40 -DSTB -DEPOLL_NEWCAMD -DEPOLL_ECM
  LFLAGS	= $(CFLAGS)
else
ifeq ($(target),rpi)
#  CC        = /opt/tools-master/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian/bin/arm-linux-gnueabihf-gcc
  CC		= gcc
  OUTPUT	= rpi
  CFLAGS	= -s -ggdb3 -O2 $(OPTS) -DEPOLL_NEWCAMD -DEPOLL_ECM -DNOPACK
  LFLAGS	= $(CFLAGS)
else

ifeq ($(target),arm-coolstream)
  CC        = /opt/arm-cx2450x-linux-gnueabi/bin/arm-cx2450x-linux-gnueabi-gcc
  OUTPUT	= arm-coolstream
  CFLAGS	= -s -ggdb3 -O2 $(OPTS) -DSTB -fPIC
  LFLAGS	= $(CFLAGS)
else
ifeq ($(target),mips-uclibc)
  CC        = /opt/cross-compiler-mips/bin/mips-gcc
  OUTPUT	= mips-uclibc
  CFLAGS	= -s -ggdb3 -O2 $(OPTS) -DSTB -fPIC
  LFLAGS	= $(CFLAGS)
else
ifeq ($(target),armeb)
  CC		= /opt/OpenWrt-SDK-ixp4xx-2.6-for-Linux-i686/staging_dir_armeb/bin/armeb-linux-uclibc-gcc
  OUTPUT	= armeb
  CFLAGS	= -s -ggdb3 -O2 $(OPTS) -DINOTIFY -DSTB
  LFLAGS	= $(CFLAGS)
else
ifeq ($(target),aarch64)
  CC		= aarch64-linux-gnu-gcc
  OUTPUT	= aarch64
  CFLAGS	= -s -ggdb3 -O2 $(OPTS) -DSTB -DEPOLL_NEWCAMD -DEPOLL_ECM
  LFLAGS	= $(CFLAGS)
else
ifeq ($(target),fritzbox)
  CC        = /opt/gcc-4.2.1-uClibc-0.9.29/mipsel-linux-uclibc/bin/mipsel-linux-uclibc-gcc-4.2.1
  OUTPUT	= fritzbox
  CFLAGS	= -s -ggdb3 -O2 $(OPTS) -DSTB
  LFLAGS	= $(CFLAGS)
else

ifeq ($(target),mips64)
  CC        = mips64-linux-gnu-gcc
  OUTPUT	= mips64
  CFLAGS	= -s -ggdb3 -O2 $(OPTS) -DSTB -DEPOLL_NEWCAMD -DEPOLL_ECM
  LFLAGS	= $(CFLAGS)
else
ifeq ($(target),ppc64el)
  CC        = powerpc64le-linux-gnu-gcc
  OUTPUT	= ppc64el
  CFLAGS	= -s -ggdb3 -O2 $(OPTS) -DSTB -DEPOLL_NEWCAMD -DEPOLL_ECM
  LFLAGS	= $(CFLAGS)
else
ifeq ($(target),win32)
  CC        = /usr/bin/i586-mingw32msvc-gcc
  OUTPUT	= win32
  CFLAGS	= -s -ggdb3 -O2 $(OPTS)
  LFLAGS	= $(CFLAGS) -D__USE_W32_SOCKETS -D_WIN32_WINDOWS=0x0501 -lws2_32 -lpthread --disable-stdcall-fixup -mno-cygwin
else
  CC        = gcc
  OUTPUT	= x
  CFLAGS	= -s -ggdb3 -O3 -m64 -I. -fpack-struct $(OPTS) -D_GNU_SOURCE # -DSIG_HANDLER ## -DRECVMSG_BLOCK ## -DICACHE # -DCACHEEX_CWCYCLE ##  ##  -D_FORTIFY_SOURCE=0 
  LFLAGS	= $(CFLAGS)
endif
endif
endif
endif
endif
endif
endif
endif
endif
endif
endif
endif
endif
endif
endif
endif
endif
endif

ifndef name
	NAME	= multics
else
	AOUT	= $(name)
endif


OBJECTS = $(OUTPUT)/sha1.o $(OUTPUT)/des.o $(OUTPUT)/md5.o $(OUTPUT)/aes.o \
	$(OUTPUT)/dcw.o $(OUTPUT)/convert.o $(OUTPUT)/tools.o $(OUTPUT)/debug.o $(OUTPUT)/parser.o $(OUTPUT)/ipdata.o \
	$(OUTPUT)/threads.o $(OUTPUT)/sockets.o $(OUTPUT)/msg-newcamd.o $(OUTPUT)/msg-cccam.o $(OUTPUT)/msg-radegast.o $(OUTPUT)/config.o \
	$(OUTPUT)/ecmdata.o $(OUTPUT)/httpserver.o $(OUTPUT)/telnet.o $(OUTPUT)/main.o

link: $(OBJECTS)
	$(CC) -o $(OUTPUT)/$(NAME) $(LFLAGS) $(OBJECTS) -lpthread
	cp $(OUTPUT)/$(NAME) multics/$(NAME).$(OUTPUT)

%.o: ../%.c Makefile common.h config.h ecmdata.h
	$(CC) -c $(CFLAGS) $< -o $@

$(OUTPUT)/httpserver.o: httpserver.h httpbuffer.c httpserver.c

$(OUTPUT)/main.o: main.c Makefile common.h httpserver.h config.h clustredcache.c cacheex.c pipe.c pipe.h \
	th-ecm.c th-cfg.c th-dns.c th-date.c th-srv.c \
	srv-cccam.c srv-newcamd.c srv-mgcamd.c srv-radegast.c srv-freecccam.c srv-camd35.c srv-cs378x.c \
	cli-common.c cli-cccam.c cli-newcamd.c cli-radegast.c cli-camd35.c cli-cs378x.c

all:
	$(MAKE) target=ppc-old
	$(MAKE) target=ppc
	$(MAKE) target=mipsel
	$(MAKE) target=mipsel-pli4
	$(MAKE) target=sh4
	$(MAKE) target=sparc
	$(MAKE) target=arm-coolstream
	$(MAKE) target=rpi
	$(MAKE) target=fritzbox
	$(MAKE) target=armeb
	$(MAKE) target=aarch64
	$(MAKE) target=ppc64el

clean:
	-rm $(OUTPUT)/*

cleanall:
	$(MAKE) clean
	$(MAKE) target=x64 clean
	$(MAKE) target=x32 clean
	$(MAKE) target=ppc-old clean
	$(MAKE) target=ppc clean
	$(MAKE) target=mipsel clean
	$(MAKE) target=mipsel-pli4 clean
	$(MAKE) target=sh4 clean
	$(MAKE) target=sparc clean
	$(MAKE) target=arm-coolstream clean
	$(MAKE) target=rpi clean
	$(MAKE) target=fritzbox clean
	$(MAKE) target=armeb clean
	$(MAKE) target=aarch64 clean
	$(MAKE) target=ppc64el clean
	-rm multics/*

