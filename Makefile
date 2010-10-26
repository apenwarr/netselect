PREFIX = /usr/local
BINDEST = ${PREFIX}/bin
MANDEST = ${PREFIX}/man/man1

CC = gcc
CFLAGS = -O2 -Wall -I. -g
LDFLAGS = -g
LIBS = 

ifdef OS2
LDFLAGS += -Zsmall-conv
LIBS += -lsocket
BINSUFFIX = .exe
STRIP =
else
STRIP = -s
endif

all: netselect

netselect: netselect.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS}

install: $(PROG)
	
ifdef OS2
	emxbind -bwq netselect
else
	chown root netselect && chmod u+s netselect
endif
	
	-install -d ${BINDEST}
	-install -d ${MANDEST}
	install -o root -g root -m 4755 \
		netselect${BINSUFFIX} ${BINDEST}
	install -o root -g root -m 0755 netselect-apt ${BINDEST}
	install -o root -g root -m 0644 netselect.1 ${MANDEST}
	install -o root -g root -m 0644 netselect-apt.1 ${MANDEST}

	
uninstall:
	$(RM) ${BINDEST}/netselect${BINSUFFIX} ${BINDEST}/netselect-apt
	$(RM) ${MANDEST}/netselect.1
	$(RM) ${MANDEST}/netselect-apt.1

clean:
	$(RM) netselect netselect${BINSUFFIX} *.o *~ build-stamp core
	$(RM) mirrors_full
