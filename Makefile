BINDEST = ${BASEDIR}/usr/local/bin
MANDEST = ${BASEDIR}/usr/local/man/man8

CFLAGS = -O2 -Wall -I. -g
LDFLAGS = -g
LIBS = 

netselect: netselect.o
	$(CC) $(LDFLAGS) -o $@ $@.o $(LIBS)
	-sudo chown root netselect && sudo chmod +s netselect

install: $(PROG)
	install -d ${BINDEST}
	install -d ${MANDEST}
	install -s -o root -g root -m 4755 netselect $(BINDEST)
	#install -o root -g root -m 0644 netselect.8 $(MANDEST)

clean:
	$(RM) netselect *.o *~ build-stamp
