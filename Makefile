BINDEST = /usr/local/bin
MANDEST = /usr/local/man/man8

CFLAGS = -O2 -Wall -I. -g
LDFLAGS = -g
LIBS = 

netselect: netselect.o
	$(CC) $(LDFLAGS) -o $@ $@.o $(LIBS)
	-sudo chown root netselect && sudo chmod +s netselect

install: $(PROG)
	install -s -o root -g root -m 4755 netselect ${BASEDIR}$(BINDEST)
	install -o root -g root -m 0644 netselect.8 ${BASEDIR}$(MANDEST)

clean:
	$(RM) netselect *.o *~
