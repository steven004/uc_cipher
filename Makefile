CC           = gcc
LD           = gcc
CFLAGS       = -Wall -Os -c -fPIC
LDFLAGS      = 
EXECS        = aes_test test_curve25519 uc_test

default: aes_test test_curve25519 uc_test

libuces.a: uces.o aes.o sha256.o curve25519-c64.o uces.o
	ar -rc $@ $^
	ranlib $@

libuces.so: uces.o aes.o sha256.o curve25519-c64.o uces.o
	$(CC) -shared -o $@ $^ 

aes.o : aes.c aes.h
	$(CC) $(CFLAGS) -o $@ $<

sha256.o : sha256.c sha256.h
	$(CC) $(CFLAGS) -o $@ $<

curve25519-c64.o : curve25519-c64.c
	$(CC) $(CFLAGS) -o $@ $<

uces.o : uces.c uces.h
	$(CC) $(CFLAGS) -o $@ $<

aes_test  : aes_test.c libuces.a
	$(CC) $(LDFLAGS) -o $@ $^

test_curve25519  : test_curve25519.c libuces.a 
	$(CC) $(LDFLAGS) -o $@ $^

uc_test  : uc_test.c libuces.so
	$(CC) $(LDFLAGS) -o $@ $^



clean:
	rm -f *.o *.a *.so
	rm -f $(EXECS) 
