all: libauditlog.so test
.PHONY: all

libauditlog.so:
	gcc -shared -fPIC libauditlog.c

test: libauditlog.so test_libauditlog
	./libauditlog-test
.PHONY: test

test_libauditlog:
	gcc test_libauditlog.c -o libauditlog-test

clean:
	rm -f libauditlog.so libauditlog-test
.PHONY: clean
