all: audit_logger.so audit_monitor test
.PHONY: all

audit_logger.so:
	gcc -shared -fPIC libauditlog.c -o audit_logger.so -ldl -lcrypto

test: audit_logger.so test_libauditlog
	mkdir -p ./artifacts
	LD_PRELOAD=./audit_logger.so ./test_libauditlog
.PHONY: test

test_libauditlog:
	gcc test_libauditlog.c -o test_libauditlog

audit_monitor:
	gcc audit_monitor.c -o audit_monitor

test_audit:
	gcc test_audit.c -o test_audit

clean:
	rm -f audit_logger.so test_libauditlog audit_monitor test_audit
.PHONY: clean
