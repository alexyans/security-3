all: audit_logger.so audit_monitor test
.PHONY: all

audit_logger.so:
	gcc -shared -fPIC libauditlog.c -o audit_logger.so -ldl -lcrypto

test: audit_logger.so test_audit_logger
	mkdir -p ./artifacts
	LD_PRELOAD=./audit_logger.so ./test_audit_logger
.PHONY: test

test_audit_logger:
	gcc test_audit_logger.c -o test_audit_logger

audit_monitor:
	gcc audit_monitor.c -o audit_monitor

clean:
	rm -f audit_logger.so test_audit_logger audit_monitor
.PHONY: clean
