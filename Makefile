all: audit_logger.so test
.PHONY: all

audit_logger.so:
	gcc -shared -fPIC libauditlog.c -o audit_logger.so -ldl -lcrypto

test: audit_logger.so test_audit_logger
	mkdir -p ./artifacts
	LD_PRELOAD=./audit_logger.so ./test_audit_logger
.PHONY: test

test_audit_logger:
	gcc test_audit_logger.c -o test_audit_logger

clean:
	rm -f audit_logger.so test_audit_logger
.PHONY: clean
