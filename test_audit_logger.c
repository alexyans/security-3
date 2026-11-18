#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#define AUDIT_LOG "artifacts/access_audit.log"
#define TEST_ARTIFACT_FILE "artifacts/target.file"

static void setup_all(void) {
    setenv("AUDIT_LOG_PATH", AUDIT_LOG, 1);
}

static int assert_structure_ok(const char *line) {
    const char *fields[] = { "\"uid\":", "\"pid\":" };
    for (int i = 0; i < 2; i++) {
        const char *pos = strstr(line, fields[i]);
        if (!pos) {
            fprintf(stderr, "FAIL: missing field %s\n", fields[i]);
            return 0;
        }
        pos += strlen(fields[i]);
        while (*pos == ' ') pos++;
        if (!isdigit(*pos)) {
            fprintf(stderr, "FAIL: field %s is not a number\n", fields[i]);
            return 0;
        }
    }
    return 1;
}

static void teardown(void) {
    remove(TEST_ARTIFACT_FILE);
    remove(AUDIT_LOG);
}

static int test_fopen(void) {
    FILE *f = fopen(TEST_ARTIFACT_FILE, "r");
    if (f) fclose(f);

    FILE *logfile = fopen(AUDIT_LOG, "r");
    if (!logfile) {
        fprintf(stderr, "FAIL: failed to create audit log\n");
        teardown();
        return 1;
    }

    char line[2048];
    int found = 0;
    while (fgets(line, sizeof(line), logfile)) {
        if (strstr(line, TEST_ARTIFACT_FILE)) {
            found = 1;
            break;
        }
    }
    fclose(logfile);

    if (!found) {
        fprintf(stderr, "FAIL: failed to log operation `fopen`\n");
        teardown();
        return 1;
    }

    if (!assert_structure_ok(line)) {
        fprintf(stderr, "FAIL: failed to validate log line structure\n");
        teardown();
        return 1;
    }

    printf("PASS: fopen logged.\n");
    teardown();
    return 0;
}

static int test_fclose(void) {
    FILE *f = fopen(TEST_ARTIFACT_FILE, "w");
    if (f) fclose(f);

    FILE *logfile = fopen(AUDIT_LOG, "r");
    if (!logfile) {
        fprintf(stderr, "FAIL: failed to create audit log\n");
        teardown();
        return 1;
    }

    char line[2048];
    int found = 0;
    while (fgets(line, sizeof(line), logfile)) {
        if (strstr(line, "CLOSED")) {
            found = 1;
            break;
        }
    }
    fclose(logfile);

    if (!found) {
        fprintf(stderr, "FAIL: failed to log operation `fclose`\n");
        teardown();
        return 1;
    }

    if (!assert_structure_ok(line)) {
        fprintf(stderr, "FAIL: failed to validate log line structure\n");
        teardown();
        return 1;
    }

    printf("PASS: fclose logged.\n");
    teardown();
    return 0;
}

int main(void) {
    setup_all();

    if (test_fopen())  return 1;
    if (test_fclose()) return 1;

    return 0;
}
