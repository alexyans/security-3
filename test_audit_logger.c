#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AUDIT_LOG "./artifacts/access_audit.log"
#define TEST_ARTIFACT_FILE "./artifacts/target.file"

static void teardown(void) {
    remove(TEST_ARTIFACT_FILE);
    remove(AUDIT_LOG);
}

int main(void) {
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

    printf("PASS: success.\n");
    teardown();
    return 0;
}
