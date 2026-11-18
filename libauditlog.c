#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include "libauditlog.h"

#define AUDIT_LOG_DEFAULT "/tmp/access_audit.log"
#define AUDIT_LOG (getenv("AUDIT_LOG_PATH") ? getenv("AUDIT_LOG_PATH") : AUDIT_LOG_DEFAULT)
#define LOG_TEMPLATE "{\"date\":\"%s\",\"time\":\"%s\",\"pid\":%d,\"uid\":%u,\"filename\":\"%s\",\"operation\":\"%s\",\"denied\":%s,\"file_hash\":\"%s\"}\n"

static FILE *(*real_fopen)(const char *, const char *) = NULL;
static int   (*real_fclose)(FILE *) = NULL;

static const char *op_to_str(log_operation op) {
    switch (op) {
        case OP_CREATED: return "CREATED";
        case OP_OPENED:  return "OPENED";
        case OP_WRITTEN: return "WRITTEN";
        case OP_CLOSED:  return "CLOSED";
        default:         return "UNKNOWN";
    }
}

static void write_log_event(const log_event *event, const char *logfile) {
    FILE *f = real_fopen(logfile, "a");
    if (!f) return;

    fprintf(f, LOG_TEMPLATE,
        event->date,
        event->time,
        event->pid,
        event->uid,
        event->filename,
        op_to_str(event->operation),
        event->denied ? "true" : "false",
        event->file_hash
    );

    real_fclose(f);
}

FILE *fopen(const char *path, const char *mode) {
    if (!real_fopen)
        real_fopen = dlsym(RTLD_NEXT, "fopen");
    if (!real_fclose)
        real_fclose = dlsym(RTLD_NEXT, "fclose");

    log_event event = {0};
    event.uid = getuid();
    write_log_event(&event, AUDIT_LOG);

    return real_fopen(path, mode);
}

int fclose(FILE *handle) {
    if (!real_fclose)
        real_fclose = dlsym(RTLD_NEXT, "fclose");

    log_event event = {0};
    event.uid = getuid();
    event.operation = OP_CLOSED;
    write_log_event(&event, AUDIT_LOG);

    return real_fclose(handle);
}
