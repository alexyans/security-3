#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include "libauditlog.h"

#define AUDIT_LOG_DEFAULT "/tmp/access_audit.log"
#define AUDIT_LOG (getenv("AUDIT_LOG_PATH") ? getenv("AUDIT_LOG_PATH") : AUDIT_LOG_DEFAULT)
#define LOG_TEMPLATE "%s %s %d %u [%s] %s %s %s\n"

static FILE *(*real_fopen)(const char *, const char *) = NULL;

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
        event->denied ? "DENIED" : "ALLOWED",
        event->file_hash
    );

    fclose(f);
}

FILE *fopen(const char *path, const char *mode) {
    if (!real_fopen)
        real_fopen = dlsym(RTLD_NEXT, "fopen");

    log_event event = {0};
    write_log_event(&event, AUDIT_LOG);

    return real_fopen(path, mode);
}
