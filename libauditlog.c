#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <dlfcn.h>
#include "libauditlog.h"

#define AUDIT_LOG_DEFAULT "/tmp/access_audit.log"
#define AUDIT_LOG (getenv("AUDIT_LOG_PATH") ? getenv("AUDIT_LOG_PATH") : AUDIT_LOG_DEFAULT)
#define LOG_TEMPLATE "{\"date\":\"%s\",\"time\":\"%s\",\"pid\":%d,\"uid\":%u,\"filename\":\"%s\",\"operation\":\"%s\",\"denied\":%d,\"file_hash\":\"%s\"}\n"

static FILE *(*real_fopen)(const char *, const char *) = NULL;
static int   (*real_fclose)(FILE *) = NULL;

static void fill_datetime(log_event *event) {
    time_t now = time(NULL);
    struct tm *utc = gmtime(&now);
    strftime(event->date, sizeof(event->date), "%Y-%m-%d", utc);
    strftime(event->time, sizeof(event->time), "%H:%M:%S", utc);
}

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
        event->denied,
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
    fill_datetime(&event);
    event.uid = getuid();
    event.pid = getpid();
    event.operation = OP_OPENED;
    if (path[0] == '/') {
        strncpy(event.filename, path, sizeof(event.filename) - 1);
    } else {
        char cwd[2048];
        getcwd(cwd, sizeof(cwd));
        snprintf(event.filename, sizeof(event.filename), "%s/%s", cwd, path);
    }
    FILE *result = real_fopen(path, mode);
    event.denied = (result == NULL && errno == EACCES) ? 1 : 0;
    write_log_event(&event, AUDIT_LOG);

    return result;
}

int fclose(FILE *handle) {
    if (!real_fclose)
        real_fclose = dlsym(RTLD_NEXT, "fclose");

    log_event event = {0};
    fill_datetime(&event);
    event.uid = getuid();
    event.pid = getpid();
    event.operation = OP_CLOSED;
    char fdlink[32];
    snprintf(fdlink, sizeof(fdlink), "/proc/self/fd/%d", fileno(handle));
    ssize_t n = readlink(fdlink, event.filename, sizeof(event.filename) - 1);
    if (n > 0) event.filename[n] = '\0';
    int result = real_fclose(handle);
    event.denied = 0; // flcose is not access-controlled; we always set denied to 0
    write_log_event(&event, AUDIT_LOG);

    return result;
}
