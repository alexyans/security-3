#ifndef LIBAUDITLOG_H
#define LIBAUDITLOG_H

#include <sys/types.h>
#include <stdint.h>

typedef enum {
    OP_CREATED = 0,
    OP_OPENED  = 1,
    OP_WRITTEN = 2,
    OP_CLOSED  = 3,
} log_operation;

typedef struct {
    uid_t         uid;
    pid_t         pid;
    char          filename[2048];
    char          date[11];
    char          time[9];
    log_operation operation;
    int           denied;
    char          file_hash[65];
} log_event;

#endif
