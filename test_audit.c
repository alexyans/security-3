#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

#define ARTIFACT_COUNT 10
#define WORKER_COUNT   5
#define MAX_ACTIONS    100

typedef enum {
	MODE_W,
	MODE_WP,
	MODE_A,
	MODE_R,
	MODE_COUNT,
} file_mode;

static const char *mode_strings[MODE_COUNT] = { "w", "w+", "a", "r" };

struct worker {
	pid_t pid;
	int   fd;
};

static void
worker_loop(int read_fd)
{
	void (*fn)(void);
	while (read(read_fd, &fn, sizeof(fn)) == sizeof(fn))
		fn();
	exit(0);
}

static void
spawn_workers(struct worker *workers)
{
	for (int i = 0; i < WORKER_COUNT; i++) {
		int fds[2];
		pipe(fds);
		pid_t pid = fork();
		if (pid == 0) {
			close(fds[1]);
			worker_loop(fds[0]);
		}
		close(fds[0]);
		workers[i].pid = pid;
		workers[i].fd  = fds[1];
	}
}

static void
shutdown_workers(struct worker *workers)
{
	for (int i = 0; i < WORKER_COUNT; i++) {
		close(workers[i].fd);
		waitpid(workers[i].pid, NULL, 0);
	}
}

static file_mode
flip_coin_file_mode(void)
{
	return rand() % MODE_COUNT;
}

static void
fork_and_run(struct worker *worker, void (*fn)(void))
{
	write(worker->fd, &fn, sizeof(fn));
}

static void
generate_artifacts(char artifacts[ARTIFACT_COUNT][64])
{
	long ts = (long)time(NULL);
	for (int i = 0; i < ARTIFACT_COUNT; i++) {
		snprintf(artifacts[i], 64, "/tmp/audit_test_%ld_%d.txt", ts, i);
		FILE *f = fopen(artifacts[i], "w");
		if (f) fclose(f);
	}
}

int main(void) {

	char test_artifacts[ARTIFACT_COUNT][64];
	generate_artifacts(test_artifacts);

	struct worker workers[WORKER_COUNT];
	spawn_workers(workers);

	srand((unsigned)ts);
	for (int i = 0; i < MAX_ACTIONS; i++) {
		file_mode mode = flip_coin_file_mode();
	}

	shutdown_workers(workers);
	return 0;
}
