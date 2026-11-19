#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

#define SEED_ARTIFACT_COUNT      10
#define RESTRICTED_ARTIFACT_COUNT (SEED_ARTIFACT_COUNT / 5) // 20% ratio
#define ACCESSIBLE_ARTIFACT_COUNT (SEED_ARTIFACT_COUNT - RESTRICTED_ARTIFACT_COUNT)
#define MAX_ARTIFACTS            256
#define WORKER_COUNT   5
#define MAX_ACTIONS    100
#define TEST_UID_COUNT 5

static const uid_t test_uids[TEST_UID_COUNT] = { 60001, 60002, 60003, 60004, 60005 };

typedef enum {
	MODE_W,
	MODE_WP,
	MODE_A,
	MODE_R,
	MODE_COUNT,
} file_mode;

static const char *mode_strings[MODE_COUNT] = { "w", "w+", "a", "r" };

struct action {
	char      filename[512];
	file_mode mode;
};

struct worker {
	pid_t pid;
	int   fd;
};

static int
ticker(void)
{
	static time_t last = 0;
	time_t now = time(NULL);
	if (last == 0) { last = now; return 0; }
	if (now - last >= 5) { last = now; return 1; }
	return 0;
}

static void
seed_rng(void)
{
	srand((unsigned)(getpid() ^ time(NULL)));
}

static void
worker_loop(int read_fd)
{
	struct action a;
	while (read(read_fd, &a, sizeof(a)) == sizeof(a)) {
		FILE *f = fopen(a.filename, mode_strings[a.mode]);
		if (f) {
			if (a.mode != MODE_R)
				fprintf(f, "this should change the sha pid=%d ts=%ld\n", getpid(), (long)time(NULL));
			fclose(f);
		}
	}
	exit(0);
}

static uid_t
flip_coin_uid(void)
{
	seed_rng();
	return test_uids[rand() % TEST_UID_COUNT];
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
			setuid(flip_coin_uid());
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

static const char *
flip_coin_artifact(char restricted[][512],
                   char accessible[][512], int *accessible_count)
{
	if (rand() % 5 == 0) {
		return restricted[rand() % RESTRICTED_ARTIFACT_COUNT];
	} else {
		int idx = rand() % (*accessible_count + 1);
		if (idx == *accessible_count && *accessible_count < MAX_ARTIFACTS) {
			snprintf(accessible[*accessible_count], 512, "/tmp/audit_accessible_%ld_%d.txt", (long)time(NULL), *accessible_count);
			int fd = open(accessible[*accessible_count], O_CREAT | O_WRONLY, 0666);
			if (fd >= 0) { fchmod(fd, 0666); printf("created: %s\n", accessible[*accessible_count]); close(fd); }
			(*accessible_count)++;
		} else if (idx == *accessible_count) {
			idx = *accessible_count - 1;
		}
		return accessible[idx];
	}
}

static struct worker *
flip_coin_worker(struct worker *workers)
{
	return &workers[rand() % WORKER_COUNT];
}

static void
dispatch_action(struct worker *worker, struct action *a)
{
	write(worker->fd, a, sizeof(*a));
}

static void
generate_artifacts(char restricted[][512], char accessible[][512])
{
	long ts = (long)time(NULL);
	for (int i = 0; i < RESTRICTED_ARTIFACT_COUNT; i++) {
		snprintf(restricted[i], 512, "/tmp/audit_restricted_%ld_%d.txt", ts, i);
		int fd = open(restricted[i], O_CREAT | O_WRONLY, 0600);
		if (fd >= 0) close(fd);
	}
	for (int i = 0; i < ACCESSIBLE_ARTIFACT_COUNT; i++) {
		snprintf(accessible[i], 512, "/tmp/audit_accessible_%ld_%d.txt", ts, i);
		int fd = open(accessible[i], O_CREAT | O_WRONLY, 0666);
		if (fd >= 0) { fchmod(fd, 0666); printf("created: %s\n", accessible[i]); close(fd); }
	}
}

int main(void) {

	char restricted_artifacts[RESTRICTED_ARTIFACT_COUNT][512];
	char accessible_artifacts[MAX_ARTIFACTS][512];
	int accessible_count = ACCESSIBLE_ARTIFACT_COUNT;
	generate_artifacts(restricted_artifacts, accessible_artifacts);

	seed_rng();

	struct worker workers[WORKER_COUNT];
	spawn_workers(workers);
	for (int i = 0; i < MAX_ACTIONS; i++) {
		if (ticker()) printf("%d/%d\n", i, MAX_ACTIONS);
		struct action a;
		strncpy(a.filename, flip_coin_artifact(restricted_artifacts, accessible_artifacts, &accessible_count), sizeof(a.filename) - 1);
		a.filename[sizeof(a.filename) - 1] = '\0';
		a.mode = flip_coin_file_mode();
		dispatch_action(flip_coin_worker(workers), &a);
	}

	shutdown_workers(workers);
	return 0;
}
