#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct log_entry {

	int uid; /* user id (positive integer) */
	pid_t pid; /* process id (positive integer) */

	char *file; /* filename (string) */

	time_t date; /* file access date - utc*/
	time_t time; /* file access time - utc*/

	int operation; /* access type values [0-3] */
	int action_denied; /* is action denied values [0-1] */

	char *filehash; /* file hash - sha256 - evp */

	/* add here other fields if necessary */
	/* ... */
	/* ... */

};


void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./audit_monitor \n"
		   "Options:\n"
		   "-s, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}


static int
is_event_written(const char *line)
{
	return strstr(line, "\"operation\":\"WRITTEN\"") != NULL;
}

static int
does_filename_match(const char *line, const char *filename)
{
	char parsed[2048];
	if (!parse_event_filename(line, parsed, sizeof(parsed))) return 0;
	return strcmp(parsed, filename) == 0;
}

static int
is_event_denied(const char *line)
{
	const char *p = strstr(line, "\"denied\":");
	if (!p) return 0;
	int denied;
	return sscanf(p, "\"denied\":%d", &denied) == 1 && denied;
}

static int
parse_event_uid(const char *line, unsigned int *uid)
{
	const char *p = strstr(line, "\"uid\":");
	if (!p) return 0;
	return sscanf(p, "\"uid\":%u", uid) == 1;
}

static int
parse_event_filename(const char *line, char *filename, size_t size)
{
	const char *p = strstr(line, "\"filename\":\"");
	if (!p) return 0;
	p += 12;
	size_t i = 0;
	while (*p && *p != '"' && i < size - 1)
		filename[i++] = *p++;
	filename[i] = '\0';
	return i > 0;
}

typedef char filename_t[2048];

#define DENIES_THRESHOLD 5
#define MAX_UID   65536

struct result_pair {
	filename_t files[DENIES_THRESHOLD];
	int count;
};

static int
is_pair_duplicate(struct result_pair *pair, const char *filename)
{
	for (int j = 0; j < pair->count; j++)
		if (strcmp(pair->files[j], filename) == 0)
			return 1;
	return 0;
}

static int
is_user_acc_maxed_out(struct pair *pair)
{
	return pair && pair->count >= DENIES_THRESHOLD;
}


void
list_unauthorized_accesses(FILE *log)
{
	struct result_pair **pairs_by_uid = calloc(MAX_UID, sizeof(*pairs_by_uid));
	if (!pairs_by_uid) return;

	char line[4096];
	while (fgets(line, sizeof(line), log)) {
		if (!is_event_denied(line)) continue;

		unsigned int uid;
		if (!parse_event_uid(line, &uid) || uid >= MAX_UID) continue;

		char filename[2048];
		if (!parse_event_filename(line, filename, sizeof(filename))) continue;

		if (is_user_acc_maxed_out(pairs_by_uid[uid])) continue;

		if (!pairs_by_uid[uid]) {
			pairs_by_uid[uid] = calloc(1, sizeof(struct result_pair));
			if (!pairs_by_uid[uid]) continue;
		}

		if (!is_pair_duplicate(pairs_by_uid[uid], filename)) {
			strncpy(pairs_by_uid[uid]->files[pairs_by_uid[uid]->count], filename, sizeof(filename_t) - 1);
			pairs_by_uid[uid]->count++;
		}
	}

	for (int uid = 0; uid < MAX_UID; uid++)
		if (pairs_by_uid[uid] && pairs_by_uid[uid]->count >= DENIES_THRESHOLD)
			printf("uid: %u denied_files: %d\n", uid, pairs_by_uid[uid]->count);

	for (int uid = 0; uid < MAX_UID; uid++)
		free(pairs_by_uid[uid]);
	free(pairs_by_uid);
}


void
list_file_modifications(FILE *log, char *file_to_scan)
{
	int *modifiers = calloc(MAX_UID, sizeof(int));
	if (!modifiers) return;

	char line[4096];
	while (fgets(line, sizeof(line), log)) {
		if (!is_event_written(line)) continue;
		if (!does_filename_match(line, file_to_scan)) continue;
		if (is_event_denied(line)) continue;

		unsigned int uid;
		if (!parse_event_uid(line, &uid) || uid >= MAX_UID) continue;

		modifiers[uid]++;
	}

	for (int uid = 0; uid < MAX_UID; uid++)
		if (modifiers[uid] > 0)
			printf("uid: %u modifications: %d\n", uid, modifiers[uid]);

	free(modifiers);
}


int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./access_audit.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./access_audit.log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:s")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 's':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
