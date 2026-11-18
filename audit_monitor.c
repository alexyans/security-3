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

struct pair { unsigned int uid; char file[2048]; };
struct uid_state { unsigned int uid; int count; };

#define THRESHOLD 5

static int
is_duplicate_pair(struct pair *pairs, int n, unsigned int uid, const char *filename)
{
	for (int j = 0; j < n; j++)
		if (pairs[j].uid == uid && strcmp(pairs[j].file, filename) == 0)
			return 1;
	return 0;
}

static int
are_user_pairs_maxed(struct uid_state *states, int n, unsigned int uid)
{
	for (int i = 0; i < n; i++)
		if (states[i].uid == uid) return states[i].count >= THRESHOLD;
	return 0;
}


void
list_unauthorized_accesses(FILE *log)
{
#define MAX_PAIRS 65536
	struct pair *pairs = malloc(MAX_PAIRS * sizeof(*pairs));
	if (!pairs) return;
	int n = 0;

	struct uid_state uid_states[1024];
	int uid_states_n = 0;

	char line[4096];
	while (fgets(line, sizeof(line), log)) {
		if (!is_event_denied(line)) continue;

		unsigned int uid;
		if (!parse_event_uid(line, &uid)) continue;

		char filename[2048];
		if (!parse_event_filename(line, filename, sizeof(filename))) continue;

		if (are_user_pairs_maxed(uid_states, uid_states_n, uid)) continue;

		if (!is_duplicate_pair(pairs, n, uid, filename) && n < MAX_PAIRS) {
			pairs[n].uid = uid;
			strncpy(pairs[n].file, filename, sizeof(pairs[n].file) - 1);
			n++;

			int found = 0;
			for (int j = 0; j < uid_states_n; j++)
				if (uid_states[j].uid == uid) { uid_states[j].count++; found = 1; break; }
			if (!found && uid_states_n < 1024) {
				uid_states[uid_states_n].uid = uid;
				uid_states[uid_states_n].count = 1;
				uid_states_n++;
			}
		}
	}

	for (int i = 0; i < uid_states_n; i++)
		if (uid_states[i].count >= THRESHOLD)
			printf("uid=%u denied_files=%d\n", uid_states[i].uid, uid_states[i].count);

	free(pairs);
#undef MAX_PAIRS
}


void
list_file_modifications(FILE *log, char *file_to_scan)
{

	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */

	return;

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
