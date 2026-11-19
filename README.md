## Security - Assignment 3

Team 11
Giannakakos Alexandros-Michail
2007030027

## Requirements

```
$ sudo apt install gcc make libc6-dev libssl-dev
```

## Usage

```sh
$ make && make test

# or 

$ make clean && make && make test
```

## Configure

```sh
AUDIT_LOG_PATH=/some/custom/path # defaults to /tmp/access_audit.log

```

```sh
# `test_audit` runs as root; LD_PRELOAD could not find object with a relative path
$ sudo LD_PRELOAD=/home/ubuntu/assignment_3/audit_logger.so ./test_audit
created: /tmp/audit_restricted_1795059760_0.txt
...

$ ./audit_monitor -i /tmp/audit_restricted_1795059760_0.txt
uid: 60001 modifications: 2
uid: 60002 modifications: 2
uid: 60005 modifications: 1
total modifications: 5

$ ./audit_monitor -s 
uid: 60001 denied_files: 5
uid: 60004 denied_files: 5
uid: 60005 denied_files: 5


```

## General approach

- `LD_PRELOAD` caused the dynamic linker to load our shared library before libc. The process resolves symbols to their first occurrence, therefore our file operations effectively override the ones from the standard library.

- To get a reference to the standard functions we overrode, we use `libdl`. It allows us to find subsequent occurrences of the symbols we masked.

- Log events are represented as structs and serialized to plain JSON lines of the format `{"date":"2026-11-19","time":"03:42:40","pid":15791,"uid":60005,"filename":"/tmp/audit_accessible_1795059760_3.txt","operation":"WRITTEN","denied":0,"file_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`



## Comments

1. I'm on Apple M1, so this project was written, tested and verified on an EC2 instance running Ubuntu 26.04.1 LTS ("Resolute"), kernel 7.0.0-1016-aws. I decided against containerizing. I hope it runs well.

2. A file operation receiving EACCES will not attempt to hash the file it could not open. The field is left empty.

3. `test_libauditlog.c` contains unit tests for file operations. There's nothing too interesting there, but they get a little integration-testy to cover serialization without adding layers of testing. To maintain isolation however, these tests run against files in the project tree. They can be cleaned with `make clean`, but any intermediate artifacts are also cleaned up in teardown hooks. When it comes to testing serialized outputs, I naively cover existence of certain fields in logged events, and some rough type validation with regular expressions: values may look like strings or like numbers. That level of testing should be enough anyway.

4. Unit tests make use of an environment variable `AUDIT_LOG_BYPASS` to selectively override file operations under test as opposed to file operations required in the setup and teardown of tests themselves.

5. In `audit_monitor` things are relatively straightforward. To make my life easier and avoid excessive looping, I wrote a naive array-based hash map. Considering that our aggregation key is the UID, and we can only have 65536 distinct values for those, we can simply allocate an array upfront for all of them. Nested arrays are allocated dynamically as needed, so this is a very sparse array. It gives us elegant lookups with a small memory overhead.

6. To avoid having predetermined test cases in `test_audit`, I relied on randomness. I configure certain pools of objects (worker processes, UIDs, PIDs, etc), and parameterize action objects by flipping a coin for nearly every parameter. This makes it easy to scale tests up and down as needed.

7. The RNG is seeded with a combination of PID and timestamp to avoid conflicts across runs and to ensure different workers use different seeds.

8. To randomly draw values from an enum, I use a sentinel value to track the enum size.

9. For easy copy-paste to the log analyzer tool, artifacts created in `test_audit` are printed to STDOUT.

10. In order to call `setuid()` on a process, we need to run `test_audit` as root. This has some downstream effects on file permissions, Makefile plumbing, etc. For the most part the instructions above have been tested, but when in doubt, run as root please.

11. Permissions are set accordingly to simulate access control failures. A set of restricted files is guaranteed to fail with EACCES when accessed by any worker process. In addition, workers may end up creating files of their own that will also set EACCES when accessed by other PIDs.

12. The testrunner dispatches actions to workers via pipes. Communication is one-way. A worker executes the action and blocks again waiting for the next. 

13. I considered adding "malicious mode" whereby a worker might randomly choose to repeatedly attempt restricted access. But tests already work well enough due to good uniformity.

14. In fact I tried to break that uniformity a little bit to simulate uneven workloads from different users or processes. It didn't succeed much and I didn't pursue it further.

15. Somewhat unnecessary but I added a crude ticker that reports progress to STDOUT every 5 seconds. Tests are much, much faster than that. I only added it for test runs with very large numbers of files and running objects that may face compounding delays. The only purpose is to make waiting more responsive.
