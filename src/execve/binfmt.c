#include "execve/binfmt.h"
#include "execve/execve.h"
#include "execve/aoxp.h"
#include "tracee/reg.h"
#include "tracee/tracee.h"
#include "cli/cli.h"

#include <fcntl.h>
#include <linux/limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <talloc.h>
#include <errno.h>
#include <unistd.h>

BinfmtRule* rules = NULL;
int rules_number = 0;

int register_binfmt(const BinfmtRule* rule) {
	if (!rules) {
		rules = malloc(sizeof(BinfmtRule));
		if (!rules) {
			return -ENOMEM;
		}
	} else {
		BinfmtRule* new_rules = realloc(rules, sizeof(BinfmtRule) * (rules_number + 1));
		if (!new_rules) {
			return -ENOMEM;
		}
		rules = new_rules;
	}
	// Add the new rule to the array
	rules[rules_number++] = *rule;
	return 0;
}

int unregister_binfmt(const char *name) {
	if (!rules || rules_number == 0) {
		return -ENOENT;
	}
	for (int i = 0; i < rules_number; i++) {
		if (strcmp(rules[i].name, name) == 0) {
			// Found the rule, remove it
			for (int j = i; j < rules_number - 1; j++) {
				rules[j] = rules[j + 1];
			}
			rules_number--;
			return 0;
		}
	}
	return -ENOENT;
}

int read_binfmt_rules_from_file(const char *filepath) {
	FILE *file = fopen(filepath, "r");
	if (!file) {
		return -errno;
	}
	// Read file line by line
	char line[4096];
	while (fgets(line, sizeof(line), file)) {
		BinfmtRule rule;
		memset(&rule, 0, sizeof(BinfmtRule));
		// Parse line (:name:type:offset:magic:mask:interpreter:)
		if (sscanf(line, ":%255[^:]:%c:%zu:%255[^:]:%255[^:]:%255[^:]:", rule.name, &rule.type, &rule.offset, rule.magic, rule.mask, rule.interpreter) != 6) {
			continue;
		}
		// Register rule
		if (register_binfmt(&rule) < 0) {
			continue;
		}
	}
	fclose(file);
	return 0;
}

void clear_binfmt_rule_list() {
	free(rules);
	rules = NULL;
	rules_number = 0;
}

int check_binfmt(Tracee *tracee, char host_path[PATH_MAX], char user_path[PATH_MAX]) {
	ArrayOfXPointers *argv = NULL;
	bool has_matched = false;
	BinfmtRule* r = NULL;
	int status = 0;
	char* old_user_path = NULL;

	old_user_path = talloc_strdup(tracee->ctx, user_path);
	if (!old_user_path) {
		return -ENOMEM;
	}
	for (int i = 0; i < rules_number; i++) {
		r = &rules[i];
		if (r->type == 'E') {
			size_t path_len = strlen(user_path);
			size_t ext_len = strlen(r->magic);

			if (ext_len > path_len) continue;
			if (strcmp(user_path + path_len - ext_len, r->magic) == 0) {
				has_matched = true;
				break;
			}
		}
		if (r->type == 'M') {
			// Find last 1 in the mask
			size_t mask_size = 0;
			for (int k = PATH_MAX - 1; k >= 0; k--) {
				if (r->mask[k] != 0) {
					mask_size = k + 1;
					break;
				}
			}
			if (mask_size == 0) continue;
			// Read magic number from file
			char* magic = talloc_array(tracee->ctx, char, mask_size);
			if (!magic) {
				talloc_free(old_user_path);
				return -ENOMEM;
			}
			int fd = open(host_path, O_RDONLY);
			if (fd < 0) {
				talloc_free(old_user_path);
				talloc_free(magic);
				return -errno;
			}
			if (lseek(fd, r->offset, SEEK_SET) < 0) {
				close(fd);
				talloc_free(old_user_path);
				talloc_free(magic);
				return -errno;
			}
			ssize_t rr = read(fd, magic, mask_size);
			if (rr < 0) {
				close(fd);
				talloc_free(old_user_path);
				talloc_free(magic);
				return -errno;
			}
			if ((size_t)rr < mask_size) {
				/* Not enough bytes in file */
				talloc_free(magic);
				continue;
			}
			close(fd);
			// Apply mask and compare
			for (size_t j = 0; j < mask_size; j++) {
				magic[j] &= r->mask[j];
			}
			if (memcmp(magic, r->magic, mask_size) == 0) {
				has_matched = true;
				talloc_free(magic);
				break;
			}
			talloc_free(magic);
		}
	}

	if (has_matched) {
		// Rule matched, modify path and arguments

		// Note: The interpreter path is not tokenized;
		// the entire string is used as the interpreter path.
		strcpy(user_path, r->interpreter);
		status = translate_and_check_exec(tracee, host_path, user_path);
		if (status < 0) {
			talloc_free(old_user_path);
			return status;
		}
		// Fetch argv[] only on demand.
		if (argv == NULL) {
			status = fetch_array_of_xpointers(tracee, &argv, SYSARG_2, 0);
			if (status < 0) {
				talloc_free(old_user_path);
				return status;
			}
		}
		// Add interpreter to argv
		status = resize_array_of_xpointers(argv, 0, 1 + (argv->length == 1));
		if (status < 0) {
			talloc_free(old_user_path);
			return status;
		}
		status = write_xpointees(argv, 0, 2, user_path, old_user_path);
		if (status < 0) {
			talloc_free(old_user_path);
			return status;
		}

		// Push args
		status = push_array_of_xpointers(argv, SYSARG_2);
		if (status < 0) {
			talloc_free(old_user_path);
			return status;
		}

		talloc_free(old_user_path);
		return 1;
	}

	talloc_free(old_user_path);
	return 0;
}
