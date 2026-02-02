/*
 *
 * A simple program that generates a blank keytab in a deterministic location.
 *
 * It should be SETUID(3p) root or have the right CAPABILITIES(7).
 *
 */
#include "autoconf.h" /* for our automatic config bits        */
/*

   Copyright 2023 Fermi Research Alliance, LLC

   This software was produced under U.S. Government contract DE-AC02-07CH11359
   for Fermi National Accelerator Laboratory (Fermilab), which is operated by
   Fermi Research Alliance, LLC for the U.S. Department of Energy. The U.S.
   Government has rights to use, reproduce, and distribute this software.
   NEITHER THE GOVERNMENT NOR FERMI RESEARCH ALLIANCE, LLC MAKES ANY WARRANTY,
   EXPRESS OR IMPLIED, OR ASSUMES ANY LIABILITY FOR THE USE OF THIS SOFTWARE.
   If software is modified to produce derivative works, such modified software
   should be clearly marked, so as not to confuse it with the version available
   from Fermilab.

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR FERMI RESEARCH ALLIANCE, LLC BE LIABLE FOR ANY CLAIM, DAMAGES OR
   OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
   IN THE SOFTWARE.

*/

#ifndef __PROGRAM_NAME
#define __PROGRAM_NAME "init-kcron-keytab"
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "kcron_caps.h"
#include "kcron_empty_keytab_file.h"
#include "kcron_filename.h"
#include "kcron_setup.h"

#ifndef _0600
#define _0600 (S_IRUSR | S_IWUSR)
#endif
#ifndef _0700
#define _0700 (S_IRWXU)
#endif

static inline int mkdir_if_missing(const char *dir, uid_t owner, gid_t group, mode_t mode) __attribute__((access(read_only, 1))) __attribute__((warn_unused_result));
static inline int mkdir_if_missing(const char *dir, uid_t owner, gid_t group, mode_t mode) {
  const cap_value_t caps[] = {CAP_CHOWN, CAP_DAC_OVERRIDE};
  const int num_caps = sizeof(caps) / sizeof(cap_value_t);

  struct stat st = {0};
  struct stat lst = {0};

  if (dir == NULL) {
    /* nothing to do - no dir passed */
    return 0;
  }

  /* Check for symlink to prevent TOCTOU symlink attacks */
  if (lstat(dir, &lst) == 0) {
    if (S_ISLNK(lst.st_mode)) {
      (void)fprintf(stderr, "%s: %s is a symlink, not allowed.\n", __PROGRAM_NAME, dir);
      return 1;
    }
  }

  if (stat(dir, &st) == 0) {
    /* exists */
    if (S_ISDIR(st.st_mode)) {
      /* and is a directory */
      return 0;
    } else {
      /* whatever this is, it is not a directory */
      (void)fprintf(stderr, "%s: %s is not a directory.\n", __PROGRAM_NAME, dir);
      return 1;
    }
  }

  if (enable_capabilities(caps, num_caps) != 0) {
    (void)fprintf(stderr, "%s: Cannot enable capabilities.\n", __PROGRAM_NAME);
    return 1;
  }

  /* use of CAP_DAC_OVERRIDE to bypass discretionary access controls for mkdir */
  if (mkdir(dir, mode) != 0) {
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: Unable to mkdir %s\n", __PROGRAM_NAME, dir);
    return 1;
  }

  /* use of CAP_DAC_OVERRIDE as we might not be able to write to dir */
  DIR *my_dir = opendir(dir);
  if (my_dir == NULL) {
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: Unable to locate %s ?\n", __PROGRAM_NAME, dir);
    (void)fprintf(stderr, "%s: This may be a permissions error?\n", __PROGRAM_NAME);
    return 1;
  }

  /* use of CAP_DAC_OVERRIDE as we might not be able to list dir */
  if (fstat(dirfd(my_dir), &st) != 0) {
    (void)closedir(my_dir);
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: %s could not be created.\n", __PROGRAM_NAME, dir);
    (void)fprintf(stderr, "%s: This may be a permissions error?\n", __PROGRAM_NAME);
    return 1;
  }

  disable_capabilities();

  if (!S_ISDIR(st.st_mode)) {
    (void)closedir(my_dir);
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: %s is not a directory.\n", __PROGRAM_NAME, dir);
    return 1;
  }

  if (enable_capabilities(caps, num_caps) != 0) {
    (void)fprintf(stderr, "%s: Cannot enable capabilities.\n", __PROGRAM_NAME);
    return 1;
  }

  /* use of CAP_CHOWN to change ownership of the directory */
  if (fchown(dirfd(my_dir), owner, group) != 0) {
    (void)closedir(my_dir);
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: Unable to chown %i:%i %s\n", __PROGRAM_NAME, owner, group, dir);
    (void)fprintf(stderr, "%s: This may be a permissions error?\n", __PROGRAM_NAME);
    return 1;
  }

  disable_capabilities();

  (void)closedir(my_dir);
  return 0;
}

static inline int chown_chmod_keytab(int filedescriptor, const char *keytab) __attribute__((access(read_only, 2))) __attribute__((warn_unused_result));
static inline int chown_chmod_keytab(int filedescriptor, const char *keytab) {

  const cap_value_t keytab_caps[] = {CAP_CHOWN, CAP_DAC_OVERRIDE};
  const int num_caps = sizeof(keytab_caps) / sizeof(cap_value_t);

  const uid_t uid = getuid();
  const gid_t gid = getgid();

  struct stat st = {0};

  if (filedescriptor == 0) {
    (void)fprintf(stderr, "%s: Invalid file %s.\n", __PROGRAM_NAME, keytab);
    return 1;
  }

  if (enable_capabilities(keytab_caps, num_caps) != 0) {
    (void)fprintf(stderr, "%s: Cannot enable capabilities.\n", __PROGRAM_NAME);
    return 1;
  }

  /* use of CAP_DAC_OVERRIDE to bypass access checks for fstat on keytab file */
  if (fstat(filedescriptor, &st) != 0) {
    (void)fprintf(stderr, "%s: Cannot stat file %s.\n", __PROGRAM_NAME, keytab);
    (void)disable_capabilities();
    return 1;
  }

  disable_capabilities();

  if (!S_ISREG(st.st_mode)) {
    (void)fprintf(stderr, "%s: %s is not a regular file.\n", __PROGRAM_NAME, keytab);
    return 1;
  }

  /* ensure permissions are as expected on keytab file */
  /* no capabilities required for fchmod, we already own it */
  if (fchmod(filedescriptor, _0600) != 0) {
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: Unable to chmod %o %s\n", __PROGRAM_NAME, _0600, keytab);
    return 1;
  }

  /* Set the right owner of our keytab */
  /* Don't switch euid to uid as that may permit write to program memory */
  if (st.st_uid != uid || st.st_gid != gid) {
    if (enable_capabilities(keytab_caps, num_caps) != 0) {
      (void)fprintf(stderr, "%s: Cannot enable capabilities.\n", __PROGRAM_NAME);
      return 1;
    }

    /* use of CAP_CHOWN to set ownership of the keytab file */
    if (fchown(filedescriptor, uid, gid) != 0) {
      (void)disable_capabilities();
      (void)fprintf(stderr, "%s: Unable to chown %d:%d %s\n", __PROGRAM_NAME, uid, gid, keytab);
      return 1;
    }

    disable_capabilities();
  }

  return 0;
}

static inline void free_buffers(char *keytab, char *keytab_dirname, char *keytab_filename, char *client_keytab_dirname);
static inline void free_buffers(char *keytab, char *keytab_dirname, char *keytab_filename, char *client_keytab_dirname) {
  if (keytab != NULL) {
    (void)free(keytab);
  }
  if (keytab_dirname != NULL) {
    (void)free(keytab_dirname);
  }
  if (keytab_filename != NULL) {
    (void)free(keytab_filename);
  }
  if (client_keytab_dirname != NULL) {
    (void)free(client_keytab_dirname);
  }
}

static int validate_client_dirname(char *client_keytab_dirname) __attribute__((warn_unused_result));
static int validate_client_dirname(char *client_keytab_dirname) {
  struct stat lst = {0};
  struct stat st = {0};

  if (client_keytab_dirname == NULL) {
    (void)fprintf(stderr, "%s: Client keytab directory pointer is NULL.\n", __PROGRAM_NAME);
    return 1;
  }

  /* Check symlink on client_keytab_dirname before stat */
  if (lstat(client_keytab_dirname, &lst) != 0) {
    (void)fprintf(stderr, "%s: Client keytab directory does not exist: %s.\n", __PROGRAM_NAME, client_keytab_dirname);
    (void)fprintf(stderr, "%s: Contact your admin to have it created correctly.\n", __PROGRAM_NAME);
    return 1;
  }
  if (S_ISLNK(lst.st_mode)) {
    (void)fprintf(stderr, "%s: Client keytab directory %s is a symlink, not allowed.\n", __PROGRAM_NAME, client_keytab_dirname);
    return 1;
  }

  if (stat(client_keytab_dirname, &st) == -1) {
    (void)fprintf(stderr, "%s: Client keytab directory does not exist: %s.\n", __PROGRAM_NAME, client_keytab_dirname);
    (void)fprintf(stderr, "%s: Contact your admin to have it created.\n", __PROGRAM_NAME);
    return 1;
  }
  return 0;
}

static int create_keytab_file(const char *keytab_dirname, const char *keytab_filename, const char *keytab) __attribute__((warn_unused_result));
static int create_keytab_file(const char *keytab_dirname, const char *keytab_filename, const char *keytab) {
  struct stat st = {0};
  struct stat lst = {0};
  DIR *keytab_dir = NULL;
  int filedescriptor = -1;

  const cap_value_t caps[] = {CAP_DAC_OVERRIDE};
  const int num_caps = sizeof(caps) / sizeof(cap_value_t);

  /* Validate non-null input pointers */
  if (keytab_dirname == NULL) {
    (void)fprintf(stderr, "%s: keytab_dirname pointer is NULL.\n", __PROGRAM_NAME);
    return 1;
  }
  if (keytab_filename == NULL) {
    (void)fprintf(stderr, "%s: keytab_filename pointer is NULL.\n", __PROGRAM_NAME);
    return 1;
  }
  if (keytab == NULL) {
    (void)fprintf(stderr, "%s: keytab pointer is NULL.\n", __PROGRAM_NAME);
    return 1;
  }

  /* enable CAP_DAC_OVERRIDE to bypass permission checks temporarily for
   * directory access and file creation.
   * This capability is used only around operations that need it and dropped immediately after.
   */
  if (enable_capabilities(caps, num_caps) != 0) {
    (void)fprintf(stderr, "%s: Cannot enable capabilities.\n", __PROGRAM_NAME);
    return 1;
  }

  /* Check if keytab_dirname exists and is not a symlink (to avoid TOCTOU symlink attacks) */
  if (lstat(keytab_dirname, &lst) != 0) {
    (void)fprintf(stderr, "%s: %s does not exist.\n", __PROGRAM_NAME, keytab_dirname);
    (void)disable_capabilities();
    return 1;
  }
  if (S_ISLNK(lst.st_mode)) {
    (void)fprintf(stderr, "%s: %s is a symlink, not allowed.\n", __PROGRAM_NAME, keytab_dirname);
    (void)disable_capabilities();
    return 1;
  }

  /* Open the directory handle to perform file operations safely on the directory inode */
  keytab_dir = opendir(keytab_dirname);
  if (keytab_dir == NULL) {
    (void)fprintf(stderr, "%s: Unable to locate %s ?\n", __PROGRAM_NAME, keytab_dirname);
    (void)fprintf(stderr, "%s: This may be a permissions error?\n", __PROGRAM_NAME);
    (void)disable_capabilities();
    return 1;
  }

  /* Verify the opened directory is indeed a directory */
  if (fstat(dirfd(keytab_dir), &st) != 0) {
    (void)fprintf(stderr, "%s: %s could not be read.\n", __PROGRAM_NAME, keytab_dirname);
    (void)closedir(keytab_dir);
    (void)disable_capabilities();
    return 1;
  }

  (void)disable_capabilities();

  if (!S_ISDIR(st.st_mode)) {
    (void)fprintf(stderr, "%s: %s is not a directory.\n", __PROGRAM_NAME, keytab_dirname);
    (void)closedir(keytab_dir);
    (void)disable_capabilities();
    return 1;
  }

  /* Open the keytab file with O_NOFOLLOW to prevent symlink attacks,
   * O_CREAT to create if missing, and O_CLOEXEC for descriptor safety.
   * Permissions set to 0600 for security.
   */
  filedescriptor = openat(dirfd(keytab_dir), keytab_filename, O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, _0600);
  if (filedescriptor < 0) {
    (void)closedir(keytab_dir);
    (void)fprintf(stderr, "%s: %s is missing, cannot create: %s\n", __PROGRAM_NAME, keytab, strerror(errno));
    return 1;
  }
  (void)closedir(keytab_dir);

  /* Verify that the created file is a regular file */
  if (fstat(filedescriptor, &st) != 0) {
    (void)close(filedescriptor);
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: %s could not be created.\n", __PROGRAM_NAME, keytab);
    return 1;
  }
  if (!S_ISREG(st.st_mode)) {
    (void)close(filedescriptor);
    (void)disable_capabilities();
    (void)fprintf(stderr, "%s: %s is not a regular file.\n", __PROGRAM_NAME, keytab);
    return 1;
  }

  /* Write empty keytab content to the file */
  if (write_empty_keytab(filedescriptor) != 0) {
    (void)close(filedescriptor);
    (void)fprintf(stderr, "%s: Cannot create keytab : %s.\n", __PROGRAM_NAME, keytab);
    return 1;
  }

  /* Set ownership and permission on the keytab file */
  if (chown_chmod_keytab(filedescriptor, keytab) != 0) {
    (void)close(filedescriptor);
    (void)fprintf(stderr, "%s: Cannot set permissions on keytab : %s.\n", __PROGRAM_NAME, keytab);
    return 1;
  }

  (void)close(filedescriptor);
  return 0;
}

void constructor(void) __attribute__((constructor));
void constructor(void) {
  /* Setup runtime hardening /before/ main() is even called */
  (void)harden_runtime();
}

int main(void) {
  struct stat st = {0};

  const cap_value_t caps[] = {CAP_DAC_OVERRIDE};
  const int num_caps = sizeof(caps) / sizeof(cap_value_t);

  const uid_t uid = getuid();
  const gid_t gid = getgid();

  char *keytab = calloc(FILE_PATH_MAX_LENGTH + 3, sizeof(char));
  char *keytab_dirname = calloc(FILE_PATH_MAX_LENGTH + 3, sizeof(char));
  char *keytab_filename = calloc(FILE_PATH_MAX_LENGTH + 3, sizeof(char));
  char *client_keytab_dirname = calloc(FILE_PATH_MAX_LENGTH + 3, sizeof(char));

  if ((keytab == NULL) || (keytab_dirname == NULL) || (keytab_filename == NULL) || (client_keytab_dirname == NULL)) {
    (void)free_buffers(keytab, keytab_dirname, keytab_filename, client_keytab_dirname);
    (void)fprintf(stderr, "%s: Unable to allocate memory.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  if (get_client_dirname(client_keytab_dirname) != 0) {
    (void)free_buffers(keytab, keytab_dirname, keytab_filename, client_keytab_dirname);
    (void)fprintf(stderr, "%s: Client keytab directory not set.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  if (validate_client_dirname(client_keytab_dirname) != 0) {
    (void)free_buffers(keytab, keytab_dirname, keytab_filename, client_keytab_dirname);
    exit(EXIT_FAILURE);
  }

  if (get_filenames(keytab_dirname, keytab_filename, keytab) != 0) {
    (void)free_buffers(keytab, keytab_dirname, keytab_filename, client_keytab_dirname);
    (void)fprintf(stderr, "%s: Cannot determine keytab filename.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  if (mkdir_if_missing(keytab_dirname, uid, gid, _0700) != 0) {
    (void)free_buffers(keytab, keytab_dirname, keytab_filename, client_keytab_dirname);
    (void)fprintf(stderr, "%s: Cannot make dir %s.\n", __PROGRAM_NAME, keytab_dirname);
    exit(EXIT_FAILURE);
  }

  /* use of CAP_DAC_OVERRIDE as we may not be able to chdir otherwise   */
  if (enable_capabilities(caps, num_caps) != 0) {
    (void)free_buffers(keytab, keytab_dirname, keytab_filename, client_keytab_dirname);
    (void)fprintf(stderr, "%s: Cannot enable capabilities.\n", __PROGRAM_NAME);
    exit(EXIT_FAILURE);
  }

  int stat_code = stat(keytab, &st);

  disable_capabilities();

  /* create keytab if missing */
  if (stat_code == -1) {
    if (create_keytab_file(keytab_dirname, keytab_filename, keytab) != 0) {
      (void)free_buffers(keytab, keytab_dirname, keytab_filename, client_keytab_dirname);
      exit(EXIT_FAILURE);
    }
  }

  (void)printf("%s\n", keytab);

  (void)free_buffers(keytab, keytab_dirname, keytab_filename, client_keytab_dirname);

  exit(EXIT_SUCCESS);
}
