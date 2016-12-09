/*
 * check_password.c for OpenLDAP
 *
 * See LICENSE, README and INSTALL files
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <portable.h>
#include <slap.h>

#ifdef HAVE_CRACKLIB
#include <crack.h>
#endif

#if defined(DEBUG)
#include <syslog.h>
#endif

#ifndef CRACKLIB_DICTPATH
#define CRACKLIB_DICTPATH "/usr/share/cracklib/pw_dict"
#endif

#ifndef CONFIG_FILE
#define CONFIG_FILE "/etc/openldap/check_password.conf"
#endif

#define DEFAULT_QUALITY  3
#define DEFAULT_CRACKLIB 1
#define MEMORY_MARGIN    50
#define MEM_INIT_SZ      64
#define FILENAME_MAXLEN  512

#define PASSWORD_TOO_SHORT_SZ \
  "Password for dn=\"%s\" is too short (%d/6)"
#define PASSWORD_QUALITY_SZ \
  "Password for dn=\"%s\" does not pass required number of strength checks (%d of %d)"
#define BAD_PASSWORD_SZ \
  "Bad password for dn=\"%s\" because %s"

int check_password (char *pPasswd, char **ppErrStr, Entry *pEntry);
