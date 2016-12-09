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
  "Password for dn=\"%s\" does not pass required number of strength checks for the required character sets (%d of %d)"
#define BAD_PASSWORD_SZ \
	"Bad password for dn=\"%s\" because %s"
#define CONSEC_FAIL_SZ \
  "Too many consecutive characters in the same character class for dn=\"%s\""
#define UNKNOWN_ERROR_SZ \
  "An unknown error occurred, please see your systems administrator"

typedef int (*validator) (char*);
static int read_config_file ();
static validator valid_word (char *);
static int set_quality (char *);
static int set_cracklib (char *);

int check_password (char *pPasswd, char **ppErrStr, Entry *pEntry);

struct config_entry {
  char* key;
  char* value;
  char* def_value;
} config_entries[] = { { "min_points", NULL, "3"},
    { "use_cracklib", NULL, "1"},
    { "min_upper", NULL, "0"},
    { "min_lower", NULL, "0"},
    { "min_digit", NULL, "0"},
    { "min_punct", NULL, "0"},
    { "max_consecutive_per_class", NULL, "5"},
    { NULL, NULL, NULL }};

int print_config_entries() {
  struct config_entry* centry = config_entries;

  printf("Printing Config Entries:\n");

  int i = 0;
  char* key = centry[i].key;
  while (key != NULL) {
    printf("Config Entry: %s => %s\n", key, centry[i].value);
    i++;
    key = centry[i].key;
  }

  printf("End Config Entries:\n");

  return 0;
}

int get_config_entry_int(char* entry) {
  struct config_entry* centry = config_entries;

  int i = 0;
  char* key = centry[i].key;
   while (key != NULL) {
    if ( strncmp(key, entry, strlen(key)) == 0 ) {
      if ( centry[i].value == NULL ) {
        return atoi(centry[i].def_value);
      }
      else {
        return atoi(centry[i].value);
      }
    }
    i++;
    key = centry[i].key;
  }

  return -1;
}

void dealloc_config_entries() {
  struct config_entry* centry = config_entries;

  int i = 0;
  while (centry[i].key != NULL) {
    if ( centry[i].value != NULL ) {
      ber_memfree(centry[i].value);
    }
    i++;
  }
}

char* chomp(char *s)
{
  char* t = ber_memalloc(strlen(s)+1);
  strncpy (t,s,strlen(s)+1);

  if ( t[strlen(t)-1] == '\n' ) {
    t[strlen(t)-1] = '\0';
  }

  return t;
}

static int set_quality (char *value)
{
#if defined(DEBUG)
	syslog(LOG_NOTICE, "check_password: Setting quality to [%s]", value);
#endif
#if defined(LDEBUG)
  char* msg = chomp(value);
  printf("check_password: Setting quality to [%s]\n", msg);
  ber_memfree(msg);
#endif

	/* No need to require more quality than we can check for. */
	if (!isdigit(*value) || (int) (value[0] - '0') > 4) return DEFAULT_QUALITY;
	return (int) (value[0] - '0');

}

static int set_cracklib (char *value)
{
#if defined(DEBUG)
	syslog(LOG_NOTICE, "check_password: Setting cracklib usage to [%s]", value);
#endif
#if defined(LDEBUG)
  char* msg = chomp(value);
  printf("check_password: Setting cracklib usage to [%s]\n", msg);
  ber_memfree(msg);
#endif


	return (int) (value[0] - '0');

}

static int set_digit (char *value)
{
#if defined(DEBUG)
	syslog(LOG_NOTICE, "check_password: Setting parameter to [%s]", value);
#endif
#if defined(LDEBUG)
  char* msg = chomp(value);
  printf("check_password: Setting parameter to [%s]\n", msg);
  ber_memfree(msg);
#endif
	if (!isdigit(*value) || (int) (value[0] - '0') > 9) return 0;
	return (int) (value[0] - '0');
}

static validator valid_word (char *word)
{
	struct {
		char * parameter;
		validator dealer;
	} list[] = { { "min_points", set_quality },
		{ "use_cracklib", set_cracklib },
		{ "min_upper", set_digit },
		{ "min_lower", set_digit },
		{ "min_digit", set_digit },
		{ "min_punct", set_digit },
    { "max_consecutive_per_class", set_digit},
		{ NULL, NULL } };
	int index = 0;

#if defined(DEBUG)
	syslog(LOG_NOTICE, "check_password: Validating parameter [%s]", word);
#endif
#if defined(LDEBUG)
  char* msg = chomp(word);
  printf("check_password: Validating parameter [%s]\n", msg);
  ber_memfree(msg);
#endif

	while (list[index].parameter != NULL) {
		if (strlen(word) == strlen(list[index].parameter) &&
				strcmp(list[index].parameter, word) == 0) {
#if defined(DEBUG)
			syslog(LOG_NOTICE, "check_password: Parameter accepted.");
#endif
#if defined(LDEBUG)
			printf("check_password: Parameter accepted.\n");
#endif
			return list[index].dealer;
		}
		index++;
	}

#if defined(DEBUG)
	syslog(LOG_NOTICE, "check_password: Parameter rejected.");
#endif
#if defined(LDEBUG)
	printf("check_password: Parameter rejected.\n");
#endif

	return NULL;
}

static int read_config_file ()
{
	FILE * config;
	char * line;
	int returnValue =  -1;

  line = ber_memcalloc(260, sizeof(char));

  if ( line == NULL ) {
    return returnValue;
  }

	if ( (config = fopen(CONFIG_FILE, "r")) == NULL) {
#if defined(DEBUG)
		syslog(LOG_ERR, "check_password: Opening file %s failed", CONFIG_FILE);
#endif
#if defined(LDEBUG)
  printf("check_password: Opening file %s failed\n", CONFIG_FILE);
#endif

		ber_memfree(line);
		return returnValue;
	}

  returnValue = 0;

  while (fgets(line, 256, config) != NULL) {
    char *start = line;
    char *word, *value;
    validator dealer;

#if defined(DEBUG)
    /* Debug traces to syslog. */
    syslog(LOG_NOTICE, "check_password: Got line |%s|", line);
#endif
#if defined(LDEBUG)
    /* Debug traces. */
    char* msg = chomp(line);
    printf("check_password: Got line |%s|\n", msg);
    ber_memfree(msg);
#endif

    while (isspace(*start) && isascii(*start)) start++;

    /* If we've got punctuation, just skip the line. */
    if ( ispunct(*start)) {
#if defined(DEBUG)
    /* Debug traces to syslog. */
    syslog(LOG_NOTICE, "check_password: Skipped line |%s|", line);
#endif
#if defined(LDEBUG)
    /* Debug traces. */
    char* msg = chomp(line);
    printf("check_password: Skipped line |%s|\n", msg);
    ber_memfree(msg);
#endif
      continue;
    }

    if( isascii(*start)) {

      struct config_entry* centry = config_entries;
      int i = 0;
      char* keyWord = centry[i].key;
      if ((word = strtok(start, " \t")) && (value = strtok(NULL, " \t"))) {
        while ( keyWord != NULL ) {
          if ((strncmp(keyWord,word,strlen(keyWord)) == 0) && (dealer = valid_word(word)) ) {

#if defined(DEBUG)
            syslog(LOG_NOTICE, "check_password: Word = %s, value = %s", word, value);
#endif
#if defined(LDEBUG)
            printf("check_password: Word = %s, value = %s\n", word, value);
#endif

            centry[i].value = chomp(value);
            break;
          }
          i++;
          keyWord = centry[i].key;
        }
      }
    }
  }
	fclose(config);
	ber_memfree(line);

  return returnValue;
}

static int realloc_error_message (char ** target, int curlen, int nextlen)
{
	if (curlen < nextlen + MEMORY_MARGIN) {
#if defined(DEBUG)
		syslog(LOG_WARNING, "check_password: Reallocating szErrStr from %d to %d",
				curlen, nextlen + MEMORY_MARGIN);
#endif
#if defined(LDEBUG)
  printf("check_password: Reallocating szErrStr from %d to %d\n",
				curlen, nextlen + MEMORY_MARGIN);
#endif
		ber_memfree(*target);
		curlen = nextlen + MEMORY_MARGIN;
		*target = (char *) ber_memalloc(curlen);
	}

	return curlen;
}

	int
check_password (char *pPasswd, char **ppErrStr, Entry *pEntry)
{

	char *szErrStr = (char *) ber_memalloc(MEM_INIT_SZ);
	int  mem_len = MEM_INIT_SZ;

	int nLen;
	int nLower = 0;
	int nUpper = 0;
	int nDigit = 0;
	int nPunct = 0;
	int min_lower = 0;
	int min_upper = 0;
	int min_digit = 0;
	int min_punct = 0;
  int max_consecutive_per_class = 0;
	int nQuality = 0;
	int i;

	/* Set a sensible default to keep original behaviour. */
	int min_quality = DEFAULT_QUALITY;
	int use_cracklib = DEFAULT_CRACKLIB;

	/** bail out early as cracklib will reject passwords shorter
	 * than 6 characters
	 */

	nLen = strlen (pPasswd);
	if ( nLen < 6) {
		mem_len = realloc_error_message(&szErrStr, mem_len,
				strlen(PASSWORD_TOO_SHORT_SZ) +
				strlen(pEntry->e_name.bv_val) + 1);
		sprintf (szErrStr, PASSWORD_TOO_SHORT_SZ, pEntry->e_name.bv_val, nLen);
		goto fail;
	}

  if (read_config_file() == -1) {
    syslog(LOG_ERR, "Warning: Could not read values from config file %s. Using defaults.", CONFIG_FILE);
#if defined(LDEBUG)
    printf("Error: Could not read values from config file %s\n", CONFIG_FILE);
#endif
  }

#if defined(LDEBUG) || defined(DEBUG)
  print_config_entries();
#endif

	min_quality = get_config_entry_int("min_points");
	use_cracklib = get_config_entry_int("use_cracklib");
	min_upper = get_config_entry_int("min_upper");
	min_lower = get_config_entry_int("min_lower");
	min_digit = get_config_entry_int("min_digit");
	min_punct = get_config_entry_int("min_punct");
  max_consecutive_per_class = get_config_entry_int("max_consecutive_per_class");

  /* Check Max Consecutive Per Class first since this has the most likelihood
   * of being wrong.
   */

  if ( max_consecutive_per_class != 0 ) {
    int consec_chars = 1;
    char type[10] = "unkown";
    char prev_type[10] = "unknown";
    for ( i = 0; i < nLen; i++ ) {

      if ( islower(pPasswd[i]) ) {
        strncpy(type,"lower",10);
      }
      else if ( isupper(pPasswd[i]) ) {
        strncpy(type,"upper",10);
      }
      else if ( isdigit(pPasswd[i]) ) {
        strncpy(type,"digit",10);
      }
      else if ( ispunct(pPasswd[i]) ) {
        strncpy(type,"punct",10);
      }
      else {
        strncpy(type,"unknown",10);
      }

      if ( consec_chars > max_consecutive_per_class ) {
				mem_len = realloc_error_message(&szErrStr, mem_len,
						strlen(CONSEC_FAIL_SZ) +
						strlen(pEntry->e_name.bv_val));
				sprintf (szErrStr, CONSEC_FAIL_SZ, pEntry->e_name.bv_val);
				goto fail;
      }

      if ( strncmp(type,prev_type,10) == 0 ) {
        consec_chars++;
      }
      else {
        if (strncmp("unknown",prev_type,8) != 0) {
          consec_chars = 1;
        }
        else {
          consec_chars++;
        }
        strncpy(prev_type,type,10);
      }
    }
  }

	/** The password must have at least min_quality strength points with one
	 * point for the first occurrance of a lower, upper, digit and
	 * punctuation character
	 */

	for ( i = 0; i < nLen; i++ ) {

		//if ( nQuality >= min_quality ) break;

		if ( islower (pPasswd[i]) ) {
			min_lower--;
			if ( !nLower && (min_lower < 1)) {
				nLower = 1; nQuality++;
#if defined(DEBUG)
				syslog(LOG_NOTICE, "check_password: Found lower character - quality raise %d", nQuality);
#endif
#if defined(LDEBUG)
  printf("check_password: Found lower character - quality raise %d\n", nQuality);
#endif
			}
			continue;
		}

		if ( isupper (pPasswd[i]) ) {
			min_upper--;
			if ( !nUpper && (min_upper < 1)) {
				nUpper = 1; nQuality++;
#if defined(DEBUG)
				syslog(LOG_NOTICE, "check_password: Found upper character - quality raise %d", nQuality);
#endif
#if defined(LDEBUG)
  printf("check_password: Found upper character - quality raise %d\n", nQuality);
#endif
			}
			continue;
		}

		if ( isdigit (pPasswd[i]) ) {
			min_digit--;
			if ( !nDigit && (min_digit < 1)) {
				nDigit = 1; nQuality++;
#if defined(DEBUG)
				syslog(LOG_NOTICE, "check_password: Found digit character - quality raise %d", nQuality);
#endif
#if defined(LDEBUG)
  printf("check_password: Found digit character - quality raise %d\n", nQuality);
#endif
			}
			continue;
		}

		if ( ispunct (pPasswd[i]) ) {
			min_punct--;
			if ( !nPunct && (min_punct < 1)) {
				nPunct = 1; nQuality++;
#if defined(DEBUG)
				syslog(LOG_NOTICE, "check_password: Found punctuation character - quality raise %d", nQuality);
#endif
#if defined(LDEBUG)
  printf("check_password: Found punctuation character - quality raise %d\n", nQuality);
#endif
			}
			continue;
		}
	}

  /*
   * If you have a required field, then it should be required in the strength
   * checks.
   */

  if (
        (min_lower > 0 ) ||
        (min_upper > 0 ) ||
        (min_digit > 0 ) ||
        (min_punct > 0 ) ||
        (nQuality < min_quality)
    ) {
		mem_len = realloc_error_message(&szErrStr, mem_len,
				strlen(PASSWORD_QUALITY_SZ) +
				strlen(pEntry->e_name.bv_val) + 2);
		sprintf (szErrStr, PASSWORD_QUALITY_SZ, pEntry->e_name.bv_val,
				nQuality, min_quality);
		goto fail;
	}

#ifdef HAVE_CRACKLIB

	/** Check password with cracklib */

	if ( use_cracklib > 0 ) {
		int   j = 0;
		FILE* fp;
		char  filename[FILENAME_MAXLEN];
		char  const* ext[] = { "hwm", "pwd", "pwi" };
		int   nErr = 0;

		/**
		 * Silently fail when cracklib wordlist is not found
		 */

		for ( j = 0; j < 3; j++ ) {

			snprintf (filename, FILENAME_MAXLEN - 1, "%s.%s", \
					CRACKLIB_DICTPATH, ext[j]);

			if (( fp = fopen ( filename, "r")) == NULL ) {

				nErr = 1;
				break;

			} else {

				fclose (fp);

			}
		}

		char *r;
		if ( nErr  == 0) {

			r = (char *) FascistCheck (pPasswd, CRACKLIB_DICTPATH);
			if ( r != NULL ) {
				mem_len = realloc_error_message(&szErrStr, mem_len,
						strlen(BAD_PASSWORD_SZ) +
						strlen(pEntry->e_name.bv_val) +
						strlen(r));
				sprintf (szErrStr, BAD_PASSWORD_SZ, pEntry->e_name.bv_val, r);
				goto fail;
			}
		}
	}

	else {
#if defined(DEBUG)
		syslog(LOG_NOTICE, "check_password: Cracklib verification disabled by configuration");
#endif
#if defined(LDEBUG)
		printf("check_password: Cracklib verification disabled by configuration");
#endif
	}

#endif

#if defined(LDEBUG) || defined(DEBUG)
  print_config_entries();
#endif
  dealloc_config_entries();
	*ppErrStr = strdup ("");
	ber_memfree(szErrStr);
	return (LDAP_SUCCESS);

fail:
  dealloc_config_entries();
	*ppErrStr = strdup (szErrStr);
	ber_memfree(szErrStr);
	return (EXIT_FAILURE);

}

