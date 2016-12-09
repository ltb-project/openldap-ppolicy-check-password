/*
 * check_password_test.c for OpenLDAP
 *
 * See LICENSE, README and INSTALL files
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <portable.h>
#include <slap.h>

#include "check_password.h"

int testpass(char* name, char* to_check, int expect) {
  char *errmsg = NULL;
  Entry pEntry;

  // Stubbing this out because it expects *something* here.
  pEntry.e_name.bv_val = "Test_User";

  int retval = check_password(to_check, &errmsg, &pEntry);

  if ( retval != expect ) {
    printf("%s => FAIL:\n",name);
  }
  else {
    printf("%s => OK\n",name);
  }

  if ( strcmp(errmsg,"") != 0 ) {
    printf("\tError: %s\n",errmsg);
  }

  printf("\n");

  ber_memfree(errmsg);
  return retval;
}

// Default to turning off checks.

void setconf(
  int max_consec,
  int min_points,
  int use_cracklib,
  int min_upper,
  int min_lower,
  int min_digit,
  int min_punct ) {

  FILE *config;

  config = fopen(CONFIG_FILE,"w+");

  if (config == NULL) {
    printf("Error writing config file %s\n",CONFIG_FILE);
    exit(1);
  }

  printf("max_consecutive_per_class %d\n", max_consec);
  if (max_consec >= 0) {
    fprintf(config, "max_consecutive_per_class %d\n", max_consec);
  }
  printf("min_points %d\n", min_points);
  if (min_points >= 0) {
    fprintf(config, "min_points %d\n", min_points);
  }
  printf("use_cracklib %d\n", use_cracklib);
  if (use_cracklib >= 0) {
    fprintf(config, "use_cracklib %d\n", use_cracklib);
  }
  printf("min_upper %d\n", min_upper);
  if (min_upper >= 0) {
    fprintf(config, "min_upper %d\n", min_upper);
  }
  printf("min_lower %d\n", min_lower);
  if (min_lower >= 0) {
    fprintf(config, "min_lower %d\n", min_lower);
  }
  printf("min_digit %d\n", min_digit);
  if (min_digit >= 0) {
    fprintf(config, "min_digit %d\n", min_digit);
  }
  printf("min_punct %d\n", min_punct);
  if (min_punct >= 0) {
    fprintf(config, "min_punct %d\n", min_punct);
  }

  fclose(config);
}

int main(void) {

  // Empty Config, equiv to:
  // 5,3,1,0,0,0,0
  setconf(-1,-1,-1,-1,-1,-1,-1);
  testpass("Test 0.0", "F#k2r!m.9", 0);
  testpass("Test 0.1", "simple", 1);
  testpass("Test 0.2", "SimPle", 1);
  testpass("Test 0.3", "SimPle!", 1);

  setconf(3,3,0,0,0,0,0);
  testpass("Test 1.0", "simple", 1);
  testpass("Test 1.1", "Simp1e", 0);
  testpass("Test 1.2", "SimPle", 1);

  setconf(3,3,0,0,0,0,1);
  testpass("Test 2.0", "simple", 1);
  testpass("Test 2.1", "Simp1e", 1);
  testpass("Test 2.2", "SimPle", 1);
  testpass("Test 2.1", "Simp1e!", 0);
  return 0;
}
