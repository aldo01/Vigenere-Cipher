/*****************************************************************************
 * The Vigenere Cipher
  Nimish Karan 
 *****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <malloc.h>
#include <assert.h>
#include <errno.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/stat.h>


/*****************************************************************************
 * Function prototypes
 *****************************************************************************/
void vig_error(int err);
void vig_iencrypt();
void vig_idecrypt();
char *vig_enc_str(char *str, char *key);
char *vig_dec_str(char *str, char *key);
char *vig_tidystr(char *data);
void vig_icrack();
float *vig_shifts(char *data, int *num_shifts);
float vig_cindex(char *data, int shift);
void vig_disp_shifts(float *shifts, int num_shifts);
int vig_keylen(float *shifts, int num_shift);
float *vig_ltrstat(char *data, int key_len, int key_pos);
void vig_disp_ltrstat(float *ltrstat);
float *vig_keycand(float *ltrstat);
void vig_disp_keycand(float *keycand);
char vig_keyltr(float *keycand);
void vig_disp_text(char *data, char *key, int rows);
void *vig_malloc(int size);
void vig_freeall();
void vig_malloc_growlist();
void vig_malloc_init();
void vig_malloc_term();
void vig_keywait();
char *vig_getstr(char *prompt);
char *vig_getstrfile(char *prompt, char **fname);
char *vig_loadfile(char *fname);
char *vig_getstrdef(char *prompt, char *def);
void vig_putstr(char *prompt, char *data, char *fname);
char *vig_strcat(char *s1, char *s2);
char *vig_strcat4(char *s1, char *s2, char *s3, char *s4);
char *vig_strprefix(char *str, int len);
char *vig_strset(char chr, int len);
char *vig_itos(int num);
char *vig_ctos(char chr);


/*****************************************************************************
 * Custom error codes; __ELASTERROR not available on all platforms.
 *****************************************************************************/
#ifdef __ELASTERROR
#define VIG_EBASE __ELASTERROR
#else
#define VIG_EBASE 2000
#endif
#define VIG_ELENGTH VIG_EBASE + 0


/*****************************************************************************
 * This error handling routine longjmp's to the setjmp in main below
 *****************************************************************************/
jmp_buf vig_err_env;
void vig_error(int err)
{
  char *msg;
  switch(err)
  {
    case VIG_ELENGTH: msg = "must not be zero length"; break;
    default:          msg = strerror(err);
  }
  printf("ERROR: %s\n\n", msg);
  longjmp(vig_err_env, err);
}


/*****************************************************************************
 * Main entry point; coordinate main menu
 *****************************************************************************/
int main()
{
  vig_malloc_init();
  for(;;)
  {
    if(setjmp(vig_err_env) == 0)
    {
      printf
      (
        "\n"
        "The Vigenere Cipher\n"
        
        "\n"
        "1) Encrypt a file/string\n"
        "2) Decrypt a file/string\n"
        "3) Crack a file/string (decrypt with unknown key)\n"
        "4) Quit\n"
        "\n"
      );
      switch(vig_getstr("selection")[0])
      {
        case '1': vig_iencrypt(); break;
        case '2': vig_idecrypt(); break;
        case '3': vig_icrack();   break;
        case '4': exit(0);        break;
      }
    }
    vig_freeall();
    vig_keywait();
  }
  return 0;
}



/*****************************************************************************
 * Interactive routine to enrypt / decrypt a text string or file
 *****************************************************************************/
void vig_iencrypt()
{
  char *key, *data, *fname;
  data = vig_tidystr(vig_getstrfile("plaintext", &fname));
  key  = vig_tidystr(vig_getstrfile("key", NULL));
  vig_putstr("ciphertext", vig_enc_str(data, key), fname);
}

void vig_idecrypt()
{
  char *key, *data, *fname;
  data = vig_tidystr(vig_getstrfile("ciphertext", &fname));
  key  = vig_tidystr(vig_getstrfile("key", NULL));
  vig_putstr("plaintext", vig_dec_str(data, key), fname);
}


/*****************************************************************************
 * Functions to encrypt / decrypt strings
 *****************************************************************************/
char *vig_enc_str(char *str, char *key)
{
  int ii, key_len = strlen(key);
  if(key_len < 1) { vig_error(VIG_ELENGTH); }

#define VIG_ENC_CHAR(C, K)  ('A' + ((C - 'A') + (K - 'A')) % 26)
  for(ii = 0; str[ii]; ii++)
  {
    str[ii] = VIG_ENC_CHAR(str[ii], key[ii % key_len]);
  }
  return str;
}

char *vig_dec_str(char *str, char *key)
{
  int ii, key_len = strlen(key);
  if(key_len < 1) { vig_error(VIG_ELENGTH); }

  /* The check for a key letter being '-' is used in vig_disp_text */
#define VIG_DEC_CHAR(C, K)  (K == '-') ? ' ' : \
                                      ('A' + (26 + (C - 'A') - (K - 'A')) % 26)
  for(ii = 0; str[ii]; ii++)
  {
    str[ii] = VIG_DEC_CHAR(str[ii], key[ii % key_len]);
  }
  return str;
}


/*****************************************************************************
 * Remove all non-alphabetic characters, and convert to upper case
 *****************************************************************************/
char *vig_tidystr(char *data)
{
  int ii, jj = 0;
  for (ii = 0; data[ii]; ii++)
  {
    if(isalpha(data[ii]))
    {
      data[jj++] = toupper(data[ii]);
    }
  }
  data[jj] = 0;
  return data;
}


/*****************************************************************************
 * Interactive routine to decode a ciphertext without the key
 *****************************************************************************/
void vig_icrack()
{
  char *data, *key, *fname, *ltr;
  int num_shift, key_len = 0, ii = -1;
  float *shifts;

  data = vig_tidystr(vig_getstrfile("ciphertext", &fname));
  shifts = vig_shifts(data, &num_shift);

  while(ii <= key_len)
  {
    if(ii == -1)
    { /* determine key length */
      vig_disp_shifts(shifts, num_shift);
      key_len = atoi(vig_getstrdef("key length",
                                     vig_itos(vig_keylen(shifts, num_shift))));
      if(key_len < 1) { vig_error(VIG_ELENGTH); }
      key = vig_strset('-', key_len);
      ii++;
    }
    else if(ii < key_len)
    { /* determine one letter of key */
      ltr = vig_ctos(vig_keyltr(vig_keycand(vig_ltrstat(data, key_len, ii))));
      vig_putstr("key so far", key, NULL);
      vig_disp_text(data, key, 2);
      ltr = vig_getstrdef("key letter or '-' to go back", ltr);
      if(ltr[0] == '-') { key[--ii] = '-'; }
      if(strlen(vig_tidystr(ltr)) > 0) { key[ii++] = ltr[0]; }
    }
    else
    { /* final confirmation screen */
      vig_putstr("key", key, NULL);
      vig_disp_text(data, key, 5);
      ltr = vig_getstr("to confirm or '-' to go back");
      if(ltr[0] == '-') { key[--ii] = '-'; }
      else { ii++; }
    }
  }
  vig_putstr("plaintext", vig_dec_str(data, key), fname);
}


/*****************************************************************************
 * Calculate coincidence indexes for first 256 shifts, unless data is too
 * short.
 *****************************************************************************/
float *vig_shifts(char *data, int *num_shifts)
{
  float *shifts;
  int ii, data_len = strlen(data);
  if(data_len < 1) { vig_error(VIG_ELENGTH); }

#define VIG_MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
  *num_shifts = VIG_MIN(data_len, 256);
  shifts = vig_malloc(*num_shifts * sizeof(float));

  for(ii = 0; ii < *num_shifts; ii++)
  {
    shifts[ii] = vig_cindex(data, ii);
  }

  return shifts;
}


/*****************************************************************************
 * Calculate coincidence index of a particular shift on a ciphertext
 *****************************************************************************/
float vig_cindex(char *data, int shift)
{
  int ii, matches = 0;
  assert(shift < strlen(data));
  for(ii = 0; data[ii + shift]; ii++)
  {
    if(data[ii] == data[ii + shift]) { matches++; }
  }
  return (float) 100 * matches / ii;
}


/*****************************************************************************
 * Display shift information
 *****************************************************************************/
void vig_disp_shifts(float *shifts, int num_shifts)
{
  int shift, ii, jj;
  printf ("Shift / coincidence index:\n\n");
  for(ii = 0; ii < 20; ii++)
  {
    for(jj = 0; jj < 5; jj++)
    {
      shift = 1 + ii + jj * 20;
      if(shift < num_shifts)
      {
        printf("%3d %6.2f%%    ", shift , shifts[shift]);
      }
    }
    printf("\n");
  }
  printf("\n");
}


/*****************************************************************************
 * Determine the suggested key length from the shifts information
 *****************************************************************************/
int vig_keylen(float *shifts, int num_shift)
{
  int ii, jj, cand;
  for(ii = 1; ii < num_shift; ii++)
  {
    cand = 1;
    for(jj = 1; (jj * ii) < num_shift && cand; jj++)
    {
      cand = cand && (shifts[jj * ii] > 6);
    }
    if(cand) { break; }
  }
  return (ii >= num_shift) ? 0 : ii;
}


/*****************************************************************************
 * Calculate letter frequency information for one key position
 *****************************************************************************/
float *vig_ltrstat(char *data, int key_len, int key_pos)
{
  float num_chr = 0, *ltrstat = vig_malloc(26 * sizeof(float));
  int ii, data_len = strlen(data);

  for(ii = 0; ii < 26; ii++) { ltrstat[ii] = 0; }
  for(ii = key_pos; ii < data_len; ii += key_len)
  {
    ltrstat[data[ii] - 'A']++;
    num_chr++;
  }
  for(ii = 0; ii < 26; ii++) { ltrstat[ii] *= 100 / num_chr; }

  vig_disp_ltrstat(ltrstat);
  return ltrstat;
}


/*****************************************************************************
 * Display letter frequencies
 *****************************************************************************/
void vig_disp_ltrstat(float *ltrstat)
{
  int ii;
  printf("Letter frequencies:\n");
  for(ii = 0; ii < 26; ii++)
  {
    printf("%c %6.2f%%    ", 'A' + ii, ltrstat[ii]);
    if(ii % 6 == 5) { printf("\n"); }
  }
  printf("\n\n");
}


/*****************************************************************************
 * Calculate the squared deviation from standard letter frequencies for
 * English for each possible key letter.
 *****************************************************************************/
float english_freq[] =
{  /* A */
  7.81, 1.28, 2.93, 4.11, 13.05, 2.88, 1.39,
  5.85, 6.77, 0.23, 0.42, 3.60, 2.62, 7.28,
  8.21, 2.15, 0.14, 6.64, 6.46, 9.02, 2.77,
  1.00, 1.49, 0.30, 1.51, 0.09
}; /* Z */

float *vig_keycand(float *ltrstat)
{
  float dev, *keycand = vig_malloc(26 * sizeof(float));
  int ii, jj;

  for(ii = 0; ii < 26; ii++)
  {
    keycand[ii] = 0;
    for(jj = 0; jj < 26; jj++)
    {
      dev = english_freq[(26 + jj - ii) % 26] - ltrstat[jj];
      keycand[ii] += (dev * dev);
    }
  }
  vig_disp_keycand(keycand);

  return keycand;
}


/*****************************************************************************
 * Display key candidates
 *****************************************************************************/
void vig_disp_keycand(float *keycand)
{
  int ii;
  printf("Key candidates (most likely has smallest number):\n");
  for(ii = 0; ii < 26; ii++)
  {
    printf("%c  %5.0f     ", 'A' + ii, keycand[ii]);
    if(ii % 6 == 5) { printf("\n"); }
  }
  printf("\n\n");
}


/*****************************************************************************
 * Find letter with least deviation
 *****************************************************************************/
char vig_keyltr(float *keycand)
{
  int ii, min = 0;
  for(ii = 1; ii < 26; ii++)
  {
    if(keycand[ii] < keycand[min]) { min = ii; }
  }
  return 'A' + min;
}


/*****************************************************************************
 * Display a sample of the cipher and plaintext
 *****************************************************************************/
void vig_disp_text(char *data, char *key, int rows)
{
  char *cipher = strlwr(vig_strprefix(data, rows * 79));
  char *plain  = vig_dec_str(vig_strprefix(data, rows * 79), key);
  int ii;
  for(ii = 0; (ii < rows) && cipher[ii * 79]; ii++)
  {
    printf("%.79s\n%.79s\n", cipher + (ii * 79), plain + (ii * 79));
  }
  printf("\n");
}


/*****************************************************************************
 * This is a customised version of malloc, which calls vig_error instead of
 * returning NULL, and keeps a list of allocated memory. Calling vig_freeall
 * frees everything.
 *****************************************************************************/
void **vig_mem_list;
int vig_mem_idx;
int vig_mem_llen;

void *vig_malloc(int size)
{
  if(vig_mem_idx >= vig_mem_llen) { vig_malloc_growlist(); }
  vig_mem_list[vig_mem_idx] = malloc(size);
  if(vig_mem_list[vig_mem_idx] == NULL) { vig_error(ENOMEM); }
  return vig_mem_list[vig_mem_idx++];;
}

void vig_freeall()
{
  while(vig_mem_idx > 0) { free(vig_mem_list[--vig_mem_idx]); }
}


/*****************************************************************************
 * Grow the memory block used for the list of allocated blocks.
 *****************************************************************************/
void vig_malloc_growlist()
{
  int new_llen = (vig_mem_llen == 0) ? 256 : 2 * vig_mem_llen;
  void *new_list = realloc(vig_mem_list, new_llen * sizeof(void *));
  if(new_list == NULL) { vig_error(ENOMEM); }
  vig_mem_list = new_list;
  vig_mem_llen = new_llen;
}


/*****************************************************************************
 * Initialise/cleanup vig_malloc routines
 *****************************************************************************/
void vig_malloc_init()
{
  vig_mem_idx = 0;
  vig_mem_llen = 0;
  vig_mem_list = NULL;
  atexit(vig_malloc_term);
}

void vig_malloc_term()
{
  vig_freeall();
  free(vig_mem_list);
}


/*****************************************************************************
 * Wait for user to press enter
 *****************************************************************************/
void vig_keywait()
{
  char input[4];
  printf("[Press Enter]\n");
  fgets(input, 3, stdin);
}

/*****************************************************************************
 * Input a string from the user
 *****************************************************************************/
char *vig_getstr(char *prompt)
{
  char *input = vig_malloc(256);
  printf("Enter %s\n: ", prompt);
  fgets(input, 255, stdin);
  input[strlen(input) - 1] = 0;
  printf("\n");
  return input;
}


/*****************************************************************************
 * Input a string from the user; load a file if user types !filename.
 *****************************************************************************/
char *vig_getstrfile(char *prompt, char **fname)
{
  char *input = vig_getstr(vig_strcat(prompt, " (or !filename)"));
  if(fname != NULL) { (*fname) = NULL; }
  if(input[0] == '!')
  {
    if(fname != NULL) { (*fname) = vig_strcat(input + 1, ".vig"); }
    input = vig_loadfile(input + 1);
  }
  return input;
}


/*****************************************************************************
 * Load a complete file into memory
 *****************************************************************************/
char *vig_loadfile(char *fname)
{
  FILE *fhandle;
  char *data;
  struct stat finfo;

  if(stat(fname, &finfo) != 0) { vig_error(errno); }
  data = vig_malloc(finfo.st_size + 1);

  fhandle = fopen(fname, "rt");
  if(fhandle == NULL) { vig_error(errno); }

  fread(data, finfo.st_size, 1, fhandle);
  data[finfo.st_size] = 0;
  fclose(fhandle);

  return data;
}


/*****************************************************************************
 * Input a string from the user; use given default value if user just
 * presses enter
 *****************************************************************************/
char *vig_getstrdef(char *prompt, char *def)
{
  char *str = vig_getstr(vig_strcat4(prompt, " (suggest ", def, ")"));
  return (strlen(str) == 0) ? def : str;
}


/*****************************************************************************
 * Write data to the named file, or stdout if fname is null
 *****************************************************************************/
void vig_putstr(char *prompt, char *data, char *fname)
{
  FILE *fhandle;
  printf("Generated %s\n: ", prompt);
  if(fname != NULL)
  {
    fhandle = fopen(fname, "wt");
    if(fhandle == NULL) { vig_error(errno); }
    fwrite(data, strlen(data), 1, fhandle);
    fclose(fhandle);
    printf("written to %s\n\n", fname);
  }
  else
  {
    printf("%s\n\n", data);
  }
}


/*****************************************************************************
 * Concatonate strings
 *****************************************************************************/
char *vig_strcat(char *s1, char *s2)
{
  char *str = vig_malloc(strlen(s1) + strlen(s2) + 1);
  strcpy(str, s1);
  strcat(str, s2);
  return str;
}

char *vig_strcat4(char *s1, char *s2, char *s3, char *s4)
{
  char *str = vig_malloc(strlen(s1) + strlen(s2) + strlen(s3) + strlen(s4) +1);
  strcpy(str, s1);
  strcat(str, s2);
  strcat(str, s3);
  strcat(str, s4);
  return str;
}


/*****************************************************************************
 * Extract the beginning of a string into a new block of memory
 *****************************************************************************/
char *vig_strprefix(char *str, int len)
{
  char *sub = vig_malloc(len + 1);
  memset(sub, 0, len + 1);
  strncpy(sub, str, len);
  return sub;
}


/*****************************************************************************
 * Create a string of length len, containing all 'chr's
 *****************************************************************************/
char *vig_strset(char chr, int len)
{
  char *str = vig_malloc(len + 1);
  memset(str, chr, len);
  str[len] = 0;
  return str;
}


/*****************************************************************************
 * Convert an integer/character to a string
 *****************************************************************************/
char *vig_itos(int num)
{
  char *str = vig_malloc(10);
  sprintf(str, "%d", num);
  return str;
}

char *vig_ctos(char chr)
{
  char *str = vig_malloc(2);
  str[0] = chr;
  str[1] = 0;
  return str;
}
