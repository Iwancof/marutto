#include <inttypes.h>
#include <openssl/md5.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef union __HashValue {
  unsigned char array[MD5_DIGEST_LENGTH];
  __uint128_t value;
} HashValue;

// #define DEBUG

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

const size_t MAX_PASSWORD_LENGTH = 0x100;
// const char *split_char[] = {"", ",", "/", ".", "#", "-", ":", ";",
/*
const char split_char[] = {'_', ',', ' ', '/',  '.', '#',
                           '-', ':', ';', '\"', '\''};
                           */
const char split_char[] = {'-', '_'};
HashValue target;

static inline void get_hash(char *data, size_t len, HashValue *md_value) {
  MD5_CTX md5_context;
#ifdef DEBUG
  int result = MD5_Init(&md5_context);

  if (result != 1) {
    fprintf(stderr, "Error occured in init\n");
    exit(1);
  }
#else
  MD5_Init(&md5_context);
#endif

#ifdef DEBUG
  result = MD5_Update(&md5_context, data, strlen(data));

  if (result != 1) {
    perror("update");
    exit(1);
  }
#else
  MD5_Update(&md5_context, data, strlen(data));
#endif

#ifdef DEBUG
  result = MD5_Final(&md_value->array[0], &md5_context);
  if (result != 1) {
    perror("final");
    exit(1);
  }
#else
  MD5_Final(&md_value->array[0], &md5_context);
#endif
}

static inline void md5_to_str(char ret[33], HashValue md_value) {
  for (int i = 0; i < 16; i++)
    sprintf(&ret[i * 2], "%02x", (unsigned int)md_value.array[i]);
  ret[32] = '\0';
}

char *weight_read_file(char *file_name) {
  const size_t SIZE_PER_READ = 0x100;

  FILE *f = fopen(file_name, "r");
  if (f == NULL) {
    fprintf(stderr, "Can't open file %s\n", file_name);
    exit(-1);
  }

  char *ret = NULL; // realloc(NULL, size) is equivalent to malloc(size)

  for (size_t i = 1; i <= 100; i++) {
    ret = realloc(ret, SIZE_PER_READ * i);
    size_t read_size =
        fread(&ret[SIZE_PER_READ * (i - 1)], 1, SIZE_PER_READ, f);

    if (read_size != SIZE_PER_READ) {
      return ret;
    }
  }

  // here is i is max.

  fprintf(stderr, "file %s is too big\n", file_name);
  exit(-1);
}

char **split(char *string, int *number) {
  const size_t MAX_WORD_NUMBER = 0x100;

  char *tail, *head;
  tail = head = string;

  char **ret = malloc(MAX_WORD_NUMBER), **current = ret;

  for (*number = 0; *number < MAX_WORD_NUMBER; (*number)++) {
    if (*(head++) == '\n') {
      // we need newline at last of contents.
      *current = NULL; // NULL means end of list.
      break;
    }
    for (; *head != '\n'; head++) // skip until \n
      ;

    // The string(tail to head) contains \n. so, head - tail has enough big to
    // terminate by null.
    *current = malloc(head - tail);
    strncpy(*current, tail, head - tail); // terminate

    tail = head += 1; // skip newline and reset tail.
    current += 1;
  }

  if (*number == MAX_WORD_NUMBER - 1) {
    fprintf(stderr, "Contents of file is too big\n");
    exit(-1);
  }

  return ret;
}

void dfs_entry(char **element, int n);
static inline void dfs_impl(char **trace, char **element, char *used_flag,
                            int n, int depth);
void dfs_leaf_func(char **trace, size_t len);

void append_dfs_entry(char **element, size_t len);
void append_dfs_leaf(char *password, size_t len);
static inline void append_dfs_impl(char *buffer, char **element, size_t len,
                                   size_t start_indexes[],
                                   size_t element_depth);

#define TRUE (1)
#define FALSE (0)

void dfs_entry(char **element, int n) { // search all
  char *trace[n];
  char used_flag[n];
  for (size_t i = 0; i < n; i++) {
    trace[i] = NULL;
    used_flag[i] = FALSE;
  }

  dfs_impl(trace, element, used_flag, n, 0);
}

static inline void dfs_impl(char **trace, char **element, char *used_flag,
                            int n, int depth) {

  dfs_leaf_func(trace, depth);

  if (depth == n) {
    // reach to leaf
    return;
  }

  for (size_t i = 0; i < n; i++) {
    if (used_flag[i] == FALSE) {
      used_flag[i] = TRUE;
      trace[depth] = element[i];
      dfs_impl(trace, element, used_flag, n, depth + 1);
      used_flag[i] = FALSE;
    }
  }

  trace[depth] = NULL;
}

void dfs_leaf_func(char **trace, size_t len) {
  // created information list.
  append_dfs_entry(trace, len);
}

void append_dfs_entry(char **element, size_t len) {
  if (len == 0) {
    append_dfs_leaf("", 0);
    return;
  }

  /*
  puts("[+] entry!");
  for (size_t i = 0; i < len; i++) {
    printf("%s\n", element[i]);
  }
  puts("[+] elements!");
  */

  char buffer[MAX_PASSWORD_LENGTH];
  size_t start_indexes[len + 1000];
  start_indexes[0] = 0;

  append_dfs_impl(buffer, element, len, start_indexes, 0);
}

static inline void append_dfs_impl(char *buffer, char **element, size_t len,
                                   size_t start_indexes[],
                                   size_t element_depth) {

  if (len == element_depth) {
    append_dfs_leaf(buffer, start_indexes[element_depth]);
    return;
  }
  // append element
  start_indexes[element_depth + 1] =
      start_indexes[element_depth] +
      snprintf(&buffer[start_indexes[element_depth]],
               MAX_PASSWORD_LENGTH - start_indexes[element_depth], "%s",
               element[element_depth]);

  append_dfs_impl(buffer, element, len, start_indexes, element_depth + 1);

  size_t split_pos = start_indexes[element_depth + 1] + 0; // split char.
  start_indexes[element_depth + 1] += 1;

  buffer[split_pos + 1] = '\0';
  for (size_t split_index = 0; split_index < sizeof(split_char);
       split_index++) {
    // printf("split char: '%c'\n", split_char[split_index]);
    buffer[split_pos] = split_char[split_index];
    append_dfs_impl(buffer, element, len, start_indexes, element_depth + 1);
  }
}

char *user_name;

void append_dfs_leaf(char *prefix, size_t len) {
  HashValue hash;
  char password[MAX_PASSWORD_LENGTH];
  strcpy(password, prefix);
  size_t length = len + sprintf(&password[len], "%s", user_name);

#ifdef DEBUG
  if (strlen(password) != length) {
    fprintf(stderr, "Length mismatch\n");
    exit(-1);
  }
#endif
  get_hash(password, length, &hash);

#ifdef DEBUG
  char buf[33];
  md5_to_str(buf, hash);

  printf("%s\n", buf);
#endif

  if (unlikely(hash.value == target.value)) {
    char *hash_str = malloc(33);
    md5_to_str(hash_str, hash);

    printf("password found!!!!\nusername:%s password:%s, hash:%s\n", user_name,
           prefix, hash_str);
    exit(0);
  }
}

void md5_str_to_value(char *str, HashValue *value) {
  if (strlen(str) != 32) {
    fprintf(stderr, "This is not MD5 hash. MD5 hash has 32 chars\n");
    exit(-1);
  }

  char tmp[3];
  tmp[2] = '\0';
  for (size_t i = 0; i < 128 / 8; i++) {
    tmp[0] = str[i * 2];
    tmp[1] = str[i * 2 + 1];

    int t;
    sscanf(tmp, "%x", &t);
    value->array[i] = (char)t;
  }
}

int main(int argc, char *argv[]) {
  // USAGE, ./binary personal_info wordlist hash_file
  if (sizeof(__uint128_t) != MD5_DIGEST_LENGTH) {
    fprintf(stderr, "__uint128_t is not support");
    exit(-1);
  }
  if (sizeof(int64_t) * 2 != MD5_DIGEST_LENGTH) {
    fprintf(stderr, "Length error");
    exit(-1);
  }

  if (argc != 5) {
    fprintf(stderr, "USAGE: %s personal_info wordlist hash_file username\n",
            argv[0]);
    exit(-1);
  }

  char *personal_info_file = argv[1];
  char *wordlist = argv[2];
  char *hash_file = argv[3];
  user_name = argv[4];

  char *cont = weight_read_file(personal_info_file);
  char *target_str = weight_read_file(hash_file);

  int number_of_contents;
  char **r = split(cont, &number_of_contents);

  free(cont);

  puts("[+] Files loaded");

  target_str[32] = '\0';
  printf("[+] Cracking target is %s.\n", target_str);

  md5_str_to_value(target_str, &target);

#ifdef DEBUG
  char debug_data[] = "foobar";
  char expect[] = "3858f62230ac3c915f300c664312c63f";
  char buffer[33];

  HashValue debug_target;
  md5_str_to_value(expect, &debug_target);

  md5_to_str(buffer, debug_target);

  if (strcmp(expect, buffer) != 0) {
    fprintf(stderr, "Test fail\nexpect: %s, got %s\n", expect, buffer);
    exit(-1);
  }

#endif

  dfs_entry(r, number_of_contents);
  return 0;
}
