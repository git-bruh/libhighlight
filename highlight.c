/* SPDX-FileCopyrightText: 2022 git-bruh
 * SPDX-License-Identifier: MIT */
#include <assert.h>
#include <pcre.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SIZE(x) (sizeof((x)) / sizeof(*(x)))

enum rule_num {
  RULE_NOMATCH = 0,
  RULE_COMMENT,
  RULE_CONSTANT_NUMBER,
  RULE_CONSTANT_STRING,
  RULE_IDENTIFIER,
  RULE_PREPROC,
  RULE_STATEMENT,
  RULE_SYMBOL_BRACKETS,
  RULE_SYMBOL_OPERATOR,
  RULE_TYPE,
  RULE_TYPE_EXTENDED,
  RULE_MAX,
};

enum matcher_num {
  MATCHER_START = 0,
  MATCHER_SKIP,
  MATCHER_END,
  MATCHER_MAX,
};

enum {
  OVECTOR_START = 0,
  OVECTOR_END = 1,
  /* [2] is used internally by pcre. */
  OVECTOR_LEN = 3,
};

struct matcher {
  bool is_region;
  enum rule_num rule;
  pcre *patterns[MATCHER_MAX];
};

struct rule {
  enum rule_num rule;
  const char *start;
  const char *skip;
  const char *end;
};

struct range {
  size_t start;
  size_t end;
};

static const char *const end_attr = "\033[0m";

static const char *const attr(enum rule_num num) {
#define COLOR(x) ("\033[1;" #x "m")

  switch (num) {
  case RULE_COMMENT:
    return COLOR(36);
  case RULE_CONSTANT_NUMBER:
    return COLOR(33);
  case RULE_CONSTANT_STRING:
    return COLOR(32);
  case RULE_IDENTIFIER:
  case RULE_PREPROC:
    return COLOR(35);
  case RULE_STATEMENT:
    return COLOR(31);
  case RULE_SYMBOL_BRACKETS:
    return NULL;
  case RULE_SYMBOL_OPERATOR:
    return COLOR(32);
  case RULE_TYPE:
  case RULE_TYPE_EXTENDED:
    return COLOR(31);
  default:
    return NULL;
  }

#undef COLOR
}

static const char *const rule_to_str[RULE_MAX] = {
    [RULE_COMMENT] = "Comment",
    [RULE_CONSTANT_NUMBER] = "Constant_number",
    [RULE_CONSTANT_STRING] = "Constant_string",
    [RULE_IDENTIFIER] = "Identifier",
    [RULE_PREPROC] = "Preproc",
    [RULE_STATEMENT] = "Statement",
    [RULE_SYMBOL_BRACKETS] = "Symbol_brackets",
    [RULE_SYMBOL_OPERATOR] = "Symbol_operator",
    [RULE_TYPE] = "Type",
    [RULE_TYPE_EXTENDED] = "Type_extended",
};

static const struct rule rules[] = {
    {RULE_IDENTIFIER, "\\b[A-Z_][0-9A-Z_]+\\b"},
    {RULE_TYPE,
     "\\b(auto|float|double|char|int|short|long|sizeof|enum|void|static|const|"
     "struct|union|typedef|extern|(un)?signed|inline)\\b"},
    {RULE_TYPE, "\\b((s?size)|((u_?)?int(8|16|32|64|ptr)))_t\\b"},
    {RULE_TYPE, "\\b[a-z_][0-9a-z_]+(_t|_T)\\b"},
    {RULE_TYPE_EXTENDED, "\\b(bool)\\b"},
    {RULE_STATEMENT, "\\b(volatile|register)\\b"},
    {RULE_STATEMENT, "\\b(for|if|while|do|else|case|default|switch)\\b"},
    {RULE_STATEMENT, "\\b(goto|continue|break|return)\\b"},
    {RULE_PREPROC,
     "^[[:space:]]*\\#[[:space:]]*(define|pragma|include|(un|ifn?)"
     "def|endif|el(if|se)|if|warning|error)"},
    {RULE_STATEMENT, "__attribute__[[:space:]]*\\(\\([^)]*\\)\\)"},
    {RULE_STATEMENT, "__(aligned|asm|builtin|hidden|inline|packed|restrict|"
                     "section|typeof|weak)__"},
    {RULE_SYMBOL_OPERATOR, "([.:;,+*|=!\\%]|<|>|/|-|&)"},
    {RULE_SYMBOL_BRACKETS, "[(){}]|\\[|\\]"},
    {RULE_CONSTANT_NUMBER, "(\\b([1-9][0-9]*|0[0-7]*|0[Xx][0-9A-Fa-f]+|0[Bb]["
                           "01]+)([Uu]?[Ll][Ll]?|[Ll][Ll]?[Uu]?)?\\b)"},
    {RULE_CONSTANT_NUMBER, "(\\b(([0-9]*[.][0-9]+|[0-9]+[.][0-9]*)([Ee][+-]?[0-"
                           "9]+)?|[0-9]+[Ee][+-]?[0-9]+)[FfLl]?\\b)"},
    {RULE_CONSTANT_NUMBER, "(\\b0[Xx]([0-9A-Za-z]*[.][0-9A-Za-z]+|[0-9A-Za-z]+["
                           ".][0-9A-Za-z]*)[Pp][+-]?[0-9]+[FfLl]?\\b)"},
    {RULE_CONSTANT_NUMBER, "NULL"},
};

static const struct rule rule_regions[] = {
    {RULE_CONSTANT_STRING, "\"", NULL, "\""},
    {RULE_CONSTANT_STRING, "'", NULL, "'"},
    {RULE_COMMENT, "//", NULL, "$"},
    {RULE_COMMENT, "/\\*", NULL, "\\*/"},
};

static struct matcher matchers[sizeof(rules) / sizeof(*rules)];
static struct matcher
    region_matchers[sizeof(rule_regions) / sizeof(*rule_regions)];

static void match_cb(struct range *range, const char *str,
                     const enum rule_num *highlighted, void *userp) {
  assert(range->end > range->start);

  enum rule_num last_attr = RULE_NOMATCH;

  for (size_t i = range->start; i < range->end;) {
    const char *attr_str = attr(last_attr);

    if (attr_str) {
      printf("%s", attr_str);
    }

    for (; i < range->end && last_attr == highlighted[i]; i++) {
      putchar(str[i]);
    }

    if (i < range->end) {
      last_attr = highlighted[i];
    }

    if (attr_str) {
      printf("%s", end_attr);
    }
  }
}

static bool matcher_is_present(const struct matcher *matcher,
                               enum matcher_num matcher_num) {
  assert(matcher_num >= 0 && matcher_num < MATCHER_MAX);
  return !!matcher->patterns[matcher_num];
}

static void matcher_finish(struct matcher *matcher) {
  if (matcher) {
    for (enum matcher_num i = 0; i < MATCHER_MAX; i++) {
      pcre_free(matcher->patterns[i]);
    }

    memset(matcher, 0, sizeof(*matcher));
  }
}

static int matcher_init(struct matcher *matcher, const struct rule *rule) {
  assert(matcher);
  assert(rule);
  assert(rule->start);

  *matcher = (struct matcher){.rule = rule->rule};

  const char *const regs[MATCHER_MAX] = {rule->start, rule->skip, rule->end};
  const int options = PCRE_EXTENDED | PCRE_MULTILINE;

  for (enum matcher_num i = 0; i < MATCHER_MAX; i++) {
    if (regs[i]) {
      if (!(matcher->patterns[i] = pcre_compile(
                regs[i], options, &(const char *){0}, &(int){0}, NULL))) {
        matcher_finish(matcher);
        return -1;
      }
    }
  }

  assert((matcher_is_present(matcher, MATCHER_START)));

  if ((matcher_is_present(matcher, MATCHER_SKIP))) {
    assert((matcher_is_present(matcher, MATCHER_END)));
  }

  matcher->is_region = (matcher_is_present(matcher, MATCHER_END));

  return 0;
}

static int matcher_exec(const struct matcher *matcher,
                        enum matcher_num to_match, const char *str,
                        size_t offset, size_t len, int ovector[OVECTOR_LEN]) {
  assert(matcher);
  assert(ovector);
  assert(str);
  assert(offset < len);
  assert((matcher_is_present(matcher, to_match)));

  /* Make sure that we don't treat the beginning of a string as newline
   * if we have incremented past the start. Actual newlines will be matched
   * properly by themselves since we don't skip over them. */
  const int options = (offset != 0 ? PCRE_NOTBOL : 0);

  int ret = pcre_exec(matcher->patterns[to_match], NULL, str, len, offset,
                      options, ovector, OVECTOR_LEN);
  assert(ret >= 0 || ret == PCRE_ERROR_NOMATCH);
  return (ret >= 0 ? 0 : -1);
}

typedef void (*match_fn)(struct range *, const char *, const enum rule_num *,
                         void *);

static void match_inner(const char *str, size_t offset, size_t len,
                        const struct matcher matchers[], size_t len_matchers,
                        enum rule_num *highlighted, void *userp) {
  assert(str);

  for (size_t i = 0; i < len_matchers; i++) {
    size_t offset_current = offset;

    assert(!matchers[i].is_region);

    for (; offset_current < len;) {
      int ovector[OVECTOR_LEN] = {0};
      int ret = matcher_exec(&matchers[i], MATCHER_START, str, offset_current,
                             len, ovector);

      if (ret == -1) {
        assert(ovector[OVECTOR_START] == -1);
        assert(ovector[OVECTOR_END] == -1);

        break;
      }

      assert(ovector[OVECTOR_START] >= offset_current);
      assert(ovector[OVECTOR_END] >= offset_current);
      assert(ovector[OVECTOR_END] > ovector[OVECTOR_START]);
      assert((size_t)ovector[OVECTOR_END] <= len);

      for (size_t j = ovector[OVECTOR_START]; j < ovector[OVECTOR_END]; j++) {
        highlighted[j] = matchers[i].rule;
      }

      offset_current = ovector[OVECTOR_END];
    }
  }
}

static int match_public(const char *str, size_t len, void *userp,
                        match_fn match_cb, const struct matcher matchers[],
                        size_t len_matchers,
                        const struct matcher region_matchers[],
                        size_t len_region_matchers) {
  if (!str || len == 0) {
    return -1;
  }

  /* RULE_NOMATCH == 0, so we calloc */
  enum rule_num *highlighted = calloc(len, sizeof(*highlighted));

  if (!highlighted) {
    return -1;
  }

  for (size_t offset = 0; offset < len;) {
    /* The match that starts earliest. This is used to skip overlapping regions
     * Like the comment in `char *s = "// Comment in string";` */
    int ovector[OVECTOR_LEN] = {0};
    const struct matcher *matcher = NULL;

    size_t offset_before_skip = offset;

    /* Only check (offset + 1) so that offset is on a newline for proper
     * circumflex ('^') matching. */
    while ((offset + 1) < len && str[offset + 1] == '\n') {
      offset++;
    }

    assert((offset + 1) <= len);

    /* (offset + 1) prevents matching the current character.
     * If (offset + 1) == len then don't bother. Just match the last character.
     */
    char *newline =
        (((offset + 1) < len) ? strchr(&str[offset + 1], '\n') : NULL);

    /* Only scan upto the next newline to avoid too many lookaheads.
     * Take the following string:
     * // Comment
     * // Another comment
     * // One more comment
     * "string"
     * Instead of stumbling over `"string"` 3 times for each comment (//) match,
     * we only encounter it once. This ofcourse doesn't save us from superflous
     * matches in a single line with multiple regions. */
    size_t len_upto_newline = (newline ? (newline - str) : len);

    if ((offset - offset_before_skip) > 0) {
      match_cb(&(struct range){.start = offset_before_skip, .end = offset}, str,
               highlighted, userp);
    }

    for (size_t i = 0; i < len_region_matchers; i++) {
      assert(region_matchers[i].is_region);

      int tmp[OVECTOR_LEN] = {0};
      int ret = matcher_exec(&region_matchers[i], MATCHER_START, str, offset,
                             len_upto_newline, tmp);

      if (ret == -1) {
        assert(tmp[OVECTOR_START] == -1);
        assert(tmp[OVECTOR_END] == -1);

        continue;
      }

      assert(tmp[OVECTOR_START] >= offset);
      assert(tmp[OVECTOR_END] >= offset);
      assert((size_t)tmp[OVECTOR_END] <= len);

      if (!matcher || tmp[OVECTOR_START] < ovector[OVECTOR_START]) {
        matcher = &region_matchers[i],

        ovector[OVECTOR_START] = tmp[OVECTOR_START];
        ovector[OVECTOR_END] = tmp[OVECTOR_END];
      }
    }

    if (!matcher) {
      match_inner(str, offset, len_upto_newline, matchers, len_matchers,
                  highlighted, userp);
      match_cb(&(struct range){.start = offset, .end = len_upto_newline}, str,
               highlighted, userp);
      offset = len_upto_newline;
    } else {
      int tmp[OVECTOR_LEN] = {0};

      /* We must pass the string length as the max len here as matches
       * can span across lines. */
      int ret = matcher_exec(matcher, MATCHER_END, str, ovector[OVECTOR_END],
                             len, tmp);

      /* Match till the end of the line if the end didn't match. */
      ovector[OVECTOR_END] = ((ret == 0) ? tmp[OVECTOR_END] : len_upto_newline);

      for (size_t i = ovector[OVECTOR_START]; i < ovector[OVECTOR_END]; i++) {
        highlighted[i] = matcher->rule;
      }

      match_inner(str, offset, ovector[OVECTOR_START], matchers, len_matchers,
                  highlighted, userp);

      match_cb(&(struct range){.start = offset, .end = ovector[OVECTOR_END]},
               str, highlighted, userp);
      offset = ovector[OVECTOR_END];
    }
  }

  free(highlighted);

  return 0;
}

int main(void) {
  size_t sz = 2412160 * 2;
  char *buf = malloc(sz);

  size_t len = 0;

  {
    size_t i = 0;

    while ((i + 1) < sz) {
      int c = getchar();

      if (c == EOF) {
        break;
      }

      buf[i++] = (char)c;
    }

    assert(i < sz);
    buf[i] = '\0';
    len = i;
  }

  for (size_t i = 0; i < SIZE(matchers); i++) {
    int ret = matcher_init(&matchers[i], &rules[i]);
    assert(ret == 0);
  }

  for (size_t i = 0; i < SIZE(region_matchers); i++) {
    int ret = matcher_init(&region_matchers[i], &rule_regions[i]);
    assert(ret == 0);
  }

  match_public(buf, len, NULL, match_cb, matchers, SIZE(matchers),
               region_matchers, SIZE(region_matchers));

  for (size_t i = 0; i < SIZE(matchers); i++) {
    matcher_finish(&matchers[i]);
  }

  for (size_t i = 0; i < SIZE(region_matchers); i++) {
    matcher_finish(&region_matchers[i]);
  }

  free(buf);
}
