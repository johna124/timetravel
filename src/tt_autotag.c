/* ============================================================
   Time-Travel v1.5 — tt_autotag.c
   Generación automática de tags semánticos a partir de deltas.
   ============================================================ */
#include "tt_autotag.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ── Keywords a ignorar ──────────────────────────────────── */
static const char *KEYWORDS[] = {
    "if", "else", "for", "while", "do", "switch", "case", "break",
    "continue", "return", "goto", "sizeof", "typedef", "struct",
    "union", "enum", "const", "static", "extern", "inline", "volatile",
    "void", "int", "char", "float", "double", "long", "short",
    "unsigned", "signed", "size_t", "ssize_t", "ptrdiff_t",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
    "NULL", "true", "false", "TRUE", "FALSE",
    "include", "define", "ifdef", "ifndef", "endif", "pragma",
    "stdio", "stdlib", "string", "unistd", "errno",
    "echo", "exit", "then", "fi", "done", "esac",
    "local", "export", "set", "unset", "shift", "function",
    "def", "class", "import", "from", "with", "try", "except",
    "finally", "raise", "yield", "lambda", "pass", "del",
    "and", "or", "not", "None", "True", "False", "self",
    "the", "this", "that", "void", "main",
    NULL
};

static int is_keyword(const char *word, size_t len)
{
    for (int i = 0; KEYWORDS[i]; ++i) {
        if (strlen(KEYWORDS[i]) == len &&
            strncmp(word, KEYWORDS[i], len) == 0)
            return 1;
    }
    return 0;
}

/* ── Token: identificador + frecuencia ───────────────────── */
typedef struct {
    char word[128];
    int count;
} TtToken;

#define MAX_TOKENS 256

static int extract_tokens(const uint8_t *data, size_t size,
                          TtToken *tokens, int max_tokens, int *ntokens)
{
    *ntokens = 0;
    size_t i = 0;

    while (i < size && *ntokens < max_tokens) {
        if (!isalpha(data[i]) && data[i] != '_') {
            i++;
            continue;
        }

        size_t start = i;
        while (i < size && (isalnum(data[i]) || data[i] == '_'))
            i++;

        size_t len = i - start;
        if (len < 3 || len >= 128)
            continue;
        if (is_keyword((const char *)(data + start), len))
            continue;

        int found = 0;
        for (int t = 0; t < *ntokens; ++t) {
            if (strlen(tokens[t].word) == len &&
                strncmp(tokens[t].word, (const char *)(data + start), len) == 0) {
                tokens[t].count++;
                found = 1;
                break;
            }
        }

        if (!found) {
            TtToken *tk = &tokens[*ntokens];
            memcpy(tk->word, data + start, len);
            tk->word[len] = '\0';
            tk->count = 1;
            (*ntokens)++;
        }
    }
    return 0;
}

static int token_cmp(const void *a, const void *b)
{
    const TtToken *ta = a, *tb = b;
    if (tb->count != ta->count)
        return tb->count - ta->count;
    return strcmp(ta->word, tb->word);
}

/* ── Contar líneas ───────────────────────────────────────── */
static int count_lines(const uint8_t *data, size_t size)
{
    if (!data || size == 0)
        return 0;
    int n = 0;
    for (size_t i = 0; i < size; ++i)
        if (data[i] == '\n')
            n++;
    if (size > 0 && data[size - 1] != '\n')
        n++;
    return n;
}

/* ── Encontrar rango de líneas cambiadas ─────────────────── */
static void find_changed_range(const uint8_t *old, size_t old_sz,
                               const uint8_t *new, size_t new_sz,
                               int *start_line, int *end_line)
{
    *start_line = 1;
    *end_line = 1;

    if (new_sz == 0 && old_sz == 0)
        return;

    /* Desde el principio */
    const uint8_t *op = old, *oe = old + old_sz;
    const uint8_t *np = new, *ne = new + new_sz;
    int line = 1;

    while (op < oe && np < ne) {
        const uint8_t *ol_s = op;
        while (op < oe && *op != '\n') op++;
        size_t ol_len = (size_t)(op - ol_s);
        if (op < oe) op++;

        const uint8_t *nl_s = np;
        while (np < ne && *np != '\n') np++;
        size_t nl_len = (size_t)(np - nl_s);
        if (np < ne) np++;

        if (ol_len != nl_len || memcmp(ol_s, nl_s, ol_len) != 0) {
            *start_line = line;
            break;
        }
        line++;
    }

    if (op >= oe || np >= ne) {
        if (op >= oe && np >= ne) {
            *end_line = *start_line;
            return;
        }
        *start_line = line;
    }

    /* Desde el final */
    int total_new = count_lines(new, new_sz);
    const uint8_t *oe2 = old + old_sz;
    const uint8_t *ne2 = new + new_sz;
    int tail_match = 0;

    while (oe2 > old && ne2 > new) {
        if (oe2 > old && *(oe2 - 1) == '\n') oe2--;
        const uint8_t *os2 = oe2;
        while (os2 > old && *(os2 - 1) != '\n') os2--;

        if (ne2 > new && *(ne2 - 1) == '\n') ne2--;
        const uint8_t *ns2 = ne2;
        while (ns2 > new && *(ns2 - 1) != '\n') ns2--;

        size_t ol2 = (size_t)(oe2 - os2);
        size_t nl2 = (size_t)(ne2 - ns2);

        if (ol2 != nl2 || memcmp(os2, ns2, ol2) != 0)
            break;

        tail_match++;
        oe2 = os2;
        ne2 = ns2;
    }

    *end_line = total_new - tail_match;
    if (*end_line < *start_line)
        *end_line = *start_line;
}

/* ── Extraer SOLO las líneas cambiadas para tokenizar ────── */
static void extract_changed_lines(const uint8_t *new, size_t new_sz,
                                  int start_line, int end_line,
                                  uint8_t *buf, size_t buf_sz, size_t *out_len)
{
    *out_len = 0;
    if (!new || new_sz == 0 || start_line < 1)
        return;

    const uint8_t *p = new;
    const uint8_t *end = new + new_sz;
    int line = 1;
    size_t pos = 0;

    while (p < end && line <= end_line) {
        const uint8_t *line_start = p;
        while (p < end && *p != '\n') p++;
        size_t line_len = (size_t)(p - line_start);
        if (p < end) p++; /* saltar \n */

        if (line >= start_line && line <= end_line) {
            size_t copy = line_len;
            if (pos + copy + 2 > buf_sz)
                break;
            memcpy(buf + pos, line_start, copy);
            pos += copy;
            buf[pos++] = '\n';
        }
        line++;
    }

    if (pos > 0 && pos < buf_sz)
        buf[pos] = '\0';
    else if (pos < buf_sz)
        buf[0] = '\0';
    *out_len = pos;
}

/* ── API pública ─────────────────────────────────────────── */


/* Detecta si un buffer es binario (contiene bytes NUL o alta proporción de no-imprimibles) */
static int is_binary_data(const uint8_t *data, size_t size)
{
    if (size == 0)
        return 0;
    
    size_t sample_size = size < 8192 ? size : 8192;  /* Muestrear primeros 8 KB */
    size_t null_count = 0;
    size_t non_printable = 0;
    
    for (size_t i = 0; i < sample_size; ++i) {
        if (data[i] == 0) {
            null_count++;
        } else if (data[i] < 32 && data[i] != '\n' && data[i] != '\r' && data[i] != '\t') {
            non_printable++;
        }
    }
    
    /* Binario si hay bytes NUL o más del 10% no-imprimibles */
    if (null_count > 0)
        return 1;
    if (non_printable > sample_size / 10)
        return 1;
    
    return 0;
}

void tt_generate_autotag(const uint8_t *old, size_t old_sz,
                         const uint8_t *new, size_t new_sz,
                         char *out, size_t outsz)
{
    if (!out || outsz == 0)
        return;
    out[0] = '\0';

    /* No generar autotags para archivos binarios */
    if (is_binary_data(new, new_sz))
        return;
    if (old && old_sz > 0 && is_binary_data(old, old_sz))
        return;

    /* Encontrar rango de cambio */
    int sl = 1, el = 1;
    find_changed_range(old, old_sz, new, new_sz, &sl, &el);

    /* Extraer SOLO las líneas cambiadas */
    uint8_t buf[8192];
    size_t len = 0;

    if (new_sz > 0) {
        extract_changed_lines(new, new_sz, sl, el, buf, sizeof buf, &len);
    } else if (old_sz > 0) {
        /* DELETE: usar old */
        extract_changed_lines(old, old_sz, sl, el, buf, sizeof buf, &len);
    }

    if (len == 0)
        return;

    TtToken tokens[MAX_TOKENS];
    int ntokens = 0;
    extract_tokens(buf, len, tokens, MAX_TOKENS, &ntokens);

    if (ntokens == 0)
        return;

    qsort(tokens, (size_t)ntokens, sizeof(TtToken), token_cmp);

    int max_tags = 4;
    size_t pos = 0;

    for (int i = 0; i < ntokens && i < max_tags; ++i) {
        int w;
        if (i == 0)
            w = snprintf(out + pos, outsz - pos, "#%s", tokens[i].word);
        else
            w = snprintf(out + pos, outsz - pos, " #%s", tokens[i].word);

        if (w < 0 || (size_t)w >= outsz - pos)
            break;
        pos += (size_t)w;
    }
}

void tt_delta_full_summary(const uint8_t *old, size_t old_sz,
                           const uint8_t *new, size_t new_sz,
                           char *out, size_t outsz)
{
    if (!out || outsz == 0)
        return;
    out[0] = '\0';

    /* No generar autotags para archivos binarios */
    if (is_binary_data(new, new_sz))
        return;
    if (old && old_sz > 0 && is_binary_data(old, old_sz))
        return;

    int old_lines = count_lines(old, old_sz);
    int new_lines = count_lines(new, new_sz);
    int diff = new_lines - old_lines;
    int added = diff > 0 ? diff : 0;
    int removed = diff < 0 ? -diff : 0;

    /* Encontrar rango de líneas cambiadas */
    int sl = 1, el = 1;
    find_changed_range(old, old_sz, new, new_sz, &sl, &el);
    int changed = el - sl + 1;

    /* Si el número total de líneas no cambió pero hay cambios en el contenido,
       las líneas fueron reemplazadas (no añadidas/borradas) */
    if (added == 0 && removed == 0 && changed > 0) {
        /* Mostrar el rango de líneas afectadas como "reemplazadas" */
        /* No asignar changed a added/removed, mantenerlos en 0 */
    }

    /* Formato: +A/-R lines START-END */
    char head[128];
    if (sl == el)
        snprintf(head, sizeof head, "+%d/-%d lines %d", added, removed, sl);
    else
        snprintf(head, sizeof head, "+%d/-%d lines %d-%d", added, removed, sl, el);

    /* Tags (solo de líneas cambiadas) */
    char tags[256] = "";
    tt_generate_autotag(old, old_sz, new, new_sz, tags, sizeof tags);

    /* Componer: "+3/-1 lines 500-503 #tag1 #tag2" */
    if (tags[0])
        snprintf(out, outsz, "%s %s", head, tags);
    else
        snprintf(out, outsz, "%s", head);
}
