// thread_hash.c lab 03 cs 333
// author: ariella marchuk 
// author email: amarchuk@pdx.edu

#define _GNU_SOURCE

#include <time.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <crypt.h>

#define DEFAULT_THREADS 1
#define MAX_THREADS     24

typedef struct config
{
    char *hash_file;   // -i
    char *dict_file;   // -d
    char *out_file;    // -o (opt.)
    int   nthreads;    // -t (def1)
    int   verbose;     // -v
    int   use_nice;    // -n   
} config_t;

// algorithm indices used for stats
typedef enum
{
    ALG_DES = 0,
    ALG_NT,
    ALG_MD5,
    ALG_SHA256,
    ALG_SHA512,
    ALG_YESCRYPT,
    ALG_GOST_YESCRYPT,
    ALG_BCRYPT,
    NUM_ALGOS
} algo_t;

typedef struct hash_entry
{
    char *hash;   // full hash string from file
    int   algo;   // algorithm enum index, -1 IF UNKNOWN
    char *plain;  // cracked password ;;mallocd or NULL if failed
} hash_entry_t;

typedef struct work_queue
{
    hash_entry_t    *hashes;
    size_t           nhashes;
    size_t           next;      // next hash index to assign
    pthread_mutex_t  lock;      // protects next
    FILE            *ofp;       // output file for printing 
    pthread_mutex_t  print_lock;
} work_queue_t;

typedef struct thread_arg
{
    int            thread_id;
    work_queue_t  *queue;
    char         **dict_words;
    size_t         dict_count;

    // per thread stats
    size_t         algo_counts[NUM_ALGOS];
    size_t         total;
    size_t         failed;
    size_t         words_hashed; 
    double         elapsed_sec;
} thread_arg_t;


// ;;;;;;;; utility
static void usage(const char *prog)
{
    /* 
    fprintf(stderr, "usage: %s -i hashfile -d dictfile [-o outfile] [-t threads] [-v]\n", prog);
    exit(EXIT_FAILURE);
    */
    
    fprintf(stderr, "usage: %s -i hashfile -d dictfile [-o outfile] [-t threads] [-v] [-n]\n", prog);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -i filename   Specify the input hash file (required)\n");
    fprintf(stderr, "  -d filename   Specify the dictionary file (required)\n");
    fprintf(stderr, "  -o filename   Specify the output file (default: stdout)\n");
    fprintf(stderr, "  -t #          Specify number of threads (1-%d, default: 1)\n", MAX_THREADS);
    fprintf(stderr, "  -v            Enable verbose output\n");
    fprintf(stderr, "  -n            Apply nice(10) to lower process priority\n");
    fprintf(stderr, "  -h            Display this help message\n");
    exit(EXIT_FAILURE); 
}

static int parse_int(const char *s, int *out)
{
    char *end = NULL;
    long val;

    errno = 0;
    val = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') { return -1; }
    if (val < 1) { return -1; }
    if (val > MAX_THREADS) { val = MAX_THREADS; }
    *out = (int)val;
    return 0;
}

static void trim_newline(char *s)
{
    size_t len;
    if (s == NULL) { return; }
    len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r'))
    {
        s[len - 1] = '\0';
        len--;
    }
}

// ;;;;;;; map hash prefix to algorithm index for stats only
static int detect_algo(const char *hash)
{
    if (hash == NULL || hash[0] == '\0') { return -1; }

    if (hash[0] != '$') { return ALG_DES; }

    if (strncmp(hash, "$1$", 3) == 0)  { return ALG_MD5; }
    if (strncmp(hash, "$3$", 3) == 0)  { return ALG_NT; }
    if (strncmp(hash, "$5$", 3) == 0)  { return ALG_SHA256; }
    if (strncmp(hash, "$6$", 3) == 0)  { return ALG_SHA512; }
    if (strncmp(hash, "$2b$", 4) == 0) { return ALG_BCRYPT; }
    if (strncmp(hash, "$gy$", 4) == 0) { return ALG_GOST_YESCRYPT; }
    if (strncmp(hash, "$y$", 3) == 0)  { return ALG_YESCRYPT; }

    return -1;  // unknown ORRRR not counted
}

static const char *algo_to_string(int algo)
{
    switch (algo)
    {
        case ALG_DES:           return "DES";
        case ALG_NT:            return "NT";
        case ALG_MD5:           return "MD5";
        case ALG_SHA256:        return "SHA256";
        case ALG_SHA512:        return "SHA512";
        case ALG_YESCRYPT:      return "yescrypt";
        case ALG_GOST_YESCRYPT: return "gost-yescrypt";
        case ALG_BCRYPT:        return "bcrypt";
        default:                return "unknown";
    }
}


// ;;;;;;;; file loading / freeing

static void free_dict(char **words, size_t nwords)
{
    size_t i;
    if (words == NULL) { return; }
    for (i = 0; i < nwords; i++) { free(words[i]); }
    free(words);
}

static void free_hashes(hash_entry_t *hashes, size_t nhashes)
{
    size_t i;
    if (hashes == NULL) { return; }
    for (i = 0; i < nhashes; i++)
    {   free(hashes[i].hash);
        free(hashes[i].plain); }
    free(hashes);
}

static void load_dict(const char *filename, char ***words_out, size_t *nwords_out)
{
    FILE    *fp;
    char    *line   = NULL;
    size_t  linecap = 0;
    ssize_t linelen;
    char    **words = NULL;
    size_t  nwords  = 0;
    size_t  cap     = 0;

    fp = fopen(filename, "r");
    if (fp == NULL)
    {   fprintf(stderr, "cannot open dictionary file '%s': %s\n", filename, strerror(errno));
        exit(EXIT_FAILURE); }

    for (;;)
    {
        linelen = getline(&line, &linecap, fp);
        if (linelen < 0) { break; } // eof

        trim_newline(line);
        if (line[0] == '\0') { continue; }

        if (nwords == cap)
        {
            size_t new_cap = (cap == 0) ? 64 : cap * 2;
            char **tmp = realloc(words, new_cap * sizeof(*tmp));
            if (tmp == NULL)
            {
                fprintf(stderr, "out of memory loading dictionary\n");
                free(line);
                fclose(fp);
                free_dict(words, nwords);
                exit(EXIT_FAILURE);
            }
            words = tmp;
            cap   = new_cap;
        }

        {
            size_t len = strlen(line);
            char  *copy = malloc(len + 1);
            if (copy == NULL)
            {
                fprintf(stderr, "out of memory copying dictionary word\n");
                free(line);
                fclose(fp);
                free_dict(words, nwords);
                exit(EXIT_FAILURE);
            }
            memcpy(copy, line, len + 1);
            words[nwords++] = copy;
        }
    }

    if (ferror(fp))
    {
        fprintf(stderr, "error reading dictionary file '%s'\n", filename);
        free(line);
        fclose(fp);
        free_dict(words, nwords);
        exit(EXIT_FAILURE);
    }

    free(line);
    fclose(fp);
    *words_out  = words;
    *nwords_out = nwords;
}

static void load_hashes(const char *filename, hash_entry_t **hashes_out, size_t *nhashes_out)
{
    FILE         *fp;
    char         *line   = NULL;
    size_t       linecap = 0;
    ssize_t      linelen;
    hash_entry_t *hashes = NULL;
    size_t       nhashes = 0;
    size_t       cap     = 0;

    fp = fopen(filename, "r");
    if (fp == NULL)
    {
        fprintf(stderr, "cannot open hash file '%s': %s\n", filename, strerror(errno));
        exit(EXIT_FAILURE);
    }

    for (;;)
    {
        linelen = getline(&line, &linecap, fp);
        if (linelen < 0) { break; }
        trim_newline(line);
        if (line[0] == '\0') { continue; }

        if (nhashes == cap)
        {
            size_t new_cap = (cap == 0) ? 64 : cap * 2;
            hash_entry_t *tmp = realloc(hashes, new_cap * sizeof(*tmp));
            if (tmp == NULL)
            {
                fprintf(stderr, "out of memory loading hashes\n");
                free(line);
                fclose(fp);
                free_hashes(hashes, nhashes);
                exit(EXIT_FAILURE);
            }
            hashes = tmp;
            cap    = new_cap;
        }

        {
            size_t len = strlen(line);
            char  *copy = malloc(len + 1);
            if (copy == NULL)
            {
                fprintf(stderr, "out of memory copying hash line\n");
                free(line);
                fclose(fp);
                free_hashes(hashes, nhashes);
                exit(EXIT_FAILURE);
            }
            memcpy(copy, line, len + 1);

            hashes[nhashes].hash  = copy;
            hashes[nhashes].algo  = -1;    // ermm for later....
            hashes[nhashes].plain = NULL;
            nhashes++;
        }
    }

    if (ferror(fp))
    {
        fprintf(stderr, "error reading hash file '%s'\n", filename);
        free(line);
        fclose(fp);
        free_hashes(hashes, nhashes);
        exit(EXIT_FAILURE);
    }

    free(line);
    fclose(fp);
    *hashes_out  = hashes;
    *nhashes_out = nhashes;
}


// ;;;;;;; stats printing
static void print_stats_line(const char *label, int id, double elapsed, const size_t counts[NUM_ALGOS], size_t total, size_t failed)
{
    fprintf(stderr, "%-6s: %3d %9.2f sec"
           "              DES:%8zu"
           "               NT:%8zu"
           "              MD5:%8zu"
           "           SHA256:%8zu"
           "           SHA512:%8zu"
           "         YESCRYPT:%8zu"
           "    GOST_YESCRYPT:%8zu"
           "           BCRYPT:%8zu"
           "  total:%9zu"
           "  failed:%9zu\n",
           label, id, elapsed,
           counts[ALG_DES],
           counts[ALG_NT],
           counts[ALG_MD5],
           counts[ALG_SHA256],
           counts[ALG_SHA512],
           counts[ALG_YESCRYPT],
           counts[ALG_GOST_YESCRYPT],
           counts[ALG_BCRYPT],
           total, failed);
}


// ;;;;;;;; single-thread cracker
static void crack_all_single(hash_entry_t *hashes, size_t nhashes, char **dict_words, size_t dict_count, FILE *ofp)
{
    size_t algo_counts[NUM_ALGOS] = {0};
    size_t total                  = 0;
    size_t failed                 = 0;
    struct timespec t0, t1;
    struct crypt_data data;
    size_t i;
    size_t di;
    double elapsed;

    clock_gettime(CLOCK_MONOTONIC, &t0);
    memset(&data, 0, sizeof(data));
    data.initialized = 0;

    for (i = 0; i < nhashes; i++)
    {
        hash_entry_t *he = &hashes[i];

        total++;
        if (he->algo >= 0 && he->algo < NUM_ALGOS) { algo_counts[he->algo]++; }

        he->plain = NULL;
        for (di = 0; di < dict_count; di++)
        {
            const char *word = dict_words[di];
            char *res = crypt_rn(word, he->hash, &data, (int)sizeof(data));
            if (res == NULL) { continue; }

            if (strcmp(res, he->hash) == 0)
            {
                size_t len = strlen(word);
                char *copy = malloc(len + 1);
                if (copy != NULL)
                {
                    memcpy(copy, word, len + 1);
                    he->plain = copy;
                }
                break;
            }
        }
        /* 
        if (he->plain == NULL) { failed++; }
        */

        if (he->plain == NULL) 
        {
            failed++;
            fprintf(ofp, "*** failed to crack  %s\n", he->hash);
        }
        else
        {
            fprintf(ofp, "cracked  %s  %s\n", he->plain, he->hash);
        }
        fflush(ofp);
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    elapsed = (t1.tv_sec  - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

    print_stats_line("thread", 0, elapsed, algo_counts, total, failed);
    print_stats_line("total", 1, elapsed, algo_counts, total, failed);
}


// ;;;;;;; multithread worker helper
static void *worker_func(void *arg)
{
    thread_arg_t   *targ = (thread_arg_t *)arg;
    work_queue_t   *q    = targ->queue;
    struct crypt_data cdata;
    size_t i;
    size_t idx;
    hash_entry_t *he;
    struct timespec t0, t1;

    // STRT TIMR
    clock_gettime(CLOCK_MONOTONIC, &t0);
    memset(&cdata, 0, sizeof(cdata));
    cdata.initialized = 0; 

    for (;;)
    {
        // grab next hash index from shared queue
        pthread_mutex_lock(&q->lock);
        if (q->next >= q->nhashes)
        {   pthread_mutex_unlock(&q->lock);
            break; }
        idx = q->next;
        q->next++;
        pthread_mutex_unlock(&q->lock);
        he = &q->hashes[idx];

        // stats...... one more hash processed
        targ->total++;
        if (he->algo >= 0 && he->algo < NUM_ALGOS) { targ->algo_counts[he->algo]++; }

        // is plain NULL before cracking ?????????
        he->plain = NULL;
        
        /*
        memset(&cdata, 0, sizeof(cdata));
        */

        for (i = 0; i < targ->dict_count; i++)
        {   const char *word = targ->dict_words[i];
            char *res = crypt_rn(word, he->hash, &cdata, (int)sizeof(cdata));
            targ->words_hashed++;

            if (res == NULL) { continue; }

            if (strcmp(res, he->hash) == 0)
            {   size_t len = strlen(word);
                char  *copy = malloc(len + 1);
                if (copy != NULL)
                {   memcpy(copy, word, len + 1);
                    he->plain = copy; }
                break;    } }
        

        /* 
        if (he->plain == NULL) { targ->failed++;}
        */

        pthread_mutex_lock(&q->print_lock);   
        if (he->plain == NULL)
        {
            targ->failed++;
            fprintf(q->ofp, "*** failed to crack  %s\n", he->hash);
        }
        else
        {
            fprintf(q->ofp, "cracked  %s  %s\n", he->plain, he->hash);
        }
        fflush(q->ofp);
        pthread_mutex_unlock(&q->print_lock);
    }
    // STOP TIMER &RECORD ELPASED TIME FOR THIS THREAD
    clock_gettime(CLOCK_MONOTONIC, &t1);
    targ->elapsed_sec = (t1.tv_sec  - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    return NULL;
}

// ;;;;;;; multithread cracker
static void crack_all_multi(hash_entry_t *hashes, size_t nhashes, char **dict_words, size_t dict_count, int nthreads, FILE *ofp)
{
    work_queue_t  q;
    pthread_t    *tids;
    thread_arg_t *args;
    int           i;
    size_t        total_counts[NUM_ALGOS] = {0};
    size_t        grand_total  = 0;
    size_t        grand_failed = 0;
    size_t        grand_words  = 0;
    double        max_elapsed  = 0.0;
    int           a;

    q.hashes  = hashes;
    q.nhashes = nhashes;
    q.next    = 0;
    q.ofp     = ofp; 
    pthread_mutex_init(&q.lock, NULL);
    pthread_mutex_init(&q.print_lock, NULL); 

    tids = calloc(nthreads, sizeof(*tids));
    args = calloc(nthreads, sizeof(*args));
    if (!tids || !args)
    {
        fprintf(stderr, "out of memory for threads\n");
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < nthreads; i++)
    {
        args[i].thread_id  = i;
        args[i].queue      = &q;
        args[i].dict_words = dict_words;
        args[i].dict_count = dict_count;
        args[i].words_hashed = 0;

        if (pthread_create(&tids[i], NULL, worker_func, &args[i]) != 0)
        {
            fprintf(stderr, "pthread_create failed\n");
            exit(EXIT_FAILURE);
        }
    }

    for (i = 0; i < nthreads; i++) { pthread_join(tids[i], NULL); }

    // aggregate + print stats
    for (i = 0; i < nthreads; i++)
    {
        print_stats_line("thread", args[i].thread_id,
                         args[i].elapsed_sec,
                         args[i].algo_counts,
                         args[i].total,
                         args[i].failed);

        if (args[i].elapsed_sec > max_elapsed) { max_elapsed = args[i].elapsed_sec; }

        grand_total  += args[i].total;
        grand_failed += args[i].failed;
        grand_words  += args[i].words_hashed;
        for (a = 0; a < NUM_ALGOS; a++) { total_counts[a] += args[i].algo_counts[a]; }
    }

    print_stats_line("total", nthreads, max_elapsed, total_counts, grand_total, grand_failed);
    free(tids);
    free(args);
    pthread_mutex_destroy(&q.lock);
    pthread_mutex_destroy(&q.print_lock); 
}

/*
// ;;;;;;;; result output 
static void write_results_single(FILE *ofp, const hash_entry_t *hashes, size_t hash_count)
{
    size_t i;

    for (i = 0; i < hash_count; i++)
    {
        // match expected output
        if (hashes[i].plain != NULL) { fprintf(ofp, "cracked  %s  %s\n", hashes[i].plain, hashes[i].hash); }
        else { fprintf(ofp, "*** failed to crack  %s\n", hashes[i].hash); }
    }

    if (fflush(ofp) == EOF)
    {
        fprintf(stderr, "error flushing output: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}
*/

// ;;;;;;; beginning of main 
int main(int argc, char *argv[])
{
    config_t      cfg;
    int           opt;
    char        **dict_words   = NULL;
    size_t        dict_count   = 0;
    hash_entry_t *hashes       = NULL;
    size_t        hash_count   = 0;
    FILE         *ofp          = stdout;

    cfg.hash_file = NULL;
    cfg.dict_file = NULL;
    cfg.out_file  = NULL;
    cfg.nthreads  = DEFAULT_THREADS;
    cfg.verbose   = 0;
    cfg.use_nice  = 0;

    while ((opt = getopt(argc, argv, "i:d:o:t:vnh")) != -1)
    {
        switch (opt)
        {
            case 'i':
                cfg.hash_file = optarg;
                break;

            case 'd':
                cfg.dict_file = optarg;
                break;

            case 'o':
                cfg.out_file = optarg;
                break;

            case 't':
                if (parse_int(optarg, &cfg.nthreads) != 0)
                {
                    fprintf(stderr, "invalid thread count '%s' (must be 1..%d)\n", optarg, MAX_THREADS);
                    usage(argv[0]);
                }
                break;

            case 'v':
                cfg.verbose = 1;
                break;

            case 'n': 
                cfg.use_nice = 1;
                break;

            case 'h':
            default:
                usage(argv[0]);
                break;
        }
    }

    if (optind != argc)
    {
        fprintf(stderr, "unexpected extra arguments\n");
        usage(argv[0]);
    }

    if (cfg.hash_file == NULL || cfg.dict_file == NULL)
    {
        fprintf(stderr, "both -i hashfile and -d dictfile are required\n");
        usage(argv[0]);
    }

    if (cfg.use_nice)
    {
        if(nice(10) == -1)
        {
            fprintf(stderr, "warning: nice(10) failed: %s\n", strerror(errno));
        }
    }

    load_hashes(cfg.hash_file, &hashes, &hash_count);
    load_dict(cfg.dict_file, &dict_words, &dict_count);

    // fill algo field for each hash STATS ONLY
    {
        size_t i;
        for (i = 0; i < hash_count; i++) { hashes[i].algo = detect_algo(hashes[i].hash); }
    }

    if (cfg.out_file != NULL)
    {
        ofp = fopen(cfg.out_file, "w");
        if (ofp == NULL)
        {
            fprintf(stderr, "cannot open output file '%s': %s\n", cfg.out_file, strerror(errno));
            free_hashes(hashes, hash_count);
            free_dict(dict_words, dict_count);
            exit(EXIT_FAILURE);
        }
    }

    if (cfg.verbose)
    {
        size_t algo_counts[NUM_ALGOS] = {0};
        size_t i;

        for (i = 0; i < hash_count; i++)
        {
            int a = hashes[i].algo;
            if (a >= 0 && a < NUM_ALGOS) { algo_counts[a]++; }
        }

        fprintf(stderr, "loaded %zu hashes from %s\n loaded %zu dictionary words from %s\n",
                hash_count, cfg.hash_file,
                dict_count, cfg.dict_file);

        for (i = 0; i < NUM_ALGOS; i++) { if (algo_counts[i] > 0) { fprintf(stderr, "  %s: %zu\n", algo_to_string((int)i), algo_counts[i]); } }

        fprintf(stderr, "hash file : %s\n", cfg.hash_file);
        fprintf(stderr, "dict file : %s\n", cfg.dict_file);
        fprintf(stderr, "out file  : %s\n", cfg.out_file ? cfg.out_file : "(stdout)");
        fprintf(stderr, "threads   : %d\n", cfg.nthreads);
        fprintf(stderr, "verbose   : %s\n", cfg.verbose ? "yes" : "no");
        fprintf(stderr, "nice      : %s\n", cfg.use_nice ? "yes" : "no");
        fprintf(stderr, "hashes    : %zu\n", hash_count);
        fprintf(stderr, "dict size : %zu\n", dict_count);
    }

    if (cfg.nthreads <= 1) { crack_all_single(hashes, hash_count, dict_words, dict_count, ofp); }
    else { crack_all_multi(hashes, hash_count, dict_words, dict_count, cfg.nthreads, ofp); }
    
    /*
    write_results_single(ofp, hashes, hash_count);
    */

    if (ofp != stdout) { fclose(ofp); }
    free_hashes(hashes, hash_count);
    free_dict(dict_words, dict_count);

    return 0;
}

// ;;;;;;; end of main
