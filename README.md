# multithreaded-password-recovery

![language](https://img.shields.io/badge/language-C-blue) ![platform](https://img.shields.io/badge/platform-Linux-lightgrey)
![CI](https://github.com/arikthehacker/multithreaded-password-recovery/actions/workflows/ci.yml/badge.svg)

A dictionary-based password recovery tool for Unix `crypt` hashes. It reads a file of
hashes and a dictionary, then cracks the hashes in parallel with a pool of worker
threads pulling from one shared queue.

## quickstart

```
git clone https://github.com/arikthehacker/multithreaded-password-recovery.git
cd multithreaded-password-recovery
sudo apt-get install -y build-essential libcrypt-dev
make run
```

expected output:

```
cracked  password  $1$Ab12Cd34$gENNEu3GnAE8/LHr/AbXs.
cracked  dragon  $5$Ef56Gh78$e7MLF9PRZsmyG4y2eLSqxtBKbHapO4Jtik5vebiLs6C
cracked  trustno1  $6$Ij90Kl12$SH1nDU/QRe9fr9ncwOx7ljuu/U8qw8TRrgG5cvI600TT1/Lh2ny/QOhqb0ofbCoQjIPIn2GQuIIB2gIbOXZm2/
cracked  swordfish  $6$Mn34Op56$ROJFWwgwnnvGHz1O/xr2zV6WwGyx3LKuT2MKEeqwtrqoIfKB2UKBq7TB.cyDO/35l72zI8UYaNiGVUvzsZhDQ.
```

`example-hashes.txt` holds four hashes (MD5, SHA256, and two SHA512) whose plaintexts are
words in `example-dict.txt`, so the run above cracks all four. It recognizes 8 hash
types: DES, NT, MD5, SHA256, SHA512, yescrypt, gost-yescrypt, and bcrypt.

## how it works

There is one work queue shared by all threads. It holds the array of hash entries and a
`next` index for the entry to hand out next. A mutex protects `next`, and a second mutex
serializes printing so output lines do not interleave:

```c
typedef struct work_queue
{
    hash_entry_t    *hashes;
    size_t           nhashes;
    size_t           next;      // next hash index to assign
    pthread_mutex_t  lock;      // protects next
    FILE            *ofp;       // output file for printing
    pthread_mutex_t  print_lock;
} work_queue_t;
```

Each worker loops: lock the queue, take the current index, bump it, unlock, then crack
that one hash against the whole dictionary. When `next` runs past the end it stops:

```c
pthread_mutex_lock(&q->lock);
if (q->next >= q->nhashes)
{   pthread_mutex_unlock(&q->lock);
    break; }
idx = q->next;
q->next++;
pthread_mutex_unlock(&q->lock);
he = &q->hashes[idx];
```

Each thread keeps its own per-algorithm counts, totals, and timing, which are merged
into one summary after the joins. Cracking uses the reentrant `crypt_rn` with a
per-thread `crypt_data` buffer so threads do not share crypt state.

## options

```
-i filename   input hash file (required)
-d filename   dictionary file (required)
-o filename   output file (default: stdout)
-t #          number of threads, 1 to 24 (default: 1)
-v            verbose output
-n            apply nice(10) to lower process priority
-h            help
```
