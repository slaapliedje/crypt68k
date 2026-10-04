/*
 * mul_timing - what a 68020/030/040's multiply time depends on. The
 * MC68030 manual says only "data dependent". Times mulu.l Dh:Dl (32x32
 * -> 64) and mulu.w (16x16 -> 32) with one operand fixed at all ones and
 * the other a pattern (zero, one, small, a top bit, alternating bits,
 * all ones), each way round: if the times differ, X25519's multiplies
 * aren't constant time on this CPU, and the pattern says how to mask it.
 * 68k only (gcc inline assembly); integers only.
 *
 *   mul_timing [rounds [runs]]   (default 25000 and 5: about five
 *                                minutes on a 32 MHz 68030)
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static long us(clock_t d)
{
	long t = (long)d, cps = (long)CLOCKS_PER_SEC;

	return t / cps * 1000000L + t % cps * 1000000L / cps;
}

/* rounds x 16 of: move.l dst,%d0; mulu.l src,%d1:%d0 */
static long time_l(unsigned long src, unsigned long dst, long rounds)
{
	clock_t t0 = clock();
	long n = rounds - 1;

	__asm__ volatile(
		"1:\n\t"
		"move.l %[d],%%d0\n\tmulu.l %[s],%%d1:%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.l %[s],%%d1:%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.l %[s],%%d1:%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.l %[s],%%d1:%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.l %[s],%%d1:%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.l %[s],%%d1:%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.l %[s],%%d1:%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.l %[s],%%d1:%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.l %[s],%%d1:%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.l %[s],%%d1:%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.l %[s],%%d1:%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.l %[s],%%d1:%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.l %[s],%%d1:%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.l %[s],%%d1:%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.l %[s],%%d1:%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.l %[s],%%d1:%%d0\n\t"
		"sub.l %[one],%[n]\n\t"
		"jpl 1b"
		: [n] "+d" (n)
		: [s] "d" (src), [d] "d" (dst), [one] "d" (1L)
		: "d0", "d1", "cc");
	return us(clock() - t0);
}

/* the same with mulu.w src,%d0 */
static long time_w(unsigned long src, unsigned long dst, long rounds)
{
	clock_t t0 = clock();
	long n = rounds - 1;

	__asm__ volatile(
		"1:\n\t"
		"move.l %[d],%%d0\n\tmulu.w %[s],%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.w %[s],%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.w %[s],%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.w %[s],%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.w %[s],%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.w %[s],%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.w %[s],%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.w %[s],%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.w %[s],%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.w %[s],%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.w %[s],%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.w %[s],%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.w %[s],%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.w %[s],%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.w %[s],%%d0\n\t"
		"move.l %[d],%%d0\n\tmulu.w %[s],%%d0\n\t"
		"sub.l %[one],%[n]\n\t"
		"jpl 1b"
		: [n] "+d" (n)
		: [s] "d" (src), [d] "d" (dst), [one] "d" (1L)
		: "d0", "cc");
	return us(clock() - t0);
}

static const unsigned long pats[] = {
	0x00000000UL, 0x00000001UL, 0x000000ffUL, 0x0000ffffUL, 0x00010000UL,
	0x00ffffffUL, 0x7fffffffUL, 0x80000000UL, 0x55555555UL, 0xaaaaaaaaUL,
	0x0f0f0f0fUL, 0xffff0000UL, 0x0000fff0UL, 0xffffffffUL
};
#define NPAT	(sizeof pats / sizeof pats[0])

/* ns per operation, without overflowing a 32-bit long */
static long per_op(long t, long per)
{
	return t / per * 1000 + t % per * 1000 / per;
}

static long measure(int v, unsigned long p, long rounds)
{
	switch (v) {
	case 0: return time_l(p, 0xffffffffUL, rounds);
	case 1: return time_l(0xffffffffUL, p, rounds);
	case 2: return time_w(p, 0xffffffffUL, rounds);
	default: return time_w(0xffffffffUL, p, rounds);
	}
}

int main(int argc, char **argv)
{
	long rounds = argc > 1 ? atol(argv[1]) : 25000, per = rounds * 16, t;
	int reps = argc > 2 ? atoi(argv[2]) : 5, r, v;
	static long best[NPAT][4], worst[NPAT][4];
	size_t i;

	/* interrupts only ever add time: interleave the cases, keep each
	 * one's fastest run */
	for (r = 0; r < reps; r++)
		for (i = 0; i < NPAT; i++)
			for (v = 0; v < 4; v++) {
				t = measure(v, pats[i], rounds);
				if (r == 0 || t < best[i][v])
					best[i][v] = t;
				if (r == 0 || t > worst[i][v])
					worst[i][v] = t;
			}
	printf("ns per (move.l + multiply), fastest of %d runs of %ld"
		" (slowest in brackets):\n", reps, per);
	printf("  operand     mulu.l src     mulu.l dst     mulu.w src     mulu.w dst\n");
	for (i = 0; i < NPAT; i++) {
		printf("  %08lx", pats[i]);
		for (v = 0; v < 4; v++)
			printf("  %5ld (%5ld)", per_op(best[i][v], per), per_op(worst[i][v], per));
		printf("\n");
	}
	return 0;
}
