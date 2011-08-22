// MD5.cpp - Modification (c) 2011 Tobias Sielaff.
//
// Thanks for the idea to reverse of the last round and for very
// valuable suggestions to sc00bz.
// 
// Also thanks to OpenSSL for their streamlined implementation of
// F and G.
//
// Based on:
// MD5.CC - source code for the C++/object oriented translation and 
//          modification of MD5.
//
// Translation and modification (c) 1995 by Mordechai T. Abzug 
//
// This translation/ modification is provided "as is," without express or 
// implied warranty of any kind.
//
// The translator/ modifier does not claim (1) that MD5 will do what you think 
// it does; (2) that this translation/ modification is accurate; or (3) that 
// this software is "merchantible."  (Language for this disclaimer partially 
// copied from the disclaimer below).
//
// Based on:
// MD5C.C - RSA Data Security, Inc., MD5 message-digest algorithm
// MDDRIVER.C - test driver for MD2, MD4 and MD5
//
// Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
// rights reserved.
//
// License to copy and use this software is granted provided that it
// is identified as the "RSA Data Security, Inc. MD5 Message-Digest
// Algorithm" in all material mentioning or referencing this software
// or this function.
//
// License is also granted to make and use derivative works provided
// that such works are identified as "derived from the RSA Data
// Security, Inc. MD5 Message-Digest Algorithm" in all material
// mentioning or referencing the derived work.
//
// RSA Data Security, Inc. makes no representations concerning either
// the merchantability of this software or the suitability of this
// software for any particular purpose. It is provided "as is"
// without express or implied warranty of any kind.
//
// These notices must be retained in any copies of any part of this
// documentation and/or software.

#include "Main.h"
#include <iostream>
#include <string>
#include <boost/thread.hpp>
#include "MD5.h"

using namespace std;


// Constants for MD5Transform routine.
// Although we could use C++ style constants, defines are actually better,
// since they let us easily evade scope clashes.
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

// More constants.
__m128i AC1 = _mm_set1_epi32(0xd76aa478);
__m128i AC2 = _mm_set1_epi32(0xe8c7b756);
__m128i AC3 = _mm_set1_epi32(0x242070db);
__m128i AC4 = _mm_set1_epi32(0xc1bdceee);
__m128i AC5 = _mm_set1_epi32(0xf57c0faf);
__m128i AC6 = _mm_set1_epi32(0x4787c62a);
__m128i AC7 = _mm_set1_epi32(0xa8304613);
__m128i AC8 = _mm_set1_epi32(0xfd469501);
__m128i AC9 = _mm_set1_epi32(0x698098d8);
__m128i AC10 = _mm_set1_epi32(0x8b44f7af);
__m128i AC11 = _mm_set1_epi32(0xffff5bb1);
__m128i AC12 = _mm_set1_epi32(0x895cd7be);
__m128i AC13 = _mm_set1_epi32(0x6b901122);
__m128i AC14 = _mm_set1_epi32(0xfd987193);
__m128i AC15 = _mm_set1_epi32(0xa679438e);
__m128i AC16 = _mm_set1_epi32(0x49b40821);
__m128i AC17 = _mm_set1_epi32(0xf61e2562);
__m128i AC18 = _mm_set1_epi32(0xc040b340);
__m128i AC19 = _mm_set1_epi32(0x265e5a51);
__m128i AC20 = _mm_set1_epi32(0xe9b6c7aa);
__m128i AC21 = _mm_set1_epi32(0xd62f105d);
__m128i AC22 = _mm_set1_epi32(0x02441453);
__m128i AC23 = _mm_set1_epi32(0xd8a1e681);
__m128i AC24 = _mm_set1_epi32(0xe7d3fbc8);
__m128i AC25 = _mm_set1_epi32(0x21e1cde6);
__m128i AC26 = _mm_set1_epi32(0xc33707d6);
__m128i AC27 = _mm_set1_epi32(0xf4d50d87);
__m128i AC28 = _mm_set1_epi32(0x455a14ed);
__m128i AC29 = _mm_set1_epi32(0xa9e3e905);
__m128i AC30 = _mm_set1_epi32(0xfcefa3f8);
__m128i AC31 = _mm_set1_epi32(0x676f02d9);
__m128i AC32 = _mm_set1_epi32(0x8d2a4c8a);
__m128i AC33 = _mm_set1_epi32(0xfffa3942);
__m128i AC34 = _mm_set1_epi32(0x8771f681);
__m128i AC35 = _mm_set1_epi32(0x6d9d6122);
__m128i AC36 = _mm_set1_epi32(0xfde5380c);
__m128i AC37 = _mm_set1_epi32(0xa4beea44);
__m128i AC38 = _mm_set1_epi32(0x4bdecfa9);
__m128i AC39 = _mm_set1_epi32(0xf6bb4b60);
__m128i AC40 = _mm_set1_epi32(0xbebfbc70);
__m128i AC41 = _mm_set1_epi32(0x289b7ec6);
__m128i AC42 = _mm_set1_epi32(0xeaa127fa);
__m128i AC43 = _mm_set1_epi32(0xd4ef3085);
__m128i AC44 = _mm_set1_epi32(0x04881d05);
__m128i AC45 = _mm_set1_epi32(0xd9d4d039);
__m128i AC46 = _mm_set1_epi32(0xe6db99e5);
__m128i AC47 = _mm_set1_epi32(0x1fa27cf8);
__m128i AC48 = _mm_set1_epi32(0xc4ac5665);
__m128i AC49 = _mm_set1_epi32(0xf4292244);
__m128i AC50 = _mm_set1_epi32(0x432aff97);
__m128i AC51 = _mm_set1_epi32(0xab9423a7);
__m128i AC52 = _mm_set1_epi32(0xfc93a039);
__m128i AC53 = _mm_set1_epi32(0x655b59c3);
__m128i AC54 = _mm_set1_epi32(0x8f0ccc92);
__m128i AC55 = _mm_set1_epi32(0xffeff47d);
__m128i AC56 = _mm_set1_epi32(0x85845dd1);
__m128i AC57 = _mm_set1_epi32(0x6fa87e4f);
__m128i AC58 = _mm_set1_epi32(0xfe2ce6e0);
__m128i AC59 = _mm_set1_epi32(0xa3014314);
__m128i AC60 = _mm_set1_epi32(0x4e0811a1);
__m128i AC61 = _mm_set1_epi32(0xf7537e82);
__m128i AC62 = _mm_set1_epi32(0xbd3af235);
__m128i AC63 = _mm_set1_epi32(0x2ad7d2bb);
__m128i AC64 = _mm_set1_epi32(0xeb86d391);
__m128i MAX32 = _mm_set1_epi32(0xFFFFFFFF);

// Even more constants.
__m128i baseA = _mm_set1_epi32(0x67452301);
__m128i baseB = _mm_set1_epi32(0xefcdab89);
__m128i baseC = _mm_set1_epi32(0x98badcfe);
__m128i baseD = _mm_set1_epi32(0x10325476);

// Orginal state, pre-reversed.
uint4 state_org[4];

// Create 128bit struct for comparing
__m128i *chk_a, *chk_b, *chk_c, *chk_d;

// ROTATE_LEFT rotates x left n bits, ROTATE_RIGHT rotates x right n bits.
#define rotate_left(x, n)			(((x) << (n)) | ((x) >> (32-(n))))
#define rotate_right(x, n)			(((x) >> (n)) | ((x) << (32-(n))))

// F, G, H and I are basic MD5 functions.
#define F(x,y,z)			((z) ^ ((x) & ((y) ^ (z)))) 
#define G(x,y,z)			((y) ^ ((z) & ((x) ^ (y)))) 
#define H(x, y, z)			((x) ^ (y) ^ (z))
#define I(x, y, z)			((y) ^ ((x) | (~z)))
#define I_32(x, y, z)		((y) ^ ((x) | (~z)))

// FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
// Rotation is separate from addition to prevent recomputation.
#define FF_FULL(a, b, c, d, x, s, ac) {								\
	(a[0]) = (a[0]) + F((b[0]), (c[0]), (d[0])) + (x[0]) + (ac);	\
	(a[1]) = (a[1]) + F((b[1]), (c[1]), (d[1])) + (x[1]) + (ac);	\
	(a[2]) = (a[2]) + F((b[2]), (c[2]), (d[2])) + (x[2]) + (ac);	\
	(a[0]) = rotate_left((a[0]), (s)) + (b[0]);						\
	(a[1]) = rotate_left((a[1]), (s)) + (b[1]);						\
	(a[2]) = rotate_left((a[2]), (s)) + (b[2]);						\
}

#define GG_FULL(a, b, c, d, x, s, ac) {								\
	(a[0]) = (a[0]) + G((b[0]), (c[0]), (d[0])) + (x[0]) + (ac);	\
	(a[1]) = (a[1]) + G((b[1]), (c[1]), (d[1])) + (x[1]) + (ac);	\
	(a[2]) = (a[2]) + G((b[2]), (c[2]), (d[2])) + (x[2]) + (ac);	\
	(a[0]) = rotate_left((a[0]), (s)) + (b[0]);						\
	(a[1]) = rotate_left((a[1]), (s)) + (b[1]);						\
	(a[2]) = rotate_left((a[2]), (s)) + (b[2]);						\
}

#define HH_FULL(a, b, c, d, x, s, ac) {								\
	(a[0]) = (a[0]) + H((b[0]), (c[0]), (d[0])) + (x[0]) + (ac);	\
	(a[1]) = (a[1]) + H((b[1]), (c[1]), (d[1])) + (x[1]) + (ac);	\
	(a[2]) = (a[2]) + H((b[2]), (c[2]), (d[2])) + (x[2]) + (ac);	\
	(a[0]) = rotate_left((a[0]), (s)) + (b[0]);						\
	(a[1]) = rotate_left((a[1]), (s)) + (b[1]);						\
	(a[2]) = rotate_left((a[2]), (s)) + (b[2]);						\
}

#define II_FULL(a, b, c, d, x, s, ac) {								\
	(a[0]) = (a[0]) + I((b[0]), (c[0]), (d[0])) + (x[0]) + (ac);	\
	(a[1]) = (a[1]) + I((b[1]), (c[1]), (d[1])) + (x[1]) + (ac);	\
	(a[2]) = (a[2]) + I((b[2]), (c[2]), (d[2])) + (x[2]) + (ac);	\
	(a[0]) = rotate_left((a[0]), (s)) + (b[0]);						\
	(a[1]) = rotate_left((a[1]), (s)) + (b[1]);						\
	(a[2]) = rotate_left((a[2]), (s)) + (b[2]);						\
}

#define FF_NULL(a, b, c, d, x, s, ac) {					\
	(a[0]) = (a[0]) + F((b[0]), (c[0]), (d[0])) + (ac);	\
	(a[1]) = (a[1]) + F((b[1]), (c[1]), (d[1])) + (ac);	\
	(a[2]) = (a[2]) + F((b[2]), (c[2]), (d[2])) + (ac);	\
	(a[0]) = rotate_left((a[0]), (s)) + (b[0]);			\
	(a[1]) = rotate_left((a[1]), (s)) + (b[1]);			\
	(a[2]) = rotate_left((a[2]), (s)) + (b[2]);			\
}

#define GG_NULL(a, b, c, d, x, s, ac) {					\
	(a[0]) = (a[0]) + G((b[0]), (c[0]), (d[0])) + (ac);	\
	(a[1]) = (a[1]) + G((b[1]), (c[1]), (d[1])) + (ac);	\
	(a[2]) = (a[2]) + G((b[2]), (c[2]), (d[2])) + (ac);	\
	(a[0]) = rotate_left((a[0]), (s)) + (b[0]);			\
	(a[1]) = rotate_left((a[1]), (s)) + (b[1]);			\
	(a[2]) = rotate_left((a[2]), (s)) + (b[2]);			\
}

#define HH_NULL(a, b, c, d, x, s, ac) {					\
	(a[0]) = (a[0]) + H((b[0]), (c[0]), (d[0])) + (ac);	\
	(a[1]) = (a[1]) + H((b[1]), (c[1]), (d[1])) + (ac);	\
	(a[2]) = (a[2]) + H((b[2]), (c[2]), (d[2])) + (ac);	\
	(a[0]) = rotate_left((a[0]), (s)) + (b[0]);			\
	(a[1]) = rotate_left((a[1]), (s)) + (b[1]);			\
	(a[2]) = rotate_left((a[2]), (s)) + (b[2]);			\
}

#define II_NULL(a, b, c, d, x, s, ac) {					\
	(a[0]) = (a[0]) + I((b[0]), (c[0]), (d[0])) + (ac);	\
	(a[1]) = (a[1]) + I((b[1]), (c[1]), (d[1])) + (ac);	\
	(a[2]) = (a[2]) + I((b[2]), (c[2]), (d[2])) + (ac);	\
	(a[0]) = rotate_left((a[0]), (s)) + (b[0]);			\
	(a[1]) = rotate_left((a[1]), (s)) + (b[1]);			\
	(a[2]) = rotate_left((a[2]), (s)) + (b[2]);			\
}

#define II_REV(a, b, c, d, x, s, ac) \
	(a) = rotate_right(((a) - (b)), (s)) - (x) -		\
		  (uint4)(ac) - I_32((b), (c), (d));		


// Initialization.
bool MD5Init(string hash)
{
	// Length correct?
	if (hash.size() != 32)
		return false;

	// Only hex?
	for (size_t i = 0; i < hash.size(); i++)
		if (!isxdigit(hash[i]))
			return false;

	// Temporary var.
	uint1 digest_rev[16];

	// Turn hex encoded string back into bytes.
	for (unsigned int i = 0; i < hash.size() / 2; i++) {
		int val = 0;
		stringstream ss;
		ss << hash.substr(i * 2, 2);
		ss >> setprecision(2) >> hex >> val;
		digest_rev[i] = (uint1)val;
	}

	// Copy everything to our state array.
	memcpy(state_org, digest_rev, 16);

	// Substract the magic.
	state_org[0] -= 0x67452301;
	state_org[1] -= 0xefcdab89;
	state_org[2] -= 0x98badcfe;
	state_org[3] -= 0x10325476;

	// Init the compare array (thread-safe).
	chk_a = new __m128i[boost::thread::hardware_concurrency()];
	chk_b = new __m128i[boost::thread::hardware_concurrency()];
	chk_c = new __m128i[boost::thread::hardware_concurrency()];
	chk_d = new __m128i[boost::thread::hardware_concurrency()];

	// Everything fine.
	return true;
}

// Reverse the last round of MD5 once data[1] changes.
// Why not strlen? I don't null-terminate the plain.
void MD5Reverse(const char* plain, const int len, const int threadIdx)
{
	// Create x.
	const uint4 *x = (uint4*)&plain[0];

	// Init.
	uint4 revA = state_org[0];
	uint4 revB = state_org[1];
	uint4 revC = state_org[2];
	uint4 revD = state_org[3];
	
	// Reverse.
	II_REV (revB, revC, revD, revA,      0, S44, 0xeb86d391); // 64
	II_REV (revC, revD, revA, revB,      0, S43, 0x2ad7d2bb); // 63
	II_REV (revD, revA, revB, revC,      0, S42, 0xbd3af235); // 62
	II_REV (revA, revB, revC, revD,      0, S41, 0xf7537e82); // 61
	II_REV (revB, revC, revD, revA,      0, S44, 0x4e0811a1); // 60
	II_REV (revC, revD, revA, revB,      0, S43, 0xa3014314); // 59
	II_REV (revD, revA, revB, revC,      0, S42, 0xfe2ce6e0); // 58
	II_REV (revA, revB, revC, revD,      0, S41, 0x6fa87e4f); // 57
	II_REV (revB, revC, revD, revA,   x[1], S44, 0x85845dd1); // 56
	II_REV (revC, revD, revA, revB,      0, S43, 0xffeff47d); // 55
	II_REV (revD, revA, revB, revC,      0, S42, 0x8f0ccc92); // 54
	II_REV (revA, revB, revC, revD,      0, S41, 0x655b59c3); // 53
	II_REV (revB, revC, revD, revA,      0, S44, 0xfc93a039); // 52
	II_REV (revC, revD, revA, revB, len<<3, S43, 0xab9423a7); // 51
	II_REV (revD, revA, revB, revC,      0, S42, 0x432aff97); // 50
	II_REV (revA, revB, revC, revD,      0, S41, 0xf4292244); // 49

	// Save it (thread-dependend memory location).
	chk_a[threadIdx] = _mm_set1_epi32(revA);
	chk_b[threadIdx] = _mm_set1_epi32(revB);
	chk_c[threadIdx] = _mm_set1_epi32(revC);
	chk_d[threadIdx] = _mm_set1_epi32(revD);
}

// Same as above, but can be used for plains with length 8 to 11.
// Compared to the routine above, this is a bit slower because we need to access x[2].
void MD5Reverse_8plus(const char* plain, const int len, const int threadIdx)
{
	// Create x.
	const uint4 *x = (uint4*)&plain[0];

	// Init.
	uint4 revA = state_org[0];
	uint4 revB = state_org[1];
	uint4 revC = state_org[2];
	uint4 revD = state_org[3];
			
	// Reverse.
	II_REV (revB, revC, revD, revA,      0, S44, 0xeb86d391); // 64
	II_REV (revC, revD, revA, revB,   x[2], S43, 0x2ad7d2bb); // 63
	II_REV (revD, revA, revB, revC,      0, S42, 0xbd3af235); // 62
	II_REV (revA, revB, revC, revD,      0, S41, 0xf7537e82); // 61
	II_REV (revB, revC, revD, revA,      0, S44, 0x4e0811a1); // 60
	II_REV (revC, revD, revA, revB,      0, S43, 0xa3014314); // 59
	II_REV (revD, revA, revB, revC,      0, S42, 0xfe2ce6e0); // 58
	II_REV (revA, revB, revC, revD,      0, S41, 0x6fa87e4f); // 57
	II_REV (revB, revC, revD, revA,   x[1], S44, 0x85845dd1); // 56
	II_REV (revC, revD, revA, revB,      0, S43, 0xffeff47d); // 55
	II_REV (revD, revA, revB, revC,      0, S42, 0x8f0ccc92); // 54
	II_REV (revA, revB, revC, revD,      0, S41, 0x655b59c3); // 53
	II_REV (revB, revC, revD, revA,      0, S44, 0xfc93a039); // 52
	II_REV (revC, revD, revA, revB, len<<3, S43, 0xab9423a7); // 51
	II_REV (revD, revA, revB, revC,      0, S42, 0x432aff97); // 50
	II_REV (revA, revB, revC, revD,      0, S41, 0xf4292244); // 49

	// Save it (thread-dependend memory location).
	chk_a[threadIdx] = _mm_set1_epi32(revA);
	chk_b[threadIdx] = _mm_set1_epi32(revB);
	chk_c[threadIdx] = _mm_set1_epi32(revC);
	chk_d[threadIdx] = _mm_set1_epi32(revD);
}

// Calculation.
int MD5Calculate(unsigned char wordPack[PACKAGE_SIZE][8], const int len, const int threadIdx)
{
	// Initialize hash value for this chunk:
	__m128i a[3]; a[0] = baseA, a[1] = baseA, a[2] = baseA;
	__m128i b[3]; b[0] = baseB, b[1] = baseB, b[2] = baseB;
	__m128i c[3]; c[0] = baseC, c[1] = baseC, c[2] = baseC;
	__m128i d[3]; d[0] = baseD, d[1] = baseD, d[2] = baseD;

	// Create temporary x.
	const uint4 *t_x0 = (uint4*)&wordPack[0][0];
	const uint4 *t_x1 = (uint4*)&wordPack[1][0];
	const uint4 *t_x2 = (uint4*)&wordPack[2][0];
	const uint4 *t_x3 = (uint4*)&wordPack[3][0];
	const uint4 *t_x4 = (uint4*)&wordPack[4][0];
	const uint4 *t_x5 = (uint4*)&wordPack[5][0];
	const uint4 *t_x6 = (uint4*)&wordPack[6][0];
	const uint4 *t_x7 = (uint4*)&wordPack[7][0];
	const uint4 *t_x8 = (uint4*)&wordPack[8][0];
	const uint4 *t_x9 = (uint4*)&wordPack[9][0];
	const uint4 *t_x10 = (uint4*)&wordPack[10][0];
	const uint4 *t_x11 = (uint4*)&wordPack[11][0];

	// Create final x.
	__m128i x0[3];
	x0[0] = _mm_set_epi32( t_x3[0],  t_x2[0],  t_x1[0],  t_x0[0]);
	x0[1] = _mm_set_epi32( t_x7[0],  t_x6[0],  t_x5[0],  t_x4[0]);
	x0[2] = _mm_set_epi32(t_x11[0], t_x10[0],  t_x9[0],  t_x8[0]);
	__m128i x1[3];
	x1[0] = _mm_set_epi32( t_x3[1],  t_x2[1],  t_x1[1],  t_x0[1]);
	x1[1] = _mm_set_epi32( t_x7[1],  t_x6[1],  t_x5[1],  t_x4[1]);
	x1[2] = _mm_set_epi32(t_x11[1], t_x10[1],  t_x9[1],  t_x8[1]);
	__m128i x14[3];
	x14[0] = _mm_set1_epi32(len << 3);
	x14[1] = _mm_set1_epi32(len << 3);
	x14[2] = _mm_set1_epi32(len << 3);

	/* Round 1 */
	FF_FULL (a, b, c, d,  x0, S11, AC1); /* 1 */
	FF_FULL (d, a, b, c,  x1, S12, AC2); /* 2 */
	FF_NULL (c, d, a, b,   0, S13, AC3); /* 3 */
	FF_NULL (b, c, d, a,   0, S14, AC4); /* 4 */
	FF_NULL (a, b, c, d,   0, S11, AC5); /* 5 */
	FF_NULL (d, a, b, c,   0, S12, AC6); /* 6 */
	FF_NULL (c, d, a, b,   0, S13, AC7); /* 7 */
	FF_NULL (b, c, d, a,   0, S14, AC8); /* 8 */
	FF_NULL (a, b, c, d,   0, S11, AC9); /* 9 */
	FF_NULL (d, a, b, c,   0, S12, AC10); /* 10 */
	FF_NULL (c, d, a, b,   0, S13, AC11); /* 11 */
	FF_NULL (b, c, d, a,   0, S14, AC12); /* 12 */
	FF_NULL (a, b, c, d,   0, S11, AC13); /* 13 */
	FF_NULL (d, a, b, c,   0, S12, AC14); /* 14 */
	FF_FULL (c, d, a, b, x14, S13, AC15); /* 15 */
	FF_NULL (b, c, d, a,   0, S14, AC16); /* 16 */

	/* Round 2 */
	GG_FULL (a, b, c, d,  x1, S21, AC17); /* 17 */
	GG_NULL (d, a, b, c,   0, S22, AC18); /* 18 */
	GG_NULL (c, d, a, b,   0, S23, AC19); /* 19 */
	GG_FULL (b, c, d, a,  x0, S24, AC20); /* 20 */
	GG_NULL (a, b, c, d,   0, S21, AC21); /* 21 */
	GG_NULL (d, a, b, c,   0, S22, AC22); /* 22 */
	GG_NULL (c, d, a, b,   0, S23, AC23); /* 23 */
	GG_NULL (b, c, d, a,   0, S24, AC24); /* 24 */
	GG_NULL (a, b, c, d,   0, S21, AC25); /* 25 */
	GG_FULL (d, a, b, c, x14, S22, AC26); /* 26 */
	GG_NULL (c, d, a, b,   0, S23, AC27); /* 27 */
	GG_NULL (b, c, d, a,   0, S24, AC28); /* 28 */
	GG_NULL (a, b, c, d,   0, S21, AC29); /* 29 */
	GG_NULL (d, a, b, c,   0, S22, AC30); /* 30 */
	GG_NULL (c, d, a, b,   0, S23, AC31); /* 31 */
	GG_NULL (b, c, d, a,   0, S24, AC32); /* 32 */

	/* Round 3 */
	HH_NULL (a, b, c, d,   0, S31, AC33); /* 33 */
	HH_NULL (d, a, b, c,   0, S32, AC34); /* 34 */
	HH_NULL (c, d, a, b,   0, S33, AC35); /* 35 */
	HH_FULL (b, c, d, a, x14, S34, AC36); /* 36 */
	HH_FULL (a, b, c, d,  x1, S31, AC37); /* 37 */
	HH_NULL (d, a, b, c,   0, S32, AC38); /* 38 */
	HH_NULL (c, d, a, b,   0, S33, AC39); /* 39 */
	HH_NULL (b, c, d, a,   0, S34, AC40); /* 40 */
	HH_NULL (a, b, c, d,   0, S31, AC41); /* 41 */
	HH_FULL (d, a, b, c,  x0, S32, AC42); /* 42 */
	HH_NULL (c, d, a, b,   0, S33, AC43); /* 43 */
	HH_NULL (b, c, d, a,   0, S34, AC44); /* 44 */
	HH_NULL (a, b, c, d,   0, S31, AC45); /* 45 */
	// Rest skipped.

	/* Round 4 */
	// Oh round 4, where art thou?

	// Create a temporary a for checking.
	__m128i tmp_a[3];
	tmp_a[2] = a[2] + x0[2];
	tmp_a[1] = a[1] + x0[1];
	tmp_a[0] = a[0] + x0[0];

	// Check!
	int result_mask = _mm_movemask_epi8(_mm_cmpeq_epi32(chk_a[threadIdx], tmp_a[2]) + 
										_mm_cmpeq_epi32(chk_a[threadIdx], tmp_a[1]) + 
										_mm_cmpeq_epi32(chk_a[threadIdx], tmp_a[0]));
	if (result_mask > 0) {
		// 1 in 2^32 chance that this gets called more than once, so
		// compute the last 3 steps to achieve 100% certainty.
		HH_NULL (d, a, b, c, 0, S32, AC46); /* 46 */
		HH_NULL (c, d, a, b, 0, S33, AC47); /* 47 */
		HH_NULL (b, c, d, a, 0, S34, AC48); /* 48 */

		// In first block?
		result_mask = _mm_movemask_epi8(_mm_cmpeq_epi32(chk_a[threadIdx], tmp_a[0]) & 
										_mm_cmpeq_epi32(chk_b[threadIdx], b[0]) & 
										_mm_cmpeq_epi32(chk_c[threadIdx], c[0]) & 
										_mm_cmpeq_epi32(chk_d[threadIdx], d[0]));
		if (result_mask > 0) {
			if (result_mask == 0xF000)
				return 3;
			else if (result_mask == 0x0F00)
				return 2;
			else if (result_mask == 0x00F0)
				return 1;
			else if (result_mask == 0x000F)
				return 0;
		}

		// In second block?
		result_mask = _mm_movemask_epi8(_mm_cmpeq_epi32(chk_a[threadIdx], tmp_a[1]) & 
										_mm_cmpeq_epi32(chk_b[threadIdx], b[1]) & 
										_mm_cmpeq_epi32(chk_c[threadIdx], c[1]) & 
										_mm_cmpeq_epi32(chk_d[threadIdx], d[1]));
		if (result_mask > 0) {
			if (result_mask == 0xF000)
				return 7;
			else if (result_mask == 0x0F00)
				return 6;
			else if (result_mask == 0x00F0)
				return 5;
			else if (result_mask == 0x000F)
				return 4;
		}

		// In thrid block?
		result_mask = _mm_movemask_epi8(_mm_cmpeq_epi32(chk_a[threadIdx], tmp_a[2]) & 
										_mm_cmpeq_epi32(chk_b[threadIdx], b[2]) & 
										_mm_cmpeq_epi32(chk_c[threadIdx], c[2]) & 
										_mm_cmpeq_epi32(chk_d[threadIdx], d[2]));
		if (result_mask > 0) {
			if (result_mask == 0xF000)
				return 11;
			else if (result_mask == 0x0F00)
				return 10;
			else if (result_mask == 0x00F0)
				return 9;
			else if (result_mask == 0x000F)
				return 8;
		}
	}

	// Not found
	return -1;
}

// Same as above, but can be used for plains with length 8 to 11.
// Compared to the routine above, this is ~1M slower because we need to access x[2].
int MD5Calculate_8plus(unsigned char wordPack[PACKAGE_SIZE][12], const int len, const int threadIdx)
{
	// Initialize hash value for this chunk:
	__m128i a[3]; a[0] = baseA, a[1] = baseA, a[2] = baseA;
	__m128i b[3]; b[0] = baseB, b[1] = baseB, b[2] = baseB;
	__m128i c[3]; c[0] = baseC, c[1] = baseC, c[2] = baseC;
	__m128i d[3]; d[0] = baseD, d[1] = baseD, d[2] = baseD;

	// Create temporary x.
	const uint4 *t_x0 = (uint4*)&wordPack[0][0];
	const uint4 *t_x1 = (uint4*)&wordPack[1][0];
	const uint4 *t_x2 = (uint4*)&wordPack[2][0];
	const uint4 *t_x3 = (uint4*)&wordPack[3][0];
	const uint4 *t_x4 = (uint4*)&wordPack[4][0];
	const uint4 *t_x5 = (uint4*)&wordPack[5][0];
	const uint4 *t_x6 = (uint4*)&wordPack[6][0];
	const uint4 *t_x7 = (uint4*)&wordPack[7][0];
	const uint4 *t_x8 = (uint4*)&wordPack[8][0];
	const uint4 *t_x9 = (uint4*)&wordPack[9][0];
	const uint4 *t_x10 = (uint4*)&wordPack[10][0];
	const uint4 *t_x11 = (uint4*)&wordPack[11][0];

	// Create final x.
	__m128i x0[3];
	x0[0] = _mm_set_epi32( t_x3[0],  t_x2[0],  t_x1[0],  t_x0[0]);
	x0[1] = _mm_set_epi32( t_x7[0],  t_x6[0],  t_x5[0],  t_x4[0]);
	x0[2] = _mm_set_epi32(t_x11[0], t_x10[0],  t_x9[0],  t_x8[0]);
	__m128i x1[3];
	x1[0] = _mm_set_epi32( t_x3[1],  t_x2[1],  t_x1[1],  t_x0[1]);
	x1[1] = _mm_set_epi32( t_x7[1],  t_x6[1],  t_x5[1],  t_x4[1]);
	x1[2] = _mm_set_epi32(t_x11[1], t_x10[1],  t_x9[1],  t_x8[1]);
	__m128i x2[3];
	x2[0] = _mm_set_epi32( t_x3[2],  t_x2[2],  t_x1[2],  t_x0[2]);
	x2[1] = _mm_set_epi32( t_x7[2],  t_x6[2],  t_x5[2],  t_x4[2]);
	x2[2] = _mm_set_epi32(t_x11[2], t_x10[2],  t_x9[2],  t_x8[2]);
	__m128i x14[3];
	x14[0] = _mm_set1_epi32(len << 3);
	x14[1] = _mm_set1_epi32(len << 3);
	x14[2] = _mm_set1_epi32(len << 3);

	/* Round 1 */
	FF_FULL (a, b, c, d,  x0, S11, AC1); /* 1 */
	FF_FULL (d, a, b, c,  x1, S12, AC2); /* 2 */
	FF_FULL (c, d, a, b,  x2, S13, AC3); /* 3 */
	FF_NULL (b, c, d, a,   0, S14, AC4); /* 4 */
	FF_NULL (a, b, c, d,   0, S11, AC5); /* 5 */
	FF_NULL (d, a, b, c,   0, S12, AC6); /* 6 */
	FF_NULL (c, d, a, b,   0, S13, AC7); /* 7 */
	FF_NULL (b, c, d, a,   0, S14, AC8); /* 8 */
	FF_NULL (a, b, c, d,   0, S11, AC9); /* 9 */
	FF_NULL (d, a, b, c,   0, S12, AC10); /* 10 */
	FF_NULL (c, d, a, b,   0, S13, AC11); /* 11 */
	FF_NULL (b, c, d, a,   0, S14, AC12); /* 12 */
	FF_NULL (a, b, c, d,   0, S11, AC13); /* 13 */
	FF_NULL (d, a, b, c,   0, S12, AC14); /* 14 */
	FF_FULL (c, d, a, b, x14, S13, AC15); /* 15 */
	FF_NULL (b, c, d, a,   0, S14, AC16); /* 16 */

	/* Round 2 */
	GG_FULL (a, b, c, d,  x1, S21, AC17); /* 17 */
	GG_NULL (d, a, b, c,   0, S22, AC18); /* 18 */
	GG_NULL (c, d, a, b,   0, S23, AC19); /* 19 */
	GG_FULL (b, c, d, a,  x0, S24, AC20); /* 20 */
	GG_NULL (a, b, c, d,   0, S21, AC21); /* 21 */
	GG_NULL (d, a, b, c,   0, S22, AC22); /* 22 */
	GG_NULL (c, d, a, b,   0, S23, AC23); /* 23 */
	GG_NULL (b, c, d, a,   0, S24, AC24); /* 24 */
	GG_NULL (a, b, c, d,   0, S21, AC25); /* 25 */
	GG_FULL (d, a, b, c, x14, S22, AC26); /* 26 */
	GG_NULL (c, d, a, b,   0, S23, AC27); /* 27 */
	GG_NULL (b, c, d, a,   0, S24, AC28); /* 28 */
	GG_NULL (a, b, c, d,   0, S21, AC29); /* 29 */
	GG_FULL (d, a, b, c,  x2, S22, AC30); /* 30 */
	GG_NULL (c, d, a, b,   0, S23, AC31); /* 31 */
	GG_NULL (b, c, d, a,   0, S24, AC32); /* 32 */

	/* Round 3 */
	HH_NULL (a, b, c, d,   0, S31, AC33); /* 33 */
	HH_NULL (d, a, b, c,   0, S32, AC34); /* 34 */
	HH_NULL (c, d, a, b,   0, S33, AC35); /* 35 */
	HH_FULL (b, c, d, a, x14, S34, AC36); /* 36 */
	HH_FULL (a, b, c, d,  x1, S31, AC37); /* 37 */
	HH_NULL (d, a, b, c,   0, S32, AC38); /* 38 */
	HH_NULL (c, d, a, b,   0, S33, AC39); /* 39 */
	HH_NULL (b, c, d, a,   0, S34, AC40); /* 40 */
	HH_NULL (a, b, c, d,   0, S31, AC41); /* 41 */
	HH_FULL (d, a, b, c,  x0, S32, AC42); /* 42 */
	HH_NULL (c, d, a, b,   0, S33, AC43); /* 43 */
	HH_NULL (b, c, d, a,   0, S34, AC44); /* 44 */
	HH_NULL (a, b, c, d,   0, S31, AC45); /* 45 */
	// Rest skipped.

	/* Round 4 */
	// Oh round 4, where art thou?

	// Create a temporary a for checking.
	__m128i tmp_a[3];
	tmp_a[2] = a[2] + x0[2];
	tmp_a[1] = a[1] + x0[1];
	tmp_a[0] = a[0] + x0[0];

	// Check!
	int result_mask = _mm_movemask_epi8(_mm_cmpeq_epi32(chk_a[threadIdx], tmp_a[2]) + 
										_mm_cmpeq_epi32(chk_a[threadIdx], tmp_a[1]) + 
										_mm_cmpeq_epi32(chk_a[threadIdx], tmp_a[0]));
	if (result_mask > 0) {
		// 1 in 2^32 chance that this gets called more than once, so
		// compute the last 3 steps to achieve 100% certainty.
		HH_NULL (d, a, b, c,  0, S32, AC46); /* 46 */
		HH_NULL (c, d, a, b,  0, S33, AC47); /* 47 */
		HH_FULL (b, c, d, a, x2, S34, AC48); /* 48 */

		// In first block?
		result_mask = _mm_movemask_epi8(_mm_cmpeq_epi32(chk_a[threadIdx], tmp_a[0]) & 
										_mm_cmpeq_epi32(chk_b[threadIdx], b[0]) & 
										_mm_cmpeq_epi32(chk_c[threadIdx], c[0]) & 
										_mm_cmpeq_epi32(chk_d[threadIdx], d[0]));
		if (result_mask > 0) {
			if (result_mask == 0xF000)
				return 3;
			else if (result_mask == 0x0F00)
				return 2;
			else if (result_mask == 0x00F0)
				return 1;
			else if (result_mask == 0x000F)
				return 0;
		}

		// In second block?
		result_mask = _mm_movemask_epi8(_mm_cmpeq_epi32(chk_a[threadIdx], tmp_a[1]) & 
										_mm_cmpeq_epi32(chk_b[threadIdx], b[1]) & 
										_mm_cmpeq_epi32(chk_c[threadIdx], c[1]) & 
										_mm_cmpeq_epi32(chk_d[threadIdx], d[1]));
		if (result_mask > 0) {
			if (result_mask == 0xF000)
				return 7;
			else if (result_mask == 0x0F00)
				return 6;
			else if (result_mask == 0x00F0)
				return 5;
			else if (result_mask == 0x000F)
				return 4;
		}

		// In thrid block?
		result_mask = _mm_movemask_epi8(_mm_cmpeq_epi32(chk_a[threadIdx], tmp_a[2]) & 
										_mm_cmpeq_epi32(chk_b[threadIdx], b[2]) & 
										_mm_cmpeq_epi32(chk_c[threadIdx], c[2]) & 
										_mm_cmpeq_epi32(chk_d[threadIdx], d[2]));
		if (result_mask > 0) {
			if (result_mask == 0xF000)
				return 11;
			else if (result_mask == 0x0F00)
				return 10;
			else if (result_mask == 0x00F0)
				return 9;
			else if (result_mask == 0x000F)
				return 8;
		}
	}

	// Not found
	return -1;
}

// Cleanup.
void MD5Cleanup()
{
	delete[] chk_a;
	delete[] chk_b;
	delete[] chk_c;
	delete[] chk_d;
}