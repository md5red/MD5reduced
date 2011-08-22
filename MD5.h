/*
MD5reduced
Copyright (C) 2011 Tobias Sielaff

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef MD5_H
 #define MD5_H


#include <emmintrin.h>

// Some "missing" operators:
inline __m128i operator +(__m128i a, __m128i b)
{
	return _mm_add_epi32(a, b);
}

inline __m128i operator -(__m128i a, __m128i b)
{
	return _mm_sub_epi32(a, b);
}

inline __m128i operator &(__m128i a, __m128i b)
{
	return _mm_and_si128(a, b);
}

inline __m128i operator |(__m128i a, __m128i b)
{
	return _mm_or_si128(a, b);
}

inline __m128i operator ^(__m128i a, __m128i b)
{
	return _mm_xor_si128(a, b);
}

inline __m128i operator ~(__m128i a)
{
	return _mm_xor_si128(a, _mm_set1_epi32(0xFFFFFFFF));
}

inline __m128i operator >>(__m128i a, int n)
{
	return _mm_srli_epi32(a, n);
}

inline __m128i operator <<(__m128i a, int n)
{
	return _mm_slli_epi32(a, n);
}

// Some types:
typedef unsigned       int uint4; // assumes integer is 4 words long
typedef unsigned short int uint2; // assumes short integer is 2 words long
typedef unsigned      char uint1; // assumes char is 1 word long

// Some methods:
bool MD5Init(std::string hash);
void MD5Reverse(const char* plain, const int len, const int threadIdx);
void MD5Reverse_8plus(const char* plain, const int len, const int threadIdx);
int  MD5Calculate(unsigned char wordPack[PACKAGE_SIZE][8], const int len, const int threadIdx);
int  MD5Calculate_8plus(unsigned char wordPack[PACKAGE_SIZE][12], const int len, const int threadIdx);
void MD5Cleanup();


#endif