
//NABEEHA MAHMOOD 23I-0588
//ZAHRA ZAHEER 23I-0751
//AYESHA NOOR 23I-0736

//-------------------------- D S   S E M   P R O J ------------------------------


#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>
#include <filesystem> 
#include <direct.h>
#include <map>
#include <stdexcept>
#include <memory>


using namespace std;
namespace fs = filesystem;

//========================================
// SHA HEADER
//========================================

#pragma once

//#include "hash.h"
#include <string>

// define fixed size integer types
#ifdef _MSC_VER
// Windows
typedef unsigned __int8  uint8_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
#else
// GCC
#include <stdint.h>
#endif


class SHA256 //: public Hash
{
public:
    /// split into 64 byte blocks (=> 512 bits), hash is 32 bytes long
    enum { BlockSize = 512 / 8, HashBytes = 32 };

    /// same as reset()
    SHA256();

    /// compute SHA256 of a memory block
    string operator()(const void* data, size_t numBytes);
    /// compute SHA256 of a string, excluding final zero
    string operator()(const string& text);

    /// add arbitrary number of bytes
    void add(const void* data, size_t numBytes);

    /// return latest hash as 64 hex characters
    string getHash();
    /// return latest hash as bytes
    void        getHash(unsigned char buffer[HashBytes]);

    /// restart
    void reset();

private:
    /// process 64 bytes
    void processBlock(const void* data);
    /// process everything left in the internal buffer
    void processBuffer();

    /// size of processed data in bytes
    uint64_t m_numBytes;
    /// valid bytes in m_buffer
    size_t   m_bufferSize;
    /// bytes not processed yet
    uint8_t  m_buffer[BlockSize];

    enum { HashValues = HashBytes / 4 };
    /// hash, stored as integers
    uint32_t m_hash[HashValues];
};


//======================================================
// SHA CPP
//======================================================


// big endian architectures need #define __BYTE_ORDER __BIG_ENDIAN
#ifndef _MSC_VER
#include <cstdint>
#endif

//#define SHA2_224_SEED_VECTOR

inline uint32_t swap32(uint32_t x) {
    return ((x << 24) & 0xff000000) |
        ((x << 8) & 0x00ff0000) |
        ((x >> 8) & 0x0000ff00) |
        ((x >> 24) & 0x000000ff);
}

inline uint64_t swap64(uint64_t x) {
    x = ((x << 8) & 0xFF00FF00FF00FF00ULL) | ((x >> 8) & 0x00FF00FF00FF00FFULL);
    x = ((x << 16) & 0xFFFF0000FFFF0000ULL) | ((x >> 16) & 0x0000FFFF0000FFFFULL);
    return (x << 32) | (x >> 32);
}

// Define endianness conversion macros
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htobe32(x) (x)
#define htobe64(x) (x)
#define be32toh(x) (x)
#define be64toh(x) (x)
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htobe32(x) swap32(x)
#define htobe64(x) swap64(x)
#define be32toh(x) swap32(x)
#define be64toh(x) swap64(x)
#endif

/// same as reset()
SHA256::SHA256()
{
    reset();
}


/// restart
void SHA256::reset()
{
    m_numBytes = 0;
    m_bufferSize = 0;

    // according to RFC 1321
    // "These words were obtained by taking the first thirty-two bits of the
    //  fractional parts of the square roots of the first eight prime numbers"
    m_hash[0] = 0x6a09e667;
    m_hash[1] = 0xbb67ae85;
    m_hash[2] = 0x3c6ef372;
    m_hash[3] = 0xa54ff53a;
    m_hash[4] = 0x510e527f;
    m_hash[5] = 0x9b05688c;
    m_hash[6] = 0x1f83d9ab;
    m_hash[7] = 0x5be0cd19;

#ifdef SHA2_224_SEED_VECTOR
    // if you want SHA2-224 instead then use these seeds
    // and throw away the last 32 bits of getHash
    m_hash[0] = 0xc1059ed8;
    m_hash[1] = 0x367cd507;
    m_hash[2] = 0x3070dd17;
    m_hash[3] = 0xf70e5939;
    m_hash[4] = 0xffc00b31;
    m_hash[5] = 0x68581511;
    m_hash[6] = 0x64f98fa7;
    m_hash[7] = 0xbefa4fa4;
#endif
}


namespace
{
    inline uint32_t rotate(uint32_t a, uint32_t c)
    {
        return (a >> c) | (a << (32 - c));
    }

    inline uint32_t swap(uint32_t x)
    {
#if defined(__GNUC__) || defined(__clang__)
        return __builtin_bswap32(x);
#endif
#ifdef MSC_VER
        return _byteswap_ulong(x);
#endif

        return (x >> 24) |
            ((x >> 8) & 0x0000FF00) |
            ((x << 8) & 0x00FF0000) |
            (x << 24);
    }

    // mix functions for processBlock()
    inline uint32_t f1(uint32_t e, uint32_t f, uint32_t g)
    {
        uint32_t term1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25);
        uint32_t term2 = (e & f) ^ (~e & g); //(g ^ (e & (f ^ g)))
        return term1 + term2;
    }

    inline uint32_t f2(uint32_t a, uint32_t b, uint32_t c)
    {
        uint32_t term1 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22);
        uint32_t term2 = ((a | b) & c) | (a & b); //(a & (b ^ c)) ^ (b & c);
        return term1 + term2;
    }
}


/// process 64 bytes
void SHA256::processBlock(const void* data)
{
    // get last hash
    uint32_t a = m_hash[0];
    uint32_t b = m_hash[1];
    uint32_t c = m_hash[2];
    uint32_t d = m_hash[3];
    uint32_t e = m_hash[4];
    uint32_t f = m_hash[5];
    uint32_t g = m_hash[6];
    uint32_t h = m_hash[7];

    // data represented as 16x 32-bit words
    const uint32_t* input = (uint32_t*)data;
    // convert to big endian
    uint32_t words[64];
    int i;
    for (i = 0; i < 16; i++)
#if defined(__BYTE_ORDER) && (__BYTE_ORDER != 0) && (__BYTE_ORDER == __BIG_ENDIAN)
        words[i] = input[i];
#else
        words[i] = swap(input[i]);
#endif

    uint32_t x, y; // temporaries

    // first round
    x = h + f1(e, f, g) + 0x428a2f98 + words[0]; y = f2(a, b, c); d += x; h = x + y;
    x = g + f1(d, e, f) + 0x71374491 + words[1]; y = f2(h, a, b); c += x; g = x + y;
    x = f + f1(c, d, e) + 0xb5c0fbcf + words[2]; y = f2(g, h, a); b += x; f = x + y;
    x = e + f1(b, c, d) + 0xe9b5dba5 + words[3]; y = f2(f, g, h); a += x; e = x + y;
    x = d + f1(a, b, c) + 0x3956c25b + words[4]; y = f2(e, f, g); h += x; d = x + y;
    x = c + f1(h, a, b) + 0x59f111f1 + words[5]; y = f2(d, e, f); g += x; c = x + y;
    x = b + f1(g, h, a) + 0x923f82a4 + words[6]; y = f2(c, d, e); f += x; b = x + y;
    x = a + f1(f, g, h) + 0xab1c5ed5 + words[7]; y = f2(b, c, d); e += x; a = x + y;

    // secound round
    x = h + f1(e, f, g) + 0xd807aa98 + words[8]; y = f2(a, b, c); d += x; h = x + y;
    x = g + f1(d, e, f) + 0x12835b01 + words[9]; y = f2(h, a, b); c += x; g = x + y;
    x = f + f1(c, d, e) + 0x243185be + words[10]; y = f2(g, h, a); b += x; f = x + y;
    x = e + f1(b, c, d) + 0x550c7dc3 + words[11]; y = f2(f, g, h); a += x; e = x + y;
    x = d + f1(a, b, c) + 0x72be5d74 + words[12]; y = f2(e, f, g); h += x; d = x + y;
    x = c + f1(h, a, b) + 0x80deb1fe + words[13]; y = f2(d, e, f); g += x; c = x + y;
    x = b + f1(g, h, a) + 0x9bdc06a7 + words[14]; y = f2(c, d, e); f += x; b = x + y;
    x = a + f1(f, g, h) + 0xc19bf174 + words[15]; y = f2(b, c, d); e += x; a = x + y;

    // extend to 24 words
    for (; i < 24; i++)
        words[i] = words[i - 16] +
        (rotate(words[i - 15], 7) ^ rotate(words[i - 15], 18) ^ (words[i - 15] >> 3)) +
        words[i - 7] +
        (rotate(words[i - 2], 17) ^ rotate(words[i - 2], 19) ^ (words[i - 2] >> 10));

    // third round
    x = h + f1(e, f, g) + 0xe49b69c1 + words[16]; y = f2(a, b, c); d += x; h = x + y;
    x = g + f1(d, e, f) + 0xefbe4786 + words[17]; y = f2(h, a, b); c += x; g = x + y;
    x = f + f1(c, d, e) + 0x0fc19dc6 + words[18]; y = f2(g, h, a); b += x; f = x + y;
    x = e + f1(b, c, d) + 0x240ca1cc + words[19]; y = f2(f, g, h); a += x; e = x + y;
    x = d + f1(a, b, c) + 0x2de92c6f + words[20]; y = f2(e, f, g); h += x; d = x + y;
    x = c + f1(h, a, b) + 0x4a7484aa + words[21]; y = f2(d, e, f); g += x; c = x + y;
    x = b + f1(g, h, a) + 0x5cb0a9dc + words[22]; y = f2(c, d, e); f += x; b = x + y;
    x = a + f1(f, g, h) + 0x76f988da + words[23]; y = f2(b, c, d); e += x; a = x + y;

    // extend to 32 words
    for (; i < 32; i++)
        words[i] = words[i - 16] +
        (rotate(words[i - 15], 7) ^ rotate(words[i - 15], 18) ^ (words[i - 15] >> 3)) +
        words[i - 7] +
        (rotate(words[i - 2], 17) ^ rotate(words[i - 2], 19) ^ (words[i - 2] >> 10));

    // fourth round
    x = h + f1(e, f, g) + 0x983e5152 + words[24]; y = f2(a, b, c); d += x; h = x + y;
    x = g + f1(d, e, f) + 0xa831c66d + words[25]; y = f2(h, a, b); c += x; g = x + y;
    x = f + f1(c, d, e) + 0xb00327c8 + words[26]; y = f2(g, h, a); b += x; f = x + y;
    x = e + f1(b, c, d) + 0xbf597fc7 + words[27]; y = f2(f, g, h); a += x; e = x + y;
    x = d + f1(a, b, c) + 0xc6e00bf3 + words[28]; y = f2(e, f, g); h += x; d = x + y;
    x = c + f1(h, a, b) + 0xd5a79147 + words[29]; y = f2(d, e, f); g += x; c = x + y;
    x = b + f1(g, h, a) + 0x06ca6351 + words[30]; y = f2(c, d, e); f += x; b = x + y;
    x = a + f1(f, g, h) + 0x14292967 + words[31]; y = f2(b, c, d); e += x; a = x + y;

    // extend to 40 words
    for (; i < 40; i++)
        words[i] = words[i - 16] +
        (rotate(words[i - 15], 7) ^ rotate(words[i - 15], 18) ^ (words[i - 15] >> 3)) +
        words[i - 7] +
        (rotate(words[i - 2], 17) ^ rotate(words[i - 2], 19) ^ (words[i - 2] >> 10));

    // fifth round
    x = h + f1(e, f, g) + 0x27b70a85 + words[32]; y = f2(a, b, c); d += x; h = x + y;
    x = g + f1(d, e, f) + 0x2e1b2138 + words[33]; y = f2(h, a, b); c += x; g = x + y;
    x = f + f1(c, d, e) + 0x4d2c6dfc + words[34]; y = f2(g, h, a); b += x; f = x + y;
    x = e + f1(b, c, d) + 0x53380d13 + words[35]; y = f2(f, g, h); a += x; e = x + y;
    x = d + f1(a, b, c) + 0x650a7354 + words[36]; y = f2(e, f, g); h += x; d = x + y;
    x = c + f1(h, a, b) + 0x766a0abb + words[37]; y = f2(d, e, f); g += x; c = x + y;
    x = b + f1(g, h, a) + 0x81c2c92e + words[38]; y = f2(c, d, e); f += x; b = x + y;
    x = a + f1(f, g, h) + 0x92722c85 + words[39]; y = f2(b, c, d); e += x; a = x + y;

    // extend to 48 words
    for (; i < 48; i++)
        words[i] = words[i - 16] +
        (rotate(words[i - 15], 7) ^ rotate(words[i - 15], 18) ^ (words[i - 15] >> 3)) +
        words[i - 7] +
        (rotate(words[i - 2], 17) ^ rotate(words[i - 2], 19) ^ (words[i - 2] >> 10));

    // sixth round
    x = h + f1(e, f, g) + 0xa2bfe8a1 + words[40]; y = f2(a, b, c); d += x; h = x + y;
    x = g + f1(d, e, f) + 0xa81a664b + words[41]; y = f2(h, a, b); c += x; g = x + y;
    x = f + f1(c, d, e) + 0xc24b8b70 + words[42]; y = f2(g, h, a); b += x; f = x + y;
    x = e + f1(b, c, d) + 0xc76c51a3 + words[43]; y = f2(f, g, h); a += x; e = x + y;
    x = d + f1(a, b, c) + 0xd192e819 + words[44]; y = f2(e, f, g); h += x; d = x + y;
    x = c + f1(h, a, b) + 0xd6990624 + words[45]; y = f2(d, e, f); g += x; c = x + y;
    x = b + f1(g, h, a) + 0xf40e3585 + words[46]; y = f2(c, d, e); f += x; b = x + y;
    x = a + f1(f, g, h) + 0x106aa070 + words[47]; y = f2(b, c, d); e += x; a = x + y;

    // extend to 56 words
    for (; i < 56; i++)
        words[i] = words[i - 16] +
        (rotate(words[i - 15], 7) ^ rotate(words[i - 15], 18) ^ (words[i - 15] >> 3)) +
        words[i - 7] +
        (rotate(words[i - 2], 17) ^ rotate(words[i - 2], 19) ^ (words[i - 2] >> 10));

    // seventh round
    x = h + f1(e, f, g) + 0x19a4c116 + words[48]; y = f2(a, b, c); d += x; h = x + y;
    x = g + f1(d, e, f) + 0x1e376c08 + words[49]; y = f2(h, a, b); c += x; g = x + y;
    x = f + f1(c, d, e) + 0x2748774c + words[50]; y = f2(g, h, a); b += x; f = x + y;
    x = e + f1(b, c, d) + 0x34b0bcb5 + words[51]; y = f2(f, g, h); a += x; e = x + y;
    x = d + f1(a, b, c) + 0x391c0cb3 + words[52]; y = f2(e, f, g); h += x; d = x + y;
    x = c + f1(h, a, b) + 0x4ed8aa4a + words[53]; y = f2(d, e, f); g += x; c = x + y;
    x = b + f1(g, h, a) + 0x5b9cca4f + words[54]; y = f2(c, d, e); f += x; b = x + y;
    x = a + f1(f, g, h) + 0x682e6ff3 + words[55]; y = f2(b, c, d); e += x; a = x + y;

    // extend to 64 words
    for (; i < 64; i++)
        words[i] = words[i - 16] +
        (rotate(words[i - 15], 7) ^ rotate(words[i - 15], 18) ^ (words[i - 15] >> 3)) +
        words[i - 7] +
        (rotate(words[i - 2], 17) ^ rotate(words[i - 2], 19) ^ (words[i - 2] >> 10));

    // eigth round
    x = h + f1(e, f, g) + 0x748f82ee + words[56]; y = f2(a, b, c); d += x; h = x + y;
    x = g + f1(d, e, f) + 0x78a5636f + words[57]; y = f2(h, a, b); c += x; g = x + y;
    x = f + f1(c, d, e) + 0x84c87814 + words[58]; y = f2(g, h, a); b += x; f = x + y;
    x = e + f1(b, c, d) + 0x8cc70208 + words[59]; y = f2(f, g, h); a += x; e = x + y;
    x = d + f1(a, b, c) + 0x90befffa + words[60]; y = f2(e, f, g); h += x; d = x + y;
    x = c + f1(h, a, b) + 0xa4506ceb + words[61]; y = f2(d, e, f); g += x; c = x + y;
    x = b + f1(g, h, a) + 0xbef9a3f7 + words[62]; y = f2(c, d, e); f += x; b = x + y;
    x = a + f1(f, g, h) + 0xc67178f2 + words[63]; y = f2(b, c, d); e += x; a = x + y;

    // update hash
    m_hash[0] += a;
    m_hash[1] += b;
    m_hash[2] += c;
    m_hash[3] += d;
    m_hash[4] += e;
    m_hash[5] += f;
    m_hash[6] += g;
    m_hash[7] += h;
}


/// add arbitrary number of bytes
void SHA256::add(const void* data, size_t numBytes)
{
    const uint8_t* current = (const uint8_t*)data;

    if (m_bufferSize > 0)
    {
        while (numBytes > 0 && m_bufferSize < BlockSize)
        {
            m_buffer[m_bufferSize++] = *current++;
            numBytes--;
        }
    }

    // full buffer
    if (m_bufferSize == BlockSize)
    {
        processBlock(m_buffer);
        m_numBytes += BlockSize;
        m_bufferSize = 0;
    }

    // no more data ?
    if (numBytes == 0)
        return;

    // process full blocks
    while (numBytes >= BlockSize)
    {
        processBlock(current);
        current += BlockSize;
        m_numBytes += BlockSize;
        numBytes -= BlockSize;
    }

    // keep remaining bytes in buffer
    while (numBytes > 0)
    {
        m_buffer[m_bufferSize++] = *current++;
        numBytes--;
    }
}


/// process final block, less than 64 bytes
void SHA256::processBuffer()
{
    // the input bytes are considered as bits strings, where the first bit is the most significant bit of the byte

    // - append "1" bit to message
    // - append "0" bits until message length in bit mod 512 is 448
    // - append length as 64 bit integer

    // number of bits
    size_t paddedLength = m_bufferSize * 8;

    // plus one bit set to 1 (always appended)
    paddedLength++;

    // number of bits must be (numBits % 512) = 448
    size_t lower11Bits = paddedLength & 511;
    if (lower11Bits <= 448)
        paddedLength += 448 - lower11Bits;
    else
        paddedLength += 512 + 448 - lower11Bits;
    // convert from bits to bytes
    paddedLength /= 8;

    // only needed if additional data flows over into a second block
    unsigned char extra[BlockSize];

    // append a "1" bit, 128 => binary 10000000
    if (m_bufferSize < BlockSize)
        m_buffer[m_bufferSize] = 128;
    else
        extra[0] = 128;

    size_t i;
    for (i = m_bufferSize + 1; i < BlockSize; i++)
        m_buffer[i] = 0;
    for (; i < paddedLength; i++)
        extra[i - BlockSize] = 0;

    // add message length in bits as 64 bit number
    uint64_t msgBits = 8 * (m_numBytes + m_bufferSize);
    // find right position
    unsigned char* addLength;
    if (paddedLength < BlockSize)
        addLength = m_buffer + paddedLength;
    else
        addLength = extra + paddedLength - BlockSize;

    // must be big endian
    *addLength++ = (unsigned char)((msgBits >> 56) & 0xFF);
    *addLength++ = (unsigned char)((msgBits >> 48) & 0xFF);
    *addLength++ = (unsigned char)((msgBits >> 40) & 0xFF);
    *addLength++ = (unsigned char)((msgBits >> 32) & 0xFF);
    *addLength++ = (unsigned char)((msgBits >> 24) & 0xFF);
    *addLength++ = (unsigned char)((msgBits >> 16) & 0xFF);
    *addLength++ = (unsigned char)((msgBits >> 8) & 0xFF);
    *addLength = (unsigned char)(msgBits & 0xFF);

    // process blocks
    processBlock(m_buffer);
    // flowed over into a second block ?
    if (paddedLength > BlockSize)
        processBlock(extra);
}


/// return latest hash as 64 hex characters
string SHA256::getHash()
{
    // compute hash (as raw bytes)
    unsigned char rawHash[HashBytes];
    getHash(rawHash);

    // convert to hex string
    string result;
    result.reserve(2 * HashBytes);
    for (int i = 0; i < HashBytes; i++)
    {
        static const char dec2hex[16 + 1] = "0123456789abcdef";
        result += dec2hex[(rawHash[i] >> 4) & 15];
        result += dec2hex[rawHash[i] & 15];
    }

    return result;
}


/// return latest hash as bytes
void SHA256::getHash(unsigned char buffer[SHA256::HashBytes])
{
    // save old hash if buffer is partially filled
    uint32_t oldHash[HashValues];
    for (int i = 0; i < HashValues; i++)
        oldHash[i] = m_hash[i];

    // process remaining bytes
    processBuffer();

    unsigned char* current = buffer;
    for (int i = 0; i < HashValues; i++)
    {
        *current++ = (m_hash[i] >> 24) & 0xFF;
        *current++ = (m_hash[i] >> 16) & 0xFF;
        *current++ = (m_hash[i] >> 8) & 0xFF;
        *current++ = m_hash[i] & 0xFF;

        // restore old hash
        m_hash[i] = oldHash[i];
    }
}


/// compute SHA256 of a memory block
string SHA256::operator()(const void* data, size_t numBytes)
{
    reset();
    add(data, numBytes);
    return getHash();
}


/// compute SHA256 of a string, excluding final zero
string SHA256::operator()(const string& text)
{
    reset();
    add(text.c_str(), text.size());
    return getHash();
}




//======================================
// HASH GENERATION METHODS
//=====================================

// SHA256 object for hash generation
SHA256 sha;


bool userChoice = 0;
string generateSHA256Hash(const string& value) {
    return  sha(value);
}

//Function to calculate instructor-specific hash for a single string
unsigned long instructorHash(const string& str) {
    unsigned long hash = 0;
    for (char c : str) {
        if (isdigit(c)) {
            //    If character is a digit, multiply by its numeric value
            hash += (c - '0') * (c - '0');
        }
        else {
            //   If character is not a digit, multiply by its ASCII value
            hash += (unsigned long)c * (unsigned long)c;
        }

        //   Prevent potential overflow
        hash %= 1000000007;
    }

    // Final modulo with 29
    return hash % 29;
}

string generateHash(const string& value) {
    if (userChoice == 1)
        return  to_string(instructorHash(value));
    else
        return generateSHA256Hash(value);
}



//===========================================
//  CUSTOM STRING CLASS
//===========================================

class customString {
private:
    static const int MAX_STRING_LENGTH = 1000;

public:
    // used for copying string
    void customStrCpy(char* dest, const char* src) {
        if (src == nullptr || dest == nullptr) {
            return;
        }

        while (*src != '\0' && (dest - dest < MAX_STRING_LENGTH - 1)) {
            *dest = *src;
            dest++;
            src++;
        }
        *dest = '\0';
    }

    // returns string length
    int customStrLen(const char* str) {
        if (str == nullptr) {
            return 0;
        }

        int length = 0;
        while (*str && length < MAX_STRING_LENGTH) {
            length++;
            str++;
        }
        return length;
    }

    // string input function
    void customStrInput(char* str) {
        if (str == nullptr) {
            return;
        }

        char c;
        int index = 0;
        while ((c = getchar()) != '\n' && c != EOF && index < MAX_STRING_LENGTH - 1) {
            str[index++] = c;
        }
        str[index] = '\0';
    }

    // function for string comparison
    bool customStrCmp(const char* str1, const char* str2) {
        if (str1 == nullptr || str2 == nullptr) {
            return false;
        }

        while (*str1 && *str2) {
            if (*str1 != *str2) {
                return false;
            }
            str1++;
            str2++;
        }
        return (*str1 == '\0' && *str2 == '\0');
    }

    //used to copy n characters
    void customStrNCpy(char* dest, const char* src, int num) {
        if (src == nullptr || dest == nullptr || num <= 0) {
            return;
        }

        int i = 0;
        // copies upto num characters or until source ends
        while (i < num && src[i] != '\0' && i < MAX_STRING_LENGTH - 1) {
            dest[i] = src[i];
            i++;
        }

        //this pads/appends null chars if needed 
        while (i < num && i < MAX_STRING_LENGTH) {
            dest[i] = '\0';
            i++;
        }
    }

    // concatenates string 
    void customStrCat(char* dest, const char* src) {
        if (src == nullptr || dest == nullptr) {
            return;
        }

        //finds end of teh dest string
        while (*dest && (dest - dest < MAX_STRING_LENGTH - 1)) {
            dest++;
        }

        // appends src to dest
        while (*src && (dest - dest < MAX_STRING_LENGTH - 1)) {
            *dest = *src;
            dest++;
            src++;
        }
        *dest = '\0';
    }

    // finds the substring position
    int customStrStr(const char* haystack, const char* needle) {
        if (haystack == nullptr || needle == nullptr) {
            return -1;
        }

        int needleLen = customStrLen(needle);
        if (needleLen == 0) {
            return 0;
        }

        int haystackLen = customStrLen(haystack);
        for (int i = 0; i <= haystackLen - needleLen; i++) {
            int j;
            for (j = 0; j < needleLen; j++) {
                if (haystack[i + j] != needle[j]) {
                    break;
                }
            }
            if (j == needleLen) {
                return i;
            }
        }
        return -1;
    }

    // converts the string to lowercase
    void customStrToLower(char* str) {
        if (str == nullptr) {
            return;
        }

        while (*str) {
            if (*str >= 'A' && *str <= 'Z') {
                *str = *str + ('a' - 'A');
            }
            str++;
        }
    }

    // converts to uppercase
    void customStrToUpper(char* str) {
        if (str == nullptr) {
            return;
        }

        while (*str) {
            if (*str >= 'a' && *str <= 'z') {
                *str = *str - ('a' - 'A');
            }
            str++;
        }
    }

    // trims whitespace from start and end
    void customStrTrim(char* str) {
        if (str == nullptr) {
            return;
        }

        int len = customStrLen(str);
        if (len == 0) {
            return;
        }

        // trim end
        int end = len - 1;
        while (end >= 0 && (str[end] == ' ' || str[end] == '\t' || str[end] == '\n')) {
            str[end] = '\0';
            end--;
        }

        // trim start
        int start = 0;
        while (str[start] && (str[start] == ' ' || str[start] == '\t' || str[start] == '\n')) {
            start++;
        }

        if (start > 0) {
            int i = 0;
            while (str[start + i]) {
                str[i] = str[start + i];
                i++;
            }
            str[i] = '\0';
        }
    }
};


customString customStringobj;

//=============================================
//   STACK CLASS
//=============================================

#include <iostream>

template <typename T>
class Stack {
private:
    T* data;          // Pointer to dynamically allocated array
    int capacity;     // Maximum capacity of the stack
    int size;         // Current size/number of elements

    // Helper: used to resize the internal array
    void resize(int newCapacity) {
        T* newData = new T[newCapacity];
        for (int i = 0; i < size; ++i) {
            newData[i] = data[i];
        }
        delete[] data; // frees old memory
        data = newData;
        capacity = newCapacity;
    }

public:
    // Constructor
    Stack(int initialCapacity = 4)
        : capacity(initialCapacity), size(0) {
        data = new T[capacity];
    }

    // Destructor
    ~Stack() {
        delete[] data;
    }

    // Pushes an element to the stack
    void push_back(const T& value) {
        if (size == capacity) {
            resize(capacity * 2); // doubles the capacity if full
        }
        data[size++] = value;
    }

    // Removes the last element from the stack
    void pop_back() {
        if (size > 0) {
            --size;
        }
        else {
            cerr << "Error: Stack is empty, cannot pop." << endl;
        }
    }

    // Accesses the top element
    T& top() {
        if (size > 0) {
            return data[size - 1];
        }
        else {
            cerr << "Error: Stack is empty." << endl;
            static T invalidValue = T();
            return invalidValue;
        }
    }

    // for checking if the stack is empty 
    bool isEmpty() const {
        return size == 0;
    }

    // gives the current size of the stack
    int getSize() const {
        return size;
    }

    // clears the stack
    void clear() {
        size = 0; // Resets size, in this case capacity remains the same
    }
};




//=============================================
// FILE MANAGEMENT CLASS
//============================================


class CSVHandler {
private:
    struct Row {
        char** cells; // Array of column data for this row
        Row* next;    // Pointer to the next row
        Row() : cells(nullptr), next(nullptr) {}
    };

    char** columnNames; // Array for column names
    int columnCount;    // Number of the columns
    Row* head;          // The head of the linked list for rows
    int rowCount;       // Total number of rows read

public:
    CSVHandler() : columnNames(nullptr), columnCount(0), head(nullptr), rowCount(0) {}

    ~CSVHandler() {
        // cleans up column names
        if (columnNames) {
            for (int i = 0; i < columnCount; ++i) {
                delete[] columnNames[i];
            }
            delete[] columnNames;
        }

        // cleans up linked list of rows
        Row* current = head;
        while (current) {
            for (int i = 0; i < columnCount; ++i) {
                delete[] current->cells[i];
            }
            delete[] current->cells;
            Row* temp = current;
            current = current->next;
            delete temp;
        }
    }

    //adds another row
    void addRow(const string& filePath, char** rowData, int columnCount) {
        ofstream file(filePath, ios::app);
        if (!file.is_open()) {
            cerr << "Error: File could not be oppened." << endl;
            return;
        }

        // Write row data with commas
        for (int i = 0; i < columnCount; i++) {
            file << rowData[i];
            if (i < columnCount - 1) {
                file << ",";
            }
        }

        file << endl;
        file.close();
    }

    bool deleteRow(const string& filePath, const char* key, int keyColumn) {
        // Creates a temp file
        string tempFile = filePath + ".tmp";
        ifstream inFile(filePath);
        ofstream outFile(tempFile);

        if (!inFile.is_open() || !outFile.is_open()) {
            return false;
        }

        string line;
        bool found = false;

        // Copy header
        getline(inFile, line);
        outFile << line << endl;

        // Process each row
        while (getline(inFile, line)) {
            stringstream ss(line);
            string cell;
            int currentCol = 0;
            bool skipRow = false;

            while (getline(ss, cell, ',')) {
                if (currentCol == keyColumn && customStringobj.customStrCmp(cell.c_str(), key)) {
                    skipRow = true;
                    found = true;
                    break;
                }
                currentCol++;
            }

            if (!skipRow) {
                outFile << line << endl;
            }
        }

        inFile.close();
        outFile.close();

        // Replaces the original with temp file
        if (found) {
            remove(filePath.c_str());
            rename(tempFile.c_str(), filePath.c_str());
        }
        else {
            remove(tempFile.c_str());
        }

        return found;
    }

    // Gives the column names
    char** getColumnNames(const string& filePath, int& columnCount) {
        ifstream file(filePath);
        if (!file.is_open()) {
            columnCount = 0;
            return nullptr;
        }

        string headerLine;
        getline(file, headerLine);

        // Counts columns
        stringstream ss(headerLine);
        string column;
        columnCount = 0;
        while (getline(ss, column, ',')) {
            columnCount++;
        }

        // Allocates memory for the column names array
        char** columnNames = new char* [columnCount];
        for (int i = 0; i < columnCount; i++) {
            columnNames[i] = new char[100];
        }

        // Reads column names
        ss.clear();
        ss.str(headerLine);
        int i = 0;
        while (getline(ss, column, ',')) {
            customStringobj.customStrCpy(columnNames[i], column.c_str());
            i++;
        }

        file.close();
        return columnNames;
    }


    bool loadCSV(const char* filepath) {
        ifstream file(filepath);
        if (!file.is_open()) {
            cerr << "Error: Could not open file " << filepath << endl;
            return false;
        }

        // Cleanup previous data
        clearData();

        // Reads the header line
        string headerLine;
        if (!getline(file, headerLine)) {
            cerr << "Error: Empty file" << endl;
            return false;
        }

        // Counts the columns
        stringstream headerStream(headerLine);
        string columnName;
        while (getline(headerStream, columnName, ',')) {
            columnCount++;
        }

        // Allocates column names
        columnNames = new char* [columnCount];
        headerStream.clear();
        headerStream.str(headerLine);
        for (int i = 0; i < columnCount; ++i) {
            getline(headerStream, columnName, ',');
            columnNames[i] = new char[columnName.length() + 1];
            customStringobj.customStrCpy(columnNames[i], columnName.c_str());
        }

        //until an empty line, it reads data rows
        string line;
        Row* current = nullptr;
        while (getline(file, line)) {
            if (line.empty()) break; // stops if an empty row occurs

            Row* newRow = new Row();
            newRow->cells = new char* [columnCount];
            for (int i = 0; i < columnCount; ++i) {
                newRow->cells[i] = nullptr;
            }

            // This parses the row
            stringstream rowStream(line);
            string cell;
            for (int col = 0; col < columnCount; ++col) {
                if (getline(rowStream, cell, ',')) {
                    newRow->cells[col] = new char[cell.length() + 1];
                    customStringobj.customStrCpy(newRow->cells[col], cell.c_str());
                }
            }

            // Adds the row to the linked list
            if (!head) {
                head = newRow;
            }
            else {
                current->next = newRow;
            }
            current = newRow;
            rowCount++;
        }

        return true;
    }

    void displayColumns() {
        cout << "Available Columns:" << endl;
        for (int i = 0; i < columnCount; ++i) {
            cout << i + 1 << ". " << columnNames[i] << endl;
        }
    }

    //allows user to select the column based on which tree is constructed
    int selectColumn() {
        displayColumns();
        int selection;
        cout << "Enter the number of the column you want to use for tree construction: ";
        cin >> selection;

        if (selection < 1 || selection > columnCount) {
            cerr << "Invalid column selection!" << endl;
            return -1;
        }

        return selection - 1; // Takes away one; converts to 0-based index
    }

    // a helper method that gets column data as an integer array
    int* getIntColumnData(int columnIndex, int& outSize) {
        // counts valid integers
        int validCount = 0;
        Row* current = head;
        while (current) {
            try {
                stoi(current->cells[columnIndex]);
                validCount++;
            }
            catch (...) {}
            current = current->next;
        }

        // Populates the array
        int* intData = new int[validCount];
        outSize = validCount;
        int index = 0;
        current = head;
        while (current) {
            try {
                intData[index] = stoi(current->cells[columnIndex]);
                index++;
            }
            catch (...) {}
            current = current->next;
        }

        return intData;
    }

    // a helper method that gets column data as a string array
    char** getStringColumnData(int columnIndex, int& outSize) {
        char** stringData = new char* [rowCount];
        outSize = rowCount;

        int index = 0;
        Row* current = head;
        while (current) {
            stringData[index] = new char[strlen(current->cells[columnIndex]) + 1];
            customStringobj.customStrCpy(stringData[index], current->cells[columnIndex]);
            index++;
            current = current->next;
        }

        return stringData;
    }

    void appendBranchToCSV(const char* filepath, const char* branchName) {
        ofstream file(filepath, ios::app);
        if (!file.is_open()) {
            cerr << "Error: Could not open file for appending: " << filepath << endl;
            return;
        }

        file << branchName << endl;  // Appends the branch name in a new line
        file.close();
    }

private:
    void clearData() {
        // Cleans up column names
        if (columnNames) {
            for (int i = 0; i < columnCount; ++i) {
                delete[] columnNames[i];
            }
            delete[] columnNames;
            columnNames = nullptr;
        }

        // Cleans up linked list of rows
        Row* current = head;
        while (current) {
            for (int i = 0; i < columnCount; ++i) {
                delete[] current->cells[i];
            }
            delete[] current->cells;
            Row* temp = current;
            current = current->next;
            delete temp;
        }
        head = nullptr;
        rowCount = 0;
        columnCount = 0;
    }
};



//======================================================
//    B TREES
// ====================================================

// B-Tree Node structure
struct BTreeNode {
    string* keys;           // Keys in the node
    string* filePaths;      // File paths for each key
    string* rowHashes;      // Hash for each row
    string* keyHashes;      // Hash for each key
    string nodeHash;        // Hash of the entire node
    BTreeNode** children;   // Child nodes
    int t;                  // Min degree
    int numKeys;           // Number of keys in the node
    bool isLeaf;           // Checks if the node is a leaf
    BTreeNode* parent;      // Parent node reference
    char*** rowData;        // Array of row data for each key
    int* columnCounts;      // Array of column counts for each key

    // Constructor
    BTreeNode(int t, bool isLeaf) : t(t), isLeaf(isLeaf), numKeys(0), parent(nullptr)
    {
        keys = new string[2 * t - 1];
        filePaths = new string[2 * t - 1];
        rowHashes = new string[2 * t - 1];
        keyHashes = new string[2 * t - 1];
        children = new BTreeNode * [2 * t];
        rowData = new char** [2 * t - 1];
        columnCounts = new int[2 * t - 1];
        nodeHash = "";

        for (int i = 0; i < 2 * t - 1; i++) {
            rowData[i] = nullptr;
            columnCounts[i] = 0;
        }
        for (int i = 0; i < 2 * t; i++) {
            children[i] = nullptr;
        }
    }
    //destructor
    ~BTreeNode() {
        delete[] keys;
        delete[] filePaths;
        delete[] rowHashes;
        delete[] keyHashes;
        delete[] children;

        // Clean up row data
        for (int i = 0; i < 2 * t - 1; i++) {
            if (rowData[i]) {
                for (int j = 0; j < columnCounts[i]; j++) {
                    delete[] rowData[i][j];
                }
                delete[] rowData[i];
            }
        }
        delete[] rowData;
        delete[] columnCounts;
    }

    // Calculates the hash for a node
    void calculateNodeHash() {
        string combinedHash;

        // Combine hashes of all keys and their row data
        for (int i = 0; i < numKeys; i++) {
            combinedHash += keyHashes[i] + rowHashes[i];
        }

        // If not a leaf then add children's hashes
        if (!isLeaf) {
            for (int i = 0; i <= numKeys; i++) {
                if (children[i]) {
                    combinedHash += children[i]->nodeHash;
                }
            }
        }

        // Generates the final node hash
        nodeHash = generateHash(combinedHash);
    }

    // Calculates row hash for a given index
    void calculateRowHash(int index) {
        if (index >= 0 && index < numKeys && rowData[index]) {
            string combinedHash;
            for (int i = 0; i < columnCounts[index]; i++) {
                string columnHash = generateHash(string(rowData[index][i]));
                combinedHash += columnHash;
            }
            rowHashes[index] = generateHash(combinedHash);
        }
    }
};

// B-Tree structure
class BTree {

    struct NodeRelationships
    {
        string parent;
        vector<string> children;
    };

public:
    //constructor
    BTreeNode* findNode(const string& key) {
        return findNodeHelper(root, key);
    }

    NodeRelationships getNodeRelationships(const string& key)
    {
        NodeRelationships rels;
        BTreeNode* node = findNode(key);

        if (node) {
            // gives parent
            rels.parent = node->parent ? getNodeFileName(node->parent->keys[0]) : "None";

            // to get children
            if (!node->isLeaf) {
                for (int i = 0; i <= node->numKeys; i++) {
                    if (node->children[i]) {
                        rels.children.push_back(getNodeFileName(node->children[i]->keys[0]));
                    }
                }
            }
        }
        return rels;
    }

private:
    string getNodeFileName(const string& key) {
        return key + "_btree.txt";
    }

    BTreeNode* findNodeHelper(BTreeNode* node, const string& key) {
        if (!node) return nullptr;

        // Search for a key in the curr node
        int i = 0;
        while (i < node->numKeys && key > node->keys[i]) {
            i++;
        }

        // If the key is found curr node
        if (i < node->numKeys && key == node->keys[i]) {
            return node;
        }

        // If leaf node and key was not found
        if (node->isLeaf) {
            return nullptr;
        }

        // Recursively searches for appropriate child
        return findNodeHelper(node->children[i], key);
    }

    BTreeNode* root;
    int t; // Minimum degree

public:
    BTree(int t) : root(nullptr), t(t) {}

    ~BTree() {
        deleteTree(root);
    }

    // Helper func to delete the tree
    void deleteTree(BTreeNode* node) {
        if (node) {
            for (int i = 0; i <= node->numKeys; ++i) {
                deleteTree(node->children[i]);
            }
            delete node;
        }
    }

    // traverses and displays
    void traverse(BTreeNode* node, int level) {
        if (!node) return;
        cout << "Level " << level << ": ";
        for (int i = 0; i < node->numKeys; i++) {
            cout << node->keys[i] << " ";
        }
        cout << endl;
        if (!node->isLeaf) {
            for (int i = 0; i <= node->numKeys; ++i) {
                traverse(node->children[i], level + 1);
            }
        }
    }

    void traverse() {
        traverse(root, 0);
    }

    // calculates height
    int getHeight(BTreeNode* node) {
        if (!node) return 0;
        if (node->isLeaf) return 1;
        return 1 + getHeight(node->children[0]);
    }
    //gives height
    int getHeight() {
        return getHeight(root);
    }
    //insertion of new node
    void insert(const string& key, const string& filePath, char** rowData, int columnCount) {
        if (!root) {
            root = new BTreeNode(t, true);
            root->keys[0] = key;
            root->filePaths[0] = filePath;
            root->keyHashes[0] = generateHash(key);

            // Copy row data
            root->rowData[0] = new char* [columnCount];
            root->columnCounts[0] = columnCount;
            for (int i = 0; i < columnCount; i++) {
                root->rowData[0][i] = new char[strlen(rowData[i]) + 1];
                customStringobj.customStrCpy(root->rowData[0][i], rowData[i]);
            }

            root->calculateRowHash(0);
            root->calculateNodeHash();
            root->numKeys = 1;
        }
        else {
            if (root->numKeys == 2 * t - 1) {
                BTreeNode* newRoot = new BTreeNode(t, false);
                newRoot->children[0] = root;
                root->parent = newRoot;
                splitChild(newRoot, 0);
                insertNonFull(newRoot, key, filePath, rowData, columnCount);
                root = newRoot;
            }
            else {
                insertNonFull(root, key, filePath, rowData, columnCount);
            }
        }
    }
    //gives root node
    BTreeNode* getRoot() {
        return root;
    }

private:
    //inserts into node that is not full
    void insertNonFull(BTreeNode* node, const string& key, const string& filePath,
        char** rowData, int columnCount) {
        int i = node->numKeys - 1;
        //for leaf nodes
        if (node->isLeaf) {
            while (i >= 0 && key < node->keys[i]) {
                node->keys[i + 1] = node->keys[i];
                node->filePaths[i + 1] = node->filePaths[i];
                node->keyHashes[i + 1] = node->keyHashes[i];
                node->rowHashes[i + 1] = node->rowHashes[i];

                // Moves the row data
                node->rowData[i + 1] = node->rowData[i];
                node->columnCounts[i + 1] = node->columnCounts[i];
                i--;
            }

            i++;
            node->keys[i] = key;
            node->filePaths[i] = filePath;
            node->keyHashes[i] = generateHash(key);

            // copies new row data
            node->rowData[i] = new char* [columnCount];
            node->columnCounts[i] = columnCount;
            for (int j = 0; j < columnCount; j++) {
                node->rowData[i][j] = new char[strlen(rowData[j]) + 1];
                customStringobj.customStrCpy(node->rowData[i][j], rowData[j]);
            }

            node->calculateRowHash(i);
            node->numKeys++;
        }
        else {
            while (i >= 0 && key < node->keys[i]) {
                i--;
            }
            i++;

            if (node->children[i]->numKeys == 2 * t - 1) {
                splitChild(node, i);
                if (key > node->keys[i]) {
                    i++;
                }
            }
            insertNonFull(node->children[i], key, filePath, rowData, columnCount);
        }

        node->calculateNodeHash();
    }



private:
    //maintains b tree structure
    void splitChild(BTreeNode* parent, int i) {
        BTreeNode* child = parent->children[i];
        BTreeNode* newChild = new BTreeNode(child->t, child->isLeaf);
        newChild->numKeys = t - 1;
        //moves keys to new node
        for (int j = 0; j < t - 1; ++j) {
            newChild->keys[j] = child->keys[j + t];
            newChild->filePaths[j] = child->filePaths[j + t];
        }
        //if not leaf, then moves children ti new node
        if (!child->isLeaf) {
            for (int j = 0; j < t; ++j) {
                newChild->children[j] = child->children[j + t];
                if (newChild->children[j]) {
                    newChild->children[j]->parent = newChild;
                }
            }
        }
        //update full child node
        child->numKeys = t - 1;

        //adjusts the parent nodes
        for (int j = parent->numKeys; j >= i + 1; --j) {
            parent->children[j + 1] = parent->children[j];
        }
        parent->children[i + 1] = newChild;
        newChild->parent = parent;

        for (int j = parent->numKeys - 1; j >= i; --j) {
            parent->keys[j + 1] = parent->keys[j];
            parent->filePaths[j + 1] = parent->filePaths[j];
        }
        parent->keys[i] = child->keys[t - 1];
        parent->filePaths[i] = child->filePaths[t - 1];
        parent->numKeys++;

        cout << "Split child. Promoted \"" << parent->keys[i] << "\".\n";
        // hashes are updated
        child->calculateNodeHash();
        newChild->calculateNodeHash();
        parent->calculateNodeHash();
    }


};


// AVL Tree Node structure
struct AVLNode {
    string key;             // Key value
    string filePath;        // File path associated with the key
    string rowHash;         // Hash of the entire row
    string keyHash;         // Hash of the key
    string nodeHash;        // Hash of the entire node (including children)
    AVLNode* left;          // Left child
    AVLNode* right;         // Right child
    AVLNode* parent;        // Parent node
    int height;             // Height of the node
    char** rowData;         // Store entire row data
    int columnCount;        // Number of columns in the row

    AVLNode(const string& k, const string& path, char** data, int colCount) :
        key(k),
        filePath(path),
        rowData(nullptr),
        columnCount(colCount),
        keyHash(generateHash(k)),
        nodeHash(""),
        left(nullptr),
        right(nullptr),
        parent(nullptr),
        height(1) {

        // Deep copy row data
        rowData = new char* [columnCount];
        for (int i = 0; i < columnCount; ++i) {
            rowData[i] = new char[strlen(data[i]) + 1];
            customStringobj.customStrCpy(rowData[i], data[i]);
        }

        // Calculate row hash by combining hashes of individual columns
        calculateRowHash();
    }

    // Destructor to free memory
    ~AVLNode() {
        if (rowData) {
            for (int i = 0; i < columnCount; ++i) {
                delete[] rowData[i];
            }
            delete[] rowData;
        }
    }

    // New method to calculate row hash
    void calculateRowHash() {
        string combinedHash;
        // Calculate hash for each column and combine them
        for (int i = 0; i < columnCount; ++i) {
            string columnHash = generateHash(string(rowData[i]));
            combinedHash += columnHash;
        }
        // Final row hash is the hash of all combined column hashes
        rowHash = generateHash(combinedHash);
    }

    // Modified method to calculate node hash using row hash
    void calculateNodeHash() {
        // If node is a leaf, use row hash
        if (!left && !right) {
            nodeHash = rowHash;
            return;
        }

        // For non-leaf nodes, combine row hash with child hashes
        string leftHash = left ? left->nodeHash : "0";
        string rightHash = right ? right->nodeHash : "0";

        // Combine row hash with child hashes
        string combinedHash = rowHash + leftHash + rightHash;
        nodeHash = generateHash(combinedHash);
    }
};

// AVL Tree class
class AVLTree {
    struct NodeRelationships {
        string parent;
        string leftChild;
        string rightChild;
    };

    NodeRelationships getNodeRelationships(const string& key) {
        NodeRelationships rels;
        AVLNode* node = findNode(root, key);
        if (node) {
            rels.parent = node->parent ? node->parent->filePath : "None";
            rels.leftChild = node->left ? node->left->filePath : "None";
            rels.rightChild = node->right ? node->right->filePath : "None";
        }
        return rels;
    }

private:
    AVLNode* findNode(AVLNode* node, const string& key)
    {
        if (!node) return nullptr;
        if (node->key == key) return node;
        if (key < node->key) return findNode(node->left, key);
        return findNode(node->right, key);
    }
private:
    AVLNode* root;

    // Gives height of a node
    int getHeight(AVLNode* node) {
        return node ? node->height : 0;
    }

    // To get balance factor for a node
    int getBalanceFactor(AVLNode* node) {
        return node ? getHeight(node->left) - getHeight(node->right) : 0;
    }

    // Updates the node height
    void updateHeight(AVLNode* node) {
        if (node) {
            node->height = 1 + max(getHeight(node->left), getHeight(node->right));
        }
    }

    // Right rotation
    AVLNode* rotateRight(AVLNode* y) {
        AVLNode* x = y->left;
        AVLNode* T2 = x->right;

        // Performs rotation
        x->right = y;
        y->left = T2;

        // Updates heights
        updateHeight(y);
        updateHeight(x);

        // Recalculates the node hashes after rotation is performed
        y->calculateNodeHash();
        x->calculateNodeHash();

        return x;
    }

    // Left rotation
    AVLNode* rotateLeft(AVLNode* x) {
        AVLNode* y = x->right;
        AVLNode* T2 = y->left;

        // Performs rotation
        y->left = x;
        x->right = T2;

        // Updates heights
        updateHeight(x);
        updateHeight(y);

        // Recalculates node hashes after rotation is done
        x->calculateNodeHash();
        y->calculateNodeHash();

        return y;
    }

    // For balancing the nodes
    AVLNode* balance(AVLNode* node) {
        if (!node) return nullptr;

        // Updates height of the current node
        updateHeight(node);

        // Gives the balance factor
        int balance = getBalanceFactor(node);

        // For left Heavy
        if (balance > 1) {
            // Left-Right case
            if (getBalanceFactor(node->left) < 0) {
                node->left = rotateLeft(node->left);
            }
            // Left-Left case
            AVLNode* newNode = rotateRight(node);
            newNode->calculateNodeHash();
            return newNode;
        }

        // If right Heavy
        if (balance < -1) {
            // Right-Left case
            if (getBalanceFactor(node->right) > 0) {
                node->right = rotateRight(node->right);
            }
            // Right-Right case
            AVLNode* newNode = rotateLeft(node);
            newNode->calculateNodeHash();
            return newNode;
        }

        // Recalculates node hashes if not rotated
        node->calculateNodeHash();
        return node;
    }

    AVLNode* insertNode(AVLNode* node, const string& key, const string& filePath, char** rowData, int columnCount)
    {
        // Standard BST insertion
        if (!node) {
            return new AVLNode(key, filePath, rowData, columnCount);
        }

        if (key < node->key) {
            node->left = insertNode(node->left, key, filePath, rowData, columnCount);
            node->left->parent = node;  // Sets the parent of the left child
        }
        else if (key > node->key) {
            node->right = insertNode(node->right, key, filePath, rowData, columnCount);
            node->right->parent = node;  // Sets the parent of the right child
        }
        else
        {
            // Insert duplicate keys on the right side
            node->right = insertNode(node->right, key, filePath, rowData, columnCount);
            node->right->parent = node;  // Sets the parent of the right child
        }

        //for balancing 
        AVLNode* balancedNode = balance(node);

        // Recalculates the node hashes
        if (balancedNode->left) balancedNode->left->calculateNodeHash();
        if (balancedNode->right) balancedNode->right->calculateNodeHash();
        balancedNode->calculateNodeHash();

        return balancedNode;
    }


    //Inorder traversal and printing
    void inorderTraversal(AVLNode* node, int level) {
        if (!node) return;

        inorderTraversal(node->left, level + 1);

        cout << "Level " << level << ": " << node->key
            << " (Height: " << node->height << endl
            << ", Key Hash: " << node->keyHash << endl
            << ", Row Hash: " << node->rowHash << endl
            << ", Node Hash: " << node->nodeHash << ")" << endl << endl;

        inorderTraversal(node->right, level + 1);
    }

    // Gives tree height
    int getTreeHeight(AVLNode* node) {
        return node ? node->height : 0;
    }

    // Helper for deleting the entire tree 
    void deleteTree(AVLNode* node) {
        if (node) {
            deleteTree(node->left);
            deleteTree(node->right);
            delete node;
        }
    }

public:
    AVLTree() : root(nullptr) {}

    ~AVLTree() {
        deleteTree(root);
    }
    //insertion for new node
    void insert(const string& key, const string& filePath, char** rowData, int columnCount)
    {
        root = insertNode(root, key, filePath, rowData, columnCount);

        //final hash calculation for full tree after insertion is done
        if (root) {
            calculateFullTreeHash();
        }
    }
    // calculates the final tree hash : root's hash
    void calculateFullTreeHash() {
        if (root) {
            root->calculateNodeHash();
        }
    }

    //tree traversal
    void traverse() {
        cout << "AVL Tree Traversal:" << endl;
        inorderTraversal(root, 0);
    }
    //tree height
    int getHeight() {
        return getTreeHeight(root);
    }

    //gives root node hash
    string getRootHash() {
        return root ? root->nodeHash : "";
    }

    AVLNode* getRoot() {
        return root;
    }
};


// Red-Black Tree Node structure


struct NodeColor {
    static const bool RED = false;
    static const bool BLACK = true;
};

struct RBNode {
    string key;             // Key value
    string filePath;        // File path associated with the key
    string rowHash;         // Hash of the entire row
    string keyHash;         // Hash of the key
    string nodeHash;        // Hash of the entire node
    RBNode* left;          // Left child
    RBNode* right;         // Right child
    RBNode* parent;        // Parent node
    bool color;            // Tracks node color
    char** rowData;        // Stores the entire row data
    int columnCount;       // Number of columns in the row

    // Constructor
    RBNode(const string& k, const string& path, char** data, int colCount) :
        key(k),
        filePath(path),
        rowData(nullptr),
        columnCount(colCount),
        keyHash(generateHash(k)),
        nodeHash(""),
        left(nullptr),
        right(nullptr),
        parent(nullptr),
        color(NodeColor::RED) {

        // Deep copy row data
        rowData = new char* [columnCount];
        for (int i = 0; i < columnCount; ++i) {
            rowData[i] = new char[strlen(data[i]) + 1];
            customStringobj.customStrCpy(rowData[i], data[i]);
        }

        // Calculate row hash
        calculateRowHash();
    }

    // Destructor
    ~RBNode() {
        if (rowData) {
            for (int i = 0; i < columnCount; ++i) {
                delete[] rowData[i];
            }
            delete[] rowData;
        }
    }

    // Calculates the row hash
    void calculateRowHash() {
        string combinedHash;
        for (int i = 0; i < columnCount; ++i) {
            string columnHash = generateHash(string(rowData[i]));
            combinedHash += columnHash;
        }
        rowHash = generateHash(combinedHash);
    }

    // Calculates the node hash
    void calculateNodeHash() {
        // If node is a leaf, use row hash
        if (!left && !right) {
            nodeHash = rowHash;
            return;
        }

        // If not a leaf node then it combines row hash with child hashes
        string leftHash = left ? left->nodeHash : "0";
        string rightHash = right ? right->nodeHash : "0";

        //For combining the row hash with child hashes
        string combinedHash = rowHash + leftHash + rightHash;
        nodeHash = generateHash(combinedHash);
    }
};

//-------------------------- red black tree
class RedBlackTree {

public:
    struct NodeRelationships {     //attributes
        string parent;
        string leftChild;
        string rightChild;
    };

    // Add these public methods
    RBNode* findNode(const string& key) {
        return findNodeHelper(root, key);
    }

    NodeRelationships getNodeRelationships(const string& key) {    //to ease the access
        NodeRelationships rels;
        RBNode* node = findNode(key);

        if (node) {
            // Get parent
            rels.parent = node->parent ? getNodeFileName(node->parent->key) : "None";

            // Get l r children
            rels.leftChild = node->left ? getNodeFileName(node->left->key) : "None";
            rels.rightChild = node->right ? getNodeFileName(node->right->key) : "None";
        }
        return rels;
    }

private:
    string getNodeFileName(const string& key) {   //returning file name 
        return key + "_rb.txt";
    }

    RBNode* findNodeHelper(RBNode* node, const string& key) {         // recursively finds a node
        if (!node) return nullptr;

        if (key == node->key) {
            return node;
        }

        if (key < node->key) {
            return findNodeHelper(node->left, key);
        }

        return findNodeHelper(node->right, key);
    }
private:
    RBNode* root;

    // Utility functions for tree manipulation
    void leftRotate(RBNode* x) {
        RBNode* y = x->right;
        x->right = y->left;

        if (y->left != nullptr) {
            y->left->parent = x;
        }

        y->parent = x->parent;

        if (x->parent == nullptr) {
            root = y;
        }
        else if (x == x->parent->left) {
            x->parent->left = y;
        }
        else {
            x->parent->right = y;
        }

        y->left = x;
        x->parent = y;
    }

    void rightRotate(RBNode* x) {
        RBNode* y = x->left;
        x->left = y->right;

        if (y->right != nullptr) {
            y->right->parent = x;
        }

        y->parent = x->parent;

        if (x->parent == nullptr) {
            root = y;
        }
        else if (x == x->parent->right) {
            x->parent->right = y;
        }
        else {
            x->parent->left = y;
        }

        y->right = x;
        x->parent = y;
    }

    void fixInsertion(RBNode* z) {
        while (z->parent && z->parent->color == NodeColor::RED) {
            if (z->parent == z->parent->parent->left) {
                RBNode* y = z->parent->parent->right;

                if (y && y->color == NodeColor::RED) {
                    // Case 1: Uncle is red
                    z->parent->color = NodeColor::BLACK;
                    y->color = NodeColor::BLACK;
                    z->parent->parent->color = NodeColor::RED;
                    z = z->parent->parent;
                }
                else {
                    if (z == z->parent->right) {
                        // Case 2: z is a right child
                        z = z->parent;
                        leftRotate(z);
                    }

                    // Case 3: z is a left child
                    z->parent->color = NodeColor::BLACK;
                    z->parent->parent->color = NodeColor::RED;
                    rightRotate(z->parent->parent);
                }
            }
            else {
                // Mirror image of above cases
                RBNode* y = z->parent->parent->left;

                if (y && y->color == NodeColor::RED) {
                    z->parent->color = NodeColor::BLACK;
                    y->color = NodeColor::BLACK;
                    z->parent->parent->color = NodeColor::RED;
                    z = z->parent->parent;
                }
                else {
                    if (z == z->parent->left) {
                        z = z->parent;
                        rightRotate(z);
                    }

                    z->parent->color = NodeColor::BLACK;
                    z->parent->parent->color = NodeColor::RED;
                    leftRotate(z->parent->parent);
                }
            }

            if (z == root) break;
        }

        // Ensure root is always black
        root->color = NodeColor::BLACK;
    }

    //in order traversal of tree
    void inorderTraversal(RBNode* node, int level) {
        if (!node) return;

        inorderTraversal(node->left, level + 1);

        cout << "Level " << level << ": " << node->key
            << " (Color: " << (node->color == NodeColor::RED ? "RED" : "BLACK") << ")" << endl;

        inorderTraversal(node->right, level + 1);
    }

    // tree height
    int getTreeHeight(RBNode* node) {
        if (!node) return 0;

        int leftHeight = getTreeHeight(node->left);
        int rightHeight = getTreeHeight(node->right);

        return 1 + max(leftHeight, rightHeight);
    }

    // deleting tree
    void deleteTree(RBNode* node) {
        if (node) {
            deleteTree(node->left);
            deleteTree(node->right);
            delete node;
        }
    }

public:
    RedBlackTree() : root(nullptr) {}

    ~RedBlackTree() {
        deleteTree(root);
    }


    // Need to add this method to the rb class to allow access to the root
    RBNode* getRoot() {
        return root;
    }


    // Modify the rb class insert method
    void insert(const string& key, const string& filePath, char** rowData, int columnCount) {
        RBNode* z = new RBNode(key, filePath, rowData, columnCount);

        // inserting as in a bst to get logn time cmpxty
        RBNode* y = nullptr;
        RBNode* x = root;

        while (x != nullptr) {
            y = x;
            if (z->key < x->key) {
                x = x->left;
            }
            else {
                x = x->right;
            }
        }

        z->parent = y;

        if (y == nullptr) {
            root = z;
        }
        else if (z->key < y->key) {
            y->left = z;
        }
        else {
            y->right = z;
        }

        //making sure updation after insertion 
        fixInsertion(z);

        //renewing hashes after insertion
        updateTreeHashes(z);
    }

    // updating tree
    void updateTreeHashes(RBNode* node) {
        while (node) {
            node->calculateNodeHash();
            node = node->parent;
        }
    }

    // traverse method
    void traverse() {
        cout << "Red-Black Tree Traversal:" << endl;
        inorderTraversal(root, 0);
    }

    //get tree height
    int getHeight() {
        return getTreeHeight(root);
    }
};

//----------------------- merkle tree implementation starts here
struct TreeNode {
    int data;
    string hash;
    TreeNode* left;
    TreeNode* right;

    TreeNode(int d, const string& h) : data(d), hash(h), left(nullptr), right(nullptr)
    {

    }
};


class TreeMerger {
public:
    // to merge trees based on merge command
    static void mergeTrees(TreeNode*& mainNode, TreeNode* newNode) {
        if (!mainNode && !newNode) {
            // If both nodes are null, nothing to merge.
            return;
        }

        if (!mainNode && newNode) {
            // If main tree has no node but the new branch has one, insert the new node
            cout << "Inserting new node with data: " << newNode->data << " into main branch." << endl;
            mainNode = newNode;
            return;
        }

        if (mainNode && !newNode) {
            // If the new branch has no node but the main tree has one, no update needed
            return;
        }

        // If hashes don't match, update the main tree by adding the new node
        if (!checkIfHashMatchesOrNot(mainNode, newNode)) {
            cout << "Updating node in main branch with data: " << newNode->data << endl;
            mainNode->data = newNode->data;  // update main ndoe data
            mainNode->hash = newNode->hash;  // update main node hash
        }

        // recursively checking the tree 
        if (mainNode->left || newNode->left) {
            // merging l child
            mergeTrees(mainNode->left, newNode->left);
        }

        if (mainNode->right || newNode->right) {
            // merging r child
            mergeTrees(mainNode->right, newNode->right);
        }
    }

private:
    // to check if hashes match between nodes
    static bool checkIfHashMatchesOrNot(TreeNode* mainNode, TreeNode* newNode) {
        if (!mainNode && !newNode) return true;  //nodes null, no update needed
        if (!mainNode || !newNode) return false; // 1 is null, one node is missing in one branch

        // Compare hashes of both nodes
        return mainNode->hash == newNode->hash;
    }
};

CSVHandler csvobj;

//==========================================================
// COMMAND FUNCTIONS
//==========================================================

// to select records within a range from a specified column
void selectRecordsWithinRange(const string& column, int start, int end, const string& fileName) {
    ifstream file(fileName);
    string line;
    int columnIndex = -1;

    // Read the header to find the column index
    if (getline(file, line)) {
        stringstream ss(line);
        string col;
        int idx = 0;

        while (getline(ss, col, ',')) {
            if (col == column) {
                columnIndex = idx;
                break;
            }
            idx++;
        }
    }

    // invalid col, return
    if (columnIndex == -1) {
        cout << "Column not found: " << column << " in file " << fileName << endl;
        return;
    }

    // cols match, process data
    while (getline(file, line)) {
        stringstream ss(line);
        string value;
        int idx = 0;

        while (getline(ss, value, ',')) {
            if (idx == columnIndex) {
                try {
                    int val = stoi(value);
                    if (val >= start && val <= end) {
                        // Match found, can update or take further action
                        //merge();
                    }
                }
                catch (const invalid_argument&) {
                    //invaldiity
                    //ret
                }
                break;
            }
            idx++;
        }
    }
}

// to update records in a file based on a condition
void updateRecords(const string& targetColumn, const string& targetValue,
    const string& updateColumn, const string& newValue, const string& fileName) {
    ifstream file(fileName);
    string line;
    int targetColumnIndex = -1, updateColumnIndex = -1;

    // finding col
    if (getline(file, line)) {
        stringstream ss(line);
        string col;
        int idx = 0;

        while (getline(ss, col, ',')) {
            if (col == targetColumn) {
                targetColumnIndex = idx;
            }
            if (col == updateColumn) {
                updateColumnIndex = idx;
            }
            idx++;
        }
    }

    // invlid col, exit
    if (targetColumnIndex == -1 || updateColumnIndex == -1) {
        cout << "Columns not found: " << targetColumn << " or " << updateColumn << " in file " << fileName << endl;
        return;
    }

    ofstream tempFile(fileName + ".tmp");
    bool updated = false;

    // process data rows
    while (getline(file, line)) {
        stringstream ss(line);
        string value;
        int idx = 0;
        bool lineUpdated = false;

        // traverse over each col in the current row
        while (getline(ss, value, ',')) {
            if (idx == targetColumnIndex && value == targetValue) {
                lineUpdated = true;
            }
            if (lineUpdated && idx == updateColumnIndex) {
                value = newValue;
            }

            // value to the temp file
            tempFile << value << (ss.peek() == ',' ? "," : "");
            idx++;
        }

        //update was made, mark as updated
        if (lineUpdated) {
            updated = true;
        }

        tempFile << endl;
    }

    file.close();
    tempFile.close();

    // replace org w curr file
    if (updated) {
        fs::remove(fileName);
        fs::rename(fileName + ".tmp", fileName);
        cout << "File " << fileName << " updated successfully." << endl;
    }
    else {
        fs::remove(fileName + ".tmp");
        cout << "No matching records found to update in file " << fileName << "." << endl;
    }
}

// to delete records from a file based on a condition
void deleteRecords(const string& targetColumn, const string& targetValue, const string& fileName) {
    ifstream file(fileName);
    string line;
    int targetColumnIndex = -1;

    // col finding
    if (getline(file, line)) {
        stringstream ss(line);
        string col;
        int idx = 0;

        while (getline(ss, col, ',')) {
            if (col == targetColumn) {
                targetColumnIndex = idx;
                break;
            }
            idx++;
        }
    }

    //invalid col
    if (targetColumnIndex == -1) {
        cout << "Column not found: " << targetColumn << " in file " << fileName << endl;
        return;
    }

    ofstream tempFile(fileName + ".tmp");
    bool deleted = false;

    // process data rows
    while (getline(file, line)) {
        stringstream ss(line);
        string value;
        int idx = 0;
        bool deleteRow = false;

        //traverse over each column in the current row
        while (getline(ss, value, ',')) {
            if (idx == targetColumnIndex && value == targetValue) {
                deleteRow = true;
                break;  // Skip writing this row to the temp file
            }
            idx++;
        }

        // If row is not marked for deletion, write it to the temp file
        if (!deleteRow) {
            tempFile << line << endl;
        }
        else {
            deleted = true;
        }
    }

    file.close();
    tempFile.close();

    // Replace the original file with the updated file
    if (deleted) {
        fs::remove(fileName); // Remove original file
        fs::rename(fileName + ".tmp", fileName); // Rename temp file to original file name
        cout << "File " << fileName << " updated successfully (records deleted)." << endl;
    }
    else {
        fs::remove(fileName + ".tmp");
        cout << "No matching records found to delete in file " << fileName << "." << endl;
    }
}


void deleteFirstRecordByValue(const string& fileName, const string& column, const string& valueToDelete) {
    ifstream file(fileName);
    ofstream tempFile("temp.txt");
    string line;
    int columnIndex = -1;
    bool deleted = false;

    // Read header and find the column index
    if (getline(file, line)) {
        stringstream ss(line);
        string col;
        int idx = 0;

        while (getline(ss, col, ',')) {
            if (col == column) {
                columnIndex = idx;
                break;
            }
            idx++;
        }
        tempFile << line << endl; // Write header to temp file
    }

    // Process data rows
    while (getline(file, line)) {
        stringstream ss(line);
        string value;
        int idx = 0;

        bool deleteRow = false;

        while (getline(ss, value, ',')) {
            if (idx == columnIndex && value == valueToDelete && !deleted) {
                deleteRow = true;  // Mark row for deletion (only first match)
                deleted = true;
                break;
            }
            idx++;
        }

        if (!deleteRow) {
            tempFile << line << endl; // Only write non-deleted rows
        }
    }

    file.close();
    tempFile.close();

    if (deleted) {
        fs::remove(fileName); // Remove original file
        fs::rename("temp.txt", fileName); // Rename temp file to original file name
        cout << "First matching record deleted successfully." << endl;
    }
    else {
        cout << "No matching record found to delete." << endl;
    }
}


//==========================================================
//  REPOSITORY CLASS
//========================================================
class Repository {
private:
    char treeType[20];
    bool isInitialized;
    string logFileName;
    string currentBranch;
    string currentCSVFile;
    int selectedColumn;

    void updateNodeRelationships(const string& filePath,
        const string& parentPath = "None",
        const string& leftChildPath = "None",
        const string& rightChildPath = "None") {
        // Read the entire file
        ifstream inFile(filePath);
        if (!inFile) return;

        vector<string> lines;
        string line;
        bool pastRelationships = false;

        // Read all lines except the old relationships
        while (getline(inFile, line)) {
            if (line.find("Parent:") != string::npos) {
                pastRelationships = true;
                continue;
            }
            if (line.find("Left Child:") != string::npos ||
                line.find("Right Child:") != string::npos) {
                continue;
            }
            if (!pastRelationships) {
                lines.push_back(line);
            }
        }
        inFile.close();

        // Write back the file with updated relationships
        ofstream outFile(filePath);
        if (!outFile) return;

        // Write original content
        for (const string& l : lines) {
            outFile << l << endl;
        }

        // Write updated relationships
        outFile << "Parent: " << parentPath << endl;
        outFile << "Left Child: " << leftChildPath << endl;
        outFile << "Right Child: " << rightChildPath << endl;

        outFile.close();
    }

    void updateAVLRelationships() {
        for (const auto& entry : fs::directory_iterator(currentBranch)) {
            if (entry.path().extension() == ".txt" &&
                entry.path().string().find("_avl.txt") != string::npos) {

                updateNodeRelationships(entry.path().string());
            }
        }
    }

    void updateBTreeRelationships() {
        for (const auto& entry : fs::directory_iterator(currentBranch)) {
            if (entry.path().extension() == ".txt" &&
                entry.path().string().find("_btree.txt") != string::npos) {
                updateNodeRelationships(entry.path().string());
            }
        }
    }

    void updateRBTreeRelationships() {
        for (const auto& entry : fs::directory_iterator(currentBranch)) {
            if (entry.path().extension() == ".txt" &&
                entry.path().string().find("_rb.txt") != string::npos) {
                // Similar to AVL tree, but for Red-Black tree nodes
                updateNodeRelationships(entry.path().string());
            }
        }
    }


public:


    Repository() : isInitialized(false), logFileName("log.txt"), currentBranch("original_branch") {
        treeType[0] = '\0';
    }

    // make folder
    void createFolder(const string& folderName) {
        if (!fs::exists(folderName)) {
            fs::create_directory(folderName);
            logEvent("> Folder created: " + folderName);
        }
    }

    //  Copy files from one folder to another
    void copyFiles(const string& srcFolder, const string& destFolder) {
        createFolder(destFolder);

        // Copy all `.txt` and `.csv` files
        for (const auto& entry : fs::directory_iterator(srcFolder)) {
            string extension = entry.path().extension().string();

            // Check for valid extensions
            if (extension == ".txt" || extension == ".csv") {
                fs::copy(entry, destFolder, fs::copy_options::overwrite_existing);
            }
        }

        logEvent("> Files copied from " + srcFolder + " to " + destFolder);
    }

    // Log events to a file
    void logEvent(const string& event, bool addBoundary = false) {
        // Get paths for logs
        string branchLogPath = currentBranch + "/log.txt";
        string mainLogPath = "log.txt";

        // Helper function to write to a log file
        auto writeToLog = [&](const string& path) {
            ofstream logFile(path, ios::app);
            if (!logFile) {
                cerr << "Error: Could not create or write to log file: " << path << endl;
                return;
            }

            if (addBoundary) {
                logFile << "-------------------" << endl;
            }

            // timestamp
            time_t now = time(0);
            char dt[26];
            ctime_s(dt, sizeof(dt), &now);
            dt[strlen(dt) - 1] = '\0';

            // Include branch name in log entry
            logFile << "[" << dt << "] [Branch: " << currentBranch << "] " << event << endl;
            logFile.close();
            };


        //main log alwasy active
        writeToLog(mainLogPath);

        // if specific non main branch actvie
        if (!currentBranch.empty() && fs::exists(currentBranch)) {
            writeToLog(branchLogPath);
        }
    }

    // Helper function to create AVL Tree from CSV
    void createAVLTreeFromCSV(const string& fileName) {
        ifstream file(fileName);
        if (!file.is_open()) {
            cout << "Error: Could not open file." << endl;
            return;
        }

        string line, columnNames;
        getline(file, columnNames); // Read the first row for column names

        // Count columns
        int columnCount = 1;
        int pos = 0;
        while ((pos = columnNames.find(',')) != string::npos) {
            columnCount++;
            columnNames.erase(0, pos + 1);
        }

        // Reset and reread column names
        file.clear();
        file.seekg(0);
        getline(file, columnNames);

        // Allocate memory for column names
        char** columns = new char* [columnCount];
        for (int i = 0; i < columnCount; ++i) {
            columns[i] = new char[100]; // Assuming max column name length of 100
        }

        // Parse column names
        stringstream headerStream(columnNames);
        string columnName;
        for (int i = 0; i < columnCount; ++i) {
            getline(headerStream, columnName, ',');
            customStringobj.customStrCpy(columns[i], columnName.c_str());
        }

        // Display column options
        cout << "Columns in the file:" << endl;
        for (int i = 0; i < columnCount; ++i) {
            cout << i + 1 << ". " << columns[i] << endl;
        }

        cout << "Enter column number to build the AVL Tree: ";
        int columnNumber;
        cin >> columnNumber;
        selectedColumn = columnNumber;
        AVLTree tree;

        int rowIndex = 2; // To track the row index

        // Prepare to read rows
        while (getline(file, line)) {
            // Allocate memory for row data
            char** rowData = new char* [columnCount];
            for (int i = 0; i < columnCount; ++i) {
                rowData[i] = new char[200]; // Assuming max cell value length of 200
                rowData[i][0] = '\0'; // Initialize as empty string
            }

            // Parse the row
            stringstream rowStream(line);
            string cellValue;
            for (int i = 0; i < columnCount; ++i) {
                if (getline(rowStream, cellValue, ',')) {
                    customStringobj.customStrCpy(rowData[i], cellValue.c_str());
                }
            }

            // Use the selected column as the key
            string key(rowData[columnNumber - 1]);

            // Create file for the node with row index appended to the file name
            string fileName = key + "_" + to_string(rowIndex) + "_avl.txt";
            ofstream nodeFile(fileName);
            if (nodeFile.is_open()) {
                // Write column names and corresponding values
                for (int i = 0; i < columnCount; ++i) {
                    nodeFile << columns[i] << ": " << rowData[i] << endl;
                }

                // Get current node information
                AVLNode* currentNode = tree.getRoot(); // Get the root node or find the node in the tree
                if (currentNode) {
                    nodeFile << "Node Hash: " << currentNode->nodeHash << endl;

                }

                // Get parent and child information
                AVLNode* parentNode = currentNode ? currentNode->parent : nullptr;
                AVLNode* leftChildNode = currentNode ? currentNode->left : nullptr;
                AVLNode* rightChildNode = currentNode ? currentNode->right : nullptr;

                // Parent reference
                nodeFile << "Parent: ";
                if (parentNode) {
                    nodeFile << parentNode->filePath << endl;
                }
                else {
                    nodeFile << "None" << endl;
                }

                // Left Child reference
                nodeFile << "Left Child: ";
                if (leftChildNode) {
                    nodeFile << leftChildNode->filePath << endl;
                }
                else {
                    nodeFile << "None" << endl;
                }

                // Right Child reference
                nodeFile << "Right Child: ";
                if (rightChildNode) {
                    nodeFile << rightChildNode->filePath << endl;
                }
                else {
                    nodeFile << "None" << endl;
                }

                nodeFile.close();
            }

            tree.insert(key, fileName, rowData, columnCount);

            // Clean up row data
            for (int i = 0; i < columnCount; ++i) {
                delete[] rowData[i];
            }
            delete[] rowData;

            rowIndex++; // Increment row index
        }

        // Clean up column names
        for (int i = 0; i < columnCount; ++i) {
            delete[] columns[i];
        }
        delete[] columns;

        file.close();

        cout << "AVL Tree created successfully.\n";
        cout << "Tree traversal by levels:\n";
        tree.traverse();
        cout << "Height of the tree: " << tree.getHeight() << endl;
    }

    //------------ creating rb
    void createRedBlackTreeFromCSV(const string& fileName) {
        ifstream file(fileName);
        if (!file.is_open()) {
            cout << "Error: Could not open file." << endl;
            return;
        }

        string line, columnNames;
        getline(file, columnNames); // Read the first row for column names

        // Count columns
        int columnCount = 1;
        int pos = 0;
        while ((pos = columnNames.find(',')) != string::npos) {
            columnCount++;
            columnNames.erase(0, pos + 1);
        }

        // Reset and reread column names
        file.clear();
        file.seekg(0);
        getline(file, columnNames);

        // Allocate memory for column names
        char** columns = new char* [columnCount];
        for (int i = 0; i < columnCount; ++i) {
            columns[i] = new char[100]; // Assuming max column name length of 100
        }

        // Parse column names
        stringstream headerStream(columnNames);
        string columnName;
        for (int i = 0; i < columnCount; ++i) {
            getline(headerStream, columnName, ',');
            customStringobj.customStrCpy(columns[i], columnName.c_str());
        }

        // Display column options
        cout << "Columns in the file:" << endl;
        for (int i = 0; i < columnCount; ++i) {
            cout << i + 1 << ". " << columns[i] << endl;
        }

        cout << "Enter column number to build the Red-Black Tree: ";
        int columnNumber;
        cin >> columnNumber;
        selectedColumn = columnNumber;
        RedBlackTree tree;

        int rowIndex = 2; // To track the row index

        // Prepare to read rows
        while (getline(file, line)) {
            // Allocate memory for row data
            char** rowData = new char* [columnCount];
            for (int i = 0; i < columnCount; ++i) {
                rowData[i] = new char[200]; // Assuming max cell value length of 200
                rowData[i][0] = '\0'; // Initialize as empty string
            }

            // Parse the row
            stringstream rowStream(line);
            string cellValue;
            for (int i = 0; i < columnCount; ++i) {
                if (getline(rowStream, cellValue, ',')) {
                    customStringobj.customStrCpy(rowData[i], cellValue.c_str());
                }
            }

            // Use the selected column as the key
            string key(rowData[columnNumber - 1]);

            // Create file for the node with row index appended to the file name
            string fileName = key + "_" + to_string(rowIndex) + "_rb.txt";
            ofstream nodeFile(fileName);
            if (nodeFile.is_open()) {
                // Write column names and corresponding values
                for (int i = 0; i < columnCount; ++i) {
                    nodeFile << columns[i] << ": " << rowData[i] << endl;
                }

                tree.insert(key, fileName, rowData, columnCount);

                // Get current node information
                RBNode* currentNode = tree.getRoot();
                while (currentNode && currentNode->key != key) {
                    if (key < currentNode->key)
                        currentNode = currentNode->left;
                    else
                        currentNode = currentNode->right;
                }

                if (currentNode) {

                    nodeFile << "Node Hash: " << currentNode->nodeHash << endl;
                }

                // Write parent and child references
                nodeFile << "Parent: ";
                if (currentNode && currentNode->parent) {
                    nodeFile << currentNode->parent->filePath << endl;
                }
                else {
                    nodeFile << "None" << endl;
                }


                // Write left child reference
                nodeFile << "Left Child: ";
                if (currentNode && currentNode->left) {
                    nodeFile << currentNode->left->key << "_rb.txt" << endl;
                }
                else {
                    nodeFile << "None" << endl;
                }

                // Write right child reference
                nodeFile << "Right Child: ";
                if (currentNode && currentNode->right) {
                    nodeFile << currentNode->right->key << "_rb.txt" << endl;
                }
                else {
                    nodeFile << "None" << endl;
                }

                nodeFile.close();
            }

            // Clean up row data
            for (int i = 0; i < columnCount; ++i) {
                delete[] rowData[i];
            }
            delete[] rowData;

            rowIndex++; // Increment row index
        }

        // Clean up column names
        for (int i = 0; i < columnCount; ++i) {
            delete[] columns[i];
        }
        delete[] columns;

        file.close();

        cout << "Red-Black Tree created successfully.\n";
        cout << "Tree traversal by levels:\n";
        tree.traverse();
        cout << "Height of the tree: " << tree.getHeight() << endl;
    }

    // Helper function to read the CSV file and create the B-Tree
    void createBTreeFromCSV(const string& fileName) {
        ifstream file(fileName);
        if (!file.is_open()) {
            cout << "Error: Could not open file." << endl;
            return;
        }

        string line, columnNames;
        getline(file, columnNames); // Read the first row for column names

        // Count columns
        int columnCount = 1;
        int pos = 0;
        while ((pos = columnNames.find(',')) != string::npos) {
            columnCount++;
            columnNames.erase(0, pos + 1);
        }

        // Reset and reread column names
        file.clear();
        file.seekg(0);
        getline(file, columnNames);

        // Allocate memory for column names
        char** columns = new char* [columnCount];
        for (int i = 0; i < columnCount; ++i) {
            columns[i] = new char[100]; // Assuming max column name length of 100
        }

        // Parse column names
        stringstream headerStream(columnNames);
        string columnName;
        for (int i = 0; i < columnCount; ++i) {
            getline(headerStream, columnName, ',');
            customStringobj.customStrCpy(columns[i], columnName.c_str());
        }

        // Display column options
        cout << "Columns in the file:" << endl;
        for (int i = 0; i < columnCount; ++i) {
            cout << i + 1 << ". " << columns[i] << endl;
        }

        cout << "Enter column number to build the B-Tree: ";
        int columnNumber;
        cin >> columnNumber;
        selectedColumn = columnNumber;
        cout << "Enter order of the B-Tree (minimum degree): ";
        int order;
        cin >> order;

        BTree tree(order);

        // Prepare to read rows
        int rowIndex = 2;
        while (getline(file, line)) {
            // Allocate memory for row data
            char** rowData = new char* [columnCount];
            for (int i = 0; i < columnCount; ++i) {
                rowData[i] = new char[200]; // Assuming max cell value length of 200
                rowData[i][0] = '\0'; // Initialize as empty string
            }

            // Parse the row
            stringstream rowStream(line);
            string cellValue;
            for (int i = 0; i < columnCount; ++i) {
                if (getline(rowStream, cellValue, ',')) {
                    customStringobj.customStrCpy(rowData[i], cellValue.c_str());
                }
            }

            // Use the selected column as the key
            string key(rowData[columnNumber - 1]);

            // Create file for the node with all row data (using row index)
            string fileNameWithRow = key + "_" + to_string(rowIndex) + "_btree.txt";
            ofstream nodeFile(fileNameWithRow);
            if (nodeFile.is_open()) {
                // Write column names and corresponding values
                for (int i = 0; i < columnCount; ++i) {
                    nodeFile << columns[i] << ": " << rowData[i] << endl;
                }

                // Write hash information
              //  cout << "Key Hash: " << generateHash(key) << endl;

                // Calculate and write row hash
                string rowHash;
                for (int i = 0; i < columnCount; i++) {
                    rowHash += generateHash(string(rowData[i]));
                }
                //  cout << "Row Hash: " << generateHash(rowHash) << endl;

                  // Write node hash if available
                BTreeNode* currentNode = tree.getRoot();
                if (currentNode) {
                    nodeFile << "Node Hash: " << currentNode->nodeHash << endl;
                    //   cout << "Node Hash: " << currentNode->nodeHash << endl;
                }

                // Parent reference
                nodeFile << "Parent: ";
                BTreeNode* parentNode = currentNode ? currentNode->parent : nullptr;
                if (parentNode) {
                    // Find the key of the parent node's first occurrence
                    nodeFile << parentNode->keys[0] << "_btree.txt" << endl;
                }
                else {
                    nodeFile << "None" << endl;
                }

                // Find the node's index and get child references
                nodeFile << "Left Child: ";
                bool foundChild = false;
                if (currentNode && !currentNode->isLeaf) {
                    for (int i = 0; i <= currentNode->numKeys; ++i) {
                        if (currentNode->children[i]) {
                            nodeFile << currentNode->children[i]->keys[0] << "_btree.txt" << endl;
                            foundChild = true;
                            break;
                        }
                    }
                }
                if (!foundChild) {
                    nodeFile << "None" << endl;
                }

                // Right Child reference
                nodeFile << "Right Child: ";
                foundChild = false;
                if (currentNode && !currentNode->isLeaf) {
                    for (int i = currentNode->numKeys; i >= 0; --i) {
                        if (currentNode->children[i]) {
                            nodeFile << currentNode->children[i]->keys[0] << "_btree.txt" << endl;
                            foundChild = true;
                            break;
                        }
                    }
                }
                if (!foundChild) {
                    nodeFile << "None" << endl;
                }

                nodeFile.close();
            }

            tree.insert(key, fileNameWithRow, rowData, columnCount);
            // Clean up row data
            for (int i = 0; i < columnCount; ++i) {
                delete[] rowData[i];
            }
            delete[] rowData;

            rowIndex++; // Increment row index for the next row
        }

        // Clean up column names
        for (int i = 0; i < columnCount; ++i) {
            delete[] columns[i];
        }
        delete[] columns;

        file.close();

        cout << "B-Tree created successfully.\n";
        cout << "Tree traversal by levels:\n";
        tree.traverse();
        cout << "Height of the tree: " << tree.getHeight() << endl;
    }

    void init(const string& csvFile) {
        if (isInitialized) {
            cout << "Repository already initialized!" << endl;
            logEvent("> Attempted re-initialization.");
            return;
        }
        currentCSVFile = csvFile;
        int hashChoice;
        cout << "Select hash method:\n";
        cout << "1. Instructor's Custom Hash\n";
        cout << "2. SHA256 Hash\n";

        while (true) {
            cout << "Enter your choice (1 or 2): ";
            cin >> hashChoice;

            if (hashChoice == 1) {
                cout << "Using Instructor Hash Method" << endl;
                ::userChoice = 1;
                break;  // Valid choice, break out of the loop
            }
            else if (hashChoice == 2) {
                cout << "Using SHA256 Hash Method" << endl;
                ::userChoice = 0;
                break;  // Valid choice, break out of the loop
            }
            else {
                cout << "Invalid Choice. Please select 1 or 2." << endl;
            }
        }



        // Prompt user for tree type
        cout << "Choose tree type (AVL/B/Red-Black): ";
        char choice[20];

        // Keep prompting the user until a valid choice is made
        while (true) {
            cin >> choice;

            if (strcmp(choice, "AVL") == 0) {
                customStringobj.customStrCpy(treeType, "AVL");
                createAVLTreeFromCSV(csvFile);
                logEvent("> AVL tree created.");
                break;  // Valid choice, break out of the loop
            }
            else if (strcmp(choice, "B") == 0) {
                customStringobj.customStrCpy(treeType, "B");
                createBTreeFromCSV(csvFile);
                logEvent("> B tree created.");
                break;  // Valid choice, break out of the loop
            }
            else if (strcmp(choice, "RB") == 0) {
                customStringobj.customStrCpy(treeType, "RB");
                createRedBlackTreeFromCSV(csvFile);
                logEvent("> Red-Black tree created.");
                break;  // Valid choice, break out of the loop
            }
            else {
                cout << "Invalid tree type selection! Please choose one of the following: AVL, B, or Red-Black." << endl;
                logEvent("> Invalid tree type selected.");
                cout << "Choose tree type (AVL/B/Red-Black): ";  // Prompt again
            }
        }


        // Create the original branch folder
        createFolder("original_branch");

        // Get the absolute path of the CSV file
        fs::path csvFilePath = fs::absolute(csvFile);
        fs::path parentFolder = csvFilePath.parent_path();

        // If parentFolder is empty, use current path
        if (parentFolder.empty()) {
            parentFolder = fs::current_path();
        }

        // Debugging: Print the parent folder
        cout << "Parent folder: " << parentFolder << endl;

        // Copy the CSV file to original_branch
        fs::copy(csvFilePath, "original_branch/", fs::copy_options::overwrite_existing);

        // Copy all .txt files from the parent folder to original_branch
        for (const auto& entry : fs::directory_iterator(parentFolder)) {
            string extension = entry.path().extension().string();
            if (extension == ".txt") {
                // Debugging: Print the files being copied
                cout << "Copying file: " << entry.path() << " to original_branch/" << endl;

                fs::copy(entry.path(), "original_branch/", fs::copy_options::overwrite_existing);
                logEvent("> Copied file: " + entry.path().string());
            }
        }

        logEvent("> Repository initialized with original branch.");

        isInitialized = true;
        cout << "Repository initialized with " << treeType << " tree type." << endl;
    }

    void createBranch(const string& branchName) {
        if (!isInitialized) {
            cout << "Initialize repository first using the init command!" << endl;
            return;
        }

        // Define the branch folder path
        string branchFolder = branchName;

        // Check if the branch folder already exists
        if (fs::exists(branchFolder)) {
            cout << "Branch '" << branchName << "' already exists!" << endl;
            logEvent("> Failed to create branch: " + branchName + " (already exists)");
            return;
        }

        // Create the branch folder
        createFolder(branchFolder);

        // Copy all files from original_branch to the new branch folder
        copyFiles("original_branch", branchFolder);

        logEvent("> Branch created: " + branchName);
        cout << "Branch '" << branchName << "' created successfully." << endl;
    }

    void checkout(const string& branchName) {
        if (!isInitialized) {
            cout << "Initialize repository first using the init command!" << endl;
            return;
        }

        // Check if the branch folder exists
        if (!fs::exists(branchName)) {
            cout << "Branch '" << branchName << "' does not exist!" << endl;
            logEvent("> Failed to switch branch: " + branchName + " (does not exist)");
            return;
        }

        // Switch to the new branch
        currentBranch = branchName;
        logEvent("> Switched to branch: " + branchName);
        cout << "Switched to branch '" << branchName << "'." << endl;
    }

    void commit(const string& message) {
        if (!isInitialized) {
            cout << "Initialize repository first using the init command!" << endl;
            return;
        }

        if (message.empty()) {
            cout << "Commit message cannot be empty!" << endl;
            logEvent("> Failed to commit changes: Empty message");
            return;
        }

        // timestamp for the commit   ( bonus marks plis )
        time_t now = time(0);
        char dt[26];
        ctime_s(dt, sizeof(dt), &now);
        dt[strlen(dt) - 1] = '\0';

        // Log the commit details
        string logMessage = "Commit on branch '" + currentBranch + "' with message: \"" + message + "\"";
        logEvent("> " + logMessage, true);

        cout << "Changes committed with message: \"" << message << "\"." << endl;
    }


    // prints all available branches
    void listBranches() {
        if (!isInitialized) {
            cout << "Initialize repository first using the init command!" << endl;
            return;
        }

        cout << "Branches:" << endl;

        for (const auto& entry : fs::directory_iterator(".")) {
            if (fs::is_directory(entry.path())) {
                string branchName = entry.path().filename().string();

                // out non-branch folders
                if (branchName == "x64" || branchName == "bin" || branchName == "obj") {
                    continue; // Skip 
                }

                cout << "- " << branchName << endl;
            }
        }

        logEvent("> Displayed all branches.");
    }

    string getCurrentBranch() const {
        return currentBranch;
    }
    void deleteBranch(const string& branchName) {
        if (!isInitialized) {
            cout << "Initialize repository first using the init command!" << endl;
            return;
        }

        // Prevent deleting the current branch
        if (branchName == currentBranch) {
            cout << "Cannot delete the currently active branch '" << branchName << "'." << endl;
            logEvent("> Failed to delete branch: " + branchName + " (currently active)");
            return;
        }

        // Check if the branch exists
        string branchFolder = branchName;
        if (!fs::exists(branchFolder) || !fs::is_directory(branchFolder)) {
            cout << "Branch '" << branchName << "' does not exist." << endl;
            logEvent("> Failed to delete branch: " + branchName + " (does not exist)");
            return;
        }

        // Delete the branch folder
        fs::remove_all(branchFolder);
        logEvent("> Branch deleted: " + branchName);
        cout << "Branch '" << branchName << "' deleted successfully." << endl;
    }


    void mergeBranches(const string& sourceBranch, const string& targetBranch) {
        if (!isInitialized) {
            cout << "Initialize repository first using the init command!" << endl;
            return;
        }

        // Prevent merging the branch into itself 
        if (sourceBranch == targetBranch) {
            cout << "Cannot merge a branch into itself." << endl;
            logEvent("> Failed to merge branches: Source and target are the same");
            return;
        }

        // Check if the source branch exists
        if (!fs::exists(sourceBranch) || !fs::is_directory(sourceBranch)) {
            cout << "Source branch '" << sourceBranch << "' does not exist." << endl;
            logEvent("> Failed to merge branches: Source branch '" + sourceBranch + "' does not exist");
            return;
        }

        // Check if the target branch exists
        if (!fs::exists(targetBranch) || !fs::is_directory(targetBranch)) {
            cout << "Target branch '" << targetBranch << "' does not exist." << endl;
            logEvent("> Failed to merge branches: Target branch '" + targetBranch + "' does not exist");
            return;
        }

        // Find CSV files in both branches
        string sourceCSV, targetCSV;
        for (const auto& entry : fs::directory_iterator(sourceBranch)) {
            if (entry.path().extension() == ".csv") {
                sourceCSV = entry.path().string();
                break;
            }
        }
        for (const auto& entry : fs::directory_iterator(targetBranch)) {
            if (entry.path().extension() == ".csv") {
                targetCSV = entry.path().string();
                break;
            }
        }

        if (sourceCSV.empty() || targetCSV.empty()) {
            cout << "CSV file not found in one of the branches." << endl;
            logEvent("> Failed to merge branches: CSV file missing");
            return;
        }

        // Read source CSV content
        ifstream sourceFile(sourceCSV);
        string header;
        getline(sourceFile, header); // Read and store header
        vector<string> uniqueRows; // Changed to vector from map
        map<string, bool> seenRows; // Track seen rows
        string line;
        while (getline(sourceFile, line)) {
            if (!seenRows[line]) {
                uniqueRows.push_back(line);
                seenRows[line] = true;
            }
        }
        sourceFile.close();

        // Read and merge target CSV content
        ifstream targetFile(targetCSV);
        getline(targetFile, line); // Skip header
        while (getline(targetFile, line)) {
            if (!seenRows[line]) {
                uniqueRows.push_back(line);
                seenRows[line] = true;
            }
        }
        targetFile.close();

        // Write merged content back to target CSV while preserving order
        ofstream mergedFile(targetCSV);
        mergedFile << header << endl; // Write header
        for (const auto& row : uniqueRows) {
            mergedFile << row << endl;
        }
        mergedFile.close();


        // Merge other files from source to target
        for (const auto& entry : fs::recursive_directory_iterator(sourceBranch)) {
            if (entry.path().extension() != ".csv") { // Skip CSV file as it's already handled
                string relativePath = fs::relative(entry.path(), sourceBranch).string();
                string targetPath = targetBranch + "/" + relativePath;

                if (fs::is_directory(entry.path())) {
                    if (!fs::exists(targetPath)) {
                        fs::create_directory(targetPath);
                    }
                }
                else {
                    fs::copy(entry.path(), targetPath, fs::copy_options::overwrite_existing);
                }
            }
        }

        // Regenerate tree files in target branch
        string targetCSVPath = targetCSV;
        if (strcmp(treeType, "AVL") == 0) {
            createAVLTreeFromCSV(targetCSVPath);
        }
        else if (strcmp(treeType, "B") == 0) {
            createBTreeFromCSV(targetCSVPath);
        }
        else if (strcmp(treeType, "RB") == 0) {
            createRedBlackTreeFromCSV(targetCSVPath);
        }

        logEvent("> Merged branch '" + sourceBranch + "' into '" + targetBranch + "'");
        cout << "Merged '" << sourceBranch << "' into '" << targetBranch << "' successfully." << endl;
    }


    void addRecord(const string& values) {
        if (!isInitialized) {
            cout << "Initialize repository first using the init command!" << endl;
            return;
        }

        // Find the original CSV file name in the current branch
        string csvFileName;
        for (const auto& entry : fs::directory_iterator(currentBranch)) {
            if (entry.path().extension() == ".csv") {
                csvFileName = entry.path().filename().string();
                break;
            }
        }

        if (csvFileName.empty()) {
            cout << "Error: No CSV file found in branch '" << currentBranch << "'." << endl;
            logEvent("> Failed to add record (CSV file not found)");
            return;
        }

        string csvPath = currentBranch + "/" + csvFileName;

        // First, verify if the file exists and has content
        ifstream checkFile(csvPath);
        if (!checkFile) {
            cout << "Error: Could not open CSV file: " << csvPath << endl;
            logEvent("> Failed to add record (file access error)");
            return;
        }

        // Get the header line
        string headerLine;
        getline(checkFile, headerLine);

        // Read the entire file content
        string fileContent = headerLine;
        string line;
        while (getline(checkFile, line)) {
            fileContent += "\n" + line;
        }
        checkFile.close();

        // Add new record to CSV
        ofstream csvFile(csvPath);
        if (!csvFile) {
            cout << "Error: Could not open CSV file for writing: " << csvPath << endl;
            logEvent("> Failed to add record (file write error)");
            return;
        }
        csvFile << fileContent << "\n" << values;
        csvFile.close();

        // Delete all existing text files in the branch
        for (const auto& entry : fs::directory_iterator(currentBranch)) {
            if (entry.path().extension() == ".txt") {
                fs::remove(entry.path());
            }
        }

        // Create tree and text files in the branch directory
        try {
            if (strcmp(treeType, "AVL") == 0) {
                createAVLTreeFromCSV(csvPath);
                // Move all newly created .txt files to the branch directory
                for (const auto& entry : fs::directory_iterator(".")) {
                    if (entry.path().extension() == ".txt" &&
                        entry.path().string().find("_avl.txt") != string::npos) {
                        string newPath = currentBranch + "/" + entry.path().filename().string();
                        if (fs::exists(entry.path())) {
                            fs::rename(entry.path(), newPath);
                        }
                    }
                }
            }
            else if (strcmp(treeType, "B") == 0) {
                createBTreeFromCSV(csvPath);
                // Move all newly created .txt files to the branch directory
                for (const auto& entry : fs::directory_iterator(".")) {
                    if (entry.path().extension() == ".txt" &&
                        entry.path().string().find("_btree.txt") != string::npos) {
                        string newPath = currentBranch + "/" + entry.path().filename().string();
                        if (fs::exists(entry.path())) {
                            fs::rename(entry.path(), newPath);
                        }
                    }
                }
            }
            else if (strcmp(treeType, "RB") == 0) {
                createRedBlackTreeFromCSV(csvPath);
                // Move all newly created .txt files to the branch directory
                for (const auto& entry : fs::directory_iterator(".")) {
                    if (entry.path().extension() == ".txt" &&
                        entry.path().string().find("_rb.txt") != string::npos) {
                        string newPath = currentBranch + "/" + entry.path().filename().string();
                        if (fs::exists(entry.path())) {
                            fs::rename(entry.path(), newPath);
                        }
                    }
                }
            }
        }
        catch (const exception& e) {
            cout << "Error rebuilding tree: " << e.what() << endl;
            logEvent("> Error rebuilding tree after adding record");
            return;
        }

        logEvent("> Record added to branch: " + currentBranch);
        cout << "Record added successfully and tree files regenerated in branch." << endl;
    }
    void deleteRecord(const string& key) {
        if (!isInitialized) {
            cout << "Initialize repository first using the init command!" << endl;
            return;
        }

        // Find CSV file in current branch
        string csvFileName;
        for (const auto& entry : fs::directory_iterator(currentBranch)) {
            if (entry.path().extension() == ".csv") {
                csvFileName = entry.path().filename().string();
                break;
            }
        }

        if (csvFileName.empty()) {
            cout << "Error: No CSV file found in branch '" << currentBranch << "'." << endl;
            logEvent("> Failed to delete record (CSV file not found)");
            return;
        }

        string csvPath = currentBranch + "/" + csvFileName;

        // Open the CSV file
        ifstream inFile(csvPath);
        if (!inFile) {
            cout << "Error: Could not open CSV file for reading." << endl;
            logEvent("> Failed to delete record (file read error)");
            return;
        }

        // Get header and store file content
        string header;
        getline(inFile, header);
        vector<string> rows;
        string line;

        // Find all matching rows
        vector<pair<int, string>> matchingRows;
        int rowIndex = 0;
        while (getline(inFile, line)) {
            rows.push_back(line);
            stringstream ss(line);
            string cell;
            vector<string> cells;

            while (getline(ss, cell, ',')) {
                cells.push_back(cell);
            }

            // Check if the key matches in the selected column
            if (cells[selectedColumn - 1].find(key) != string::npos) {
                matchingRows.push_back({ rowIndex, line });
            }
            rowIndex++;
        }
        inFile.close();

        // If multiple matches found, ask user which one to delete
        int rowToDelete = -1;
        if (matchingRows.size() > 1) {
            cout << "Multiple matching rows found:" << endl;
            for (int i = 0; i < matchingRows.size(); i++) {
                cout << i + 1 << ". " << matchingRows[i].second << endl;
            }
            cout << "Enter number of row to delete (1-" << matchingRows.size() << "): ";
            int choice;
            cin >> choice;
            if (choice >= 1 && choice <= matchingRows.size()) {
                rowToDelete = matchingRows[choice - 1].first;
            }
        }
        else if (matchingRows.size() == 1) {
            rowToDelete = matchingRows[0].first;
        }
        else {
            cout << "No matching records found." << endl;
            logEvent("> Failed to delete record (no matches found)");
            return;
        }

        // Delete the selected row
        if (rowToDelete >= 0) {
            rows.erase(rows.begin() + rowToDelete);

            // Write back to CSV
            ofstream outFile(csvPath);
            if (!outFile) {
                cout << "Error: Could not open CSV file for writing." << endl;
                logEvent("> Failed to delete record (file write error)");
                return;
            }

            outFile << header << endl;
            for (const string& row : rows) {
                outFile << row << endl;
            }
            outFile.close();

            // Delete all existing tree files in branch
            for (const auto& entry : fs::directory_iterator(currentBranch)) {
                if (entry.path().extension() == ".txt") {
                    fs::remove(entry.path());
                }
            }

            // Regenerate tree files
            try {
                if (strcmp(treeType, "AVL") == 0) {
                    createAVLTreeFromCSV(csvPath);
                    // Move new files to branch directory
                    for (const auto& entry : fs::directory_iterator(".")) {
                        if (entry.path().extension() == ".txt" &&
                            entry.path().string().find("_avl.txt") != string::npos) {
                            string newPath = currentBranch + "/" + entry.path().filename().string();
                            if (fs::exists(entry.path())) {
                                fs::rename(entry.path(), newPath);
                            }
                        }
                    }
                }
                else if (strcmp(treeType, "B") == 0) {
                    createBTreeFromCSV(csvPath);
                    for (const auto& entry : fs::directory_iterator(".")) {
                        if (entry.path().extension() == ".txt" &&
                            entry.path().string().find("_btree.txt") != string::npos) {
                            string newPath = currentBranch + "/" + entry.path().filename().string();
                            if (fs::exists(entry.path())) {
                                fs::rename(entry.path(), newPath);
                            }
                        }
                    }
                }
                else if (strcmp(treeType, "RB") == 0) {
                    createRedBlackTreeFromCSV(csvPath);
                    for (const auto& entry : fs::directory_iterator(".")) {
                        if (entry.path().extension() == ".txt" &&
                            entry.path().string().find("_rb.txt") != string::npos) {
                            string newPath = currentBranch + "/" + entry.path().filename().string();
                            if (fs::exists(entry.path())) {
                                fs::rename(entry.path(), newPath);
                            }
                        }
                    }
                }
            }
            catch (const exception& e) {
                cout << "Error rebuilding tree: " << e.what() << endl;
                logEvent("> Error rebuilding tree after deleting record");
                return;
            }

            logEvent("> Record deleted from branch: " + currentBranch);
            cout << "Record deleted successfully and tree files regenerated." << endl;
        }
    }

    void editFile() {
        cout << "Enter key to edit: ";
        string searchKey;
        cin >> searchKey;

        // First, find all matching files in the current branch
        vector<string> matchingFiles;
        for (const auto& entry : fs::directory_iterator(currentBranch)) {
            string filename = entry.path().filename().string();
            if (filename.find(searchKey) != string::npos &&
                filename.find(".txt") != string::npos) {
                matchingFiles.push_back(filename);
            }
        }

        // If no matches found
        if (matchingFiles.empty()) {
            cout << "No matching files found for key: " << searchKey << endl;
            logEvent("> Edit failed: No matching files found for key: " + searchKey);
            return;
        }

        // If multiple matches found, let user select
        string selectedFile;
        if (matchingFiles.size() > 1) {
            cout << "Multiple matches found. Select the file to edit:" << endl;
            for (int i = 0; i < matchingFiles.size(); i++) {
                cout << i + 1 << ". " << matchingFiles[i] << endl;
            }

            int choice;
            cout << "Enter number (1-" << matchingFiles.size() << "): ";
            cin >> choice;

            if (choice < 1 || choice > matchingFiles.size()) {
                cout << "Invalid selection!" << endl;
                return;
            }
            selectedFile = matchingFiles[choice - 1];
        }
        else {
            selectedFile = matchingFiles[0];
        }

        // Read the selected file
        string filePath = currentBranch + "/" + selectedFile;
        ifstream file(filePath);
        if (!file.is_open()) {
            cout << "Error opening file: " << filePath << endl;
            return;
        }

        // Read and store columns and their values
        vector<pair<string, string>> columns;
        string line;
        while (getline(file, line)) {
            int colonPos = line.find(": ");
            if (colonPos != string::npos) {
                string columnName = line.substr(0, colonPos);
                string value = line.substr(colonPos + 2);

                // Skip hash and relationship fields
                if (columnName != "Node Hash" &&
                    columnName != "Parent" &&
                    columnName != "Left Child" &&
                    columnName != "Right Child") {
                    columns.push_back({ columnName, value });
                }
            }
        }
        file.close();

        // Display columns and let user select which to edit
        cout << "Available columns to edit:" << endl;
        for (int i = 0; i < columns.size(); i++) {
            cout << i + 1 << ". " << columns[i].first << ": " << columns[i].second << endl;
        }

        cout << "Enter column number to edit (1-" << columns.size() << "): ";
        int columnChoice;
        cin >> columnChoice;

        if (columnChoice < 1 || columnChoice > columns.size()) {
            cout << "Invalid column selection!" << endl;
            return;
        }

        // Get new value
        cout << "Enter new value for " << columns[columnChoice - 1].first << ": ";
        cin.ignore();
        string newValue;
        getline(cin, newValue);

        // Update CSV file first
        string csvPath;
        for (const auto& entry : fs::directory_iterator(currentBranch)) {
            if (entry.path().extension() == ".csv") {
                csvPath = entry.path().string();
                break;
            }
        }

        if (csvPath.empty()) {
            cout << "Error: CSV file not found in branch!" << endl;
            return;
        }

        // Read CSV headers and content
        vector<vector<string>> csvContent;
        ifstream csvFile(csvPath);
        getline(csvFile, line); // Read header
        csvContent.push_back(splitCSVLine(line));

        bool recordFound = false;
        while (getline(csvFile, line)) {
            vector<string> row = splitCSVLine(line);
            if (row[selectedColumn - 1] == searchKey) {
                row[columnChoice - 1] = newValue;
                recordFound = true;
            }
            csvContent.push_back(row);
        }
        csvFile.close();

        if (!recordFound) {
            cout << "Error: Record not found in CSV file!" << endl;
            return;
        }

        // Write updated content back to CSV
        ofstream csvOutFile(csvPath);
        for (const auto& row : csvContent) {
            for (int i = 0; i < row.size(); i++) {
                csvOutFile << row[i];
                if (i < row.size() - 1) csvOutFile << ",";
            }
            csvOutFile << endl;
        }
        csvOutFile.close();

        // Regenerate tree files
        if (strcmp(treeType, "AVL") == 0) {
            createAVLTreeFromCSV(csvPath);
        }
        else if (strcmp(treeType, "B") == 0) {
            createBTreeFromCSV(csvPath);
        }
        else if (strcmp(treeType, "RB") == 0) {
            createRedBlackTreeFromCSV(csvPath);
        }

        // Move new files to branch directory
        for (const auto& entry : fs::directory_iterator(".")) {
            if (entry.path().extension() == ".txt") {
                string suffix;
                if (strcmp(treeType, "AVL") == 0) suffix = "_avl.txt";
                else if (strcmp(treeType, "B") == 0) suffix = "_btree.txt";
                else if (strcmp(treeType, "RB") == 0) suffix = "_rb.txt";

                if (entry.path().string().find(suffix) != string::npos) {
                    string newPath = currentBranch + "/" + entry.path().filename().string();
                    if (fs::exists(entry.path())) {
                        fs::rename(entry.path(), newPath);
                    }
                }
            }
        }

        logEvent("> Edited file: " + selectedFile + ", updated " + columns[columnChoice - 1].first);
        cout << "File updated successfully!" << endl;
    }


    void saveRepository(const string& savePath) {
        if (!isInitialized) {
            cout << "Initialize repository first using the init command!" << endl;
            return;
        }

        try {
            // Create save directory if it doesn't exist
            fs::create_directories(savePath);

            // Save repository metadata
            ofstream metaFile(savePath + "/metadata.txt");
            if (!metaFile) {
                throw runtime_error("Could not create metadata file");
            }
            metaFile << treeType << endl;
            metaFile << currentBranch << endl;
            metaFile << currentCSVFile << endl;
            metaFile << selectedColumn << endl;
            metaFile << userChoice << endl;
            metaFile.close();

            // Save each branch
            for (const auto& entry : fs::directory_iterator(".")) {
                if (fs::is_directory(entry) && entry.path().filename() != savePath &&
                    entry.path().filename() != "x64" &&
                    entry.path().filename() != "bin" &&
                    entry.path().filename() != "obj") {

                    string branchName = entry.path().filename().string();
                    string branchSavePath = savePath + "/" + branchName;

                    // Create branch directory in save location
                    fs::create_directory(branchSavePath);

                    // Copy all files from branch to save location
                    for (const auto& file : fs::directory_iterator(entry)) {
                        fs::copy(file.path(), branchSavePath, fs::copy_options::overwrite_existing);
                    }
                }
            }

            logEvent("> Repository saved to: " + savePath);
            cout << "Repository successfully saved to: " << savePath << endl;

        }
        catch (const exception& e) {
            cout << "Error saving repository: " << e.what() << endl;
            logEvent("> Failed to save repository: " + string(e.what()));
        }
    }

    void loadRepository(const string& loadPath) {
        try {
            if (!fs::exists(loadPath)) {
                throw runtime_error("Save directory does not exist");
            }

            // Load metadata
            ifstream metaFile(loadPath + "/metadata.txt");
            if (!metaFile) {
                throw runtime_error("Could not open metadata file");
            }

            string storedTreeType, storedCurrentBranch, storedCSVFile;
            int storedSelectedColumn, storedUserChoice;

            getline(metaFile, storedTreeType);
            getline(metaFile, storedCurrentBranch);
            getline(metaFile, storedCSVFile);
            metaFile >> storedSelectedColumn;
            metaFile >> storedUserChoice;
            metaFile.close();

            // Clean up existing repository if any
            for (const auto& entry : fs::directory_iterator(".")) {
                if (fs::is_directory(entry) &&
                    entry.path().filename() != loadPath &&
                    entry.path().filename() != "x64" &&
                    entry.path().filename() != "bin" &&
                    entry.path().filename() != "obj") {
                    fs::remove_all(entry);
                }
            }

            // Restore branches
            for (const auto& entry : fs::directory_iterator(loadPath)) {
                if (fs::is_directory(entry) && entry.path().filename() != "metadata.txt") {
                    string branchName = entry.path().filename().string();
                    fs::create_directory(branchName);

                    // Copy all files from save location to branch
                    for (const auto& file : fs::directory_iterator(entry)) {
                        fs::copy(file.path(), branchName, fs::copy_options::overwrite_existing);
                    }
                }
            }

            // Restore repository state
            customStringobj.customStrCpy(treeType, storedTreeType.c_str());
            currentBranch = storedCurrentBranch;
            currentCSVFile = storedCSVFile;
            selectedColumn = storedSelectedColumn;
            ::userChoice = storedUserChoice;
            isInitialized = true;

            logEvent("> Repository loaded from: " + loadPath);
            cout << "Repository successfully loaded from: " << loadPath << endl;
            cout << "Current branch: " << currentBranch << endl;
            cout << "Tree type: " << treeType << endl;

        }
        catch (const exception& e) {
            cout << "Error loading repository: " << e.what() << endl;
            logEvent("> Failed to load repository: " + string(e.what()));
        }
    }

    // Helper function to split CSV line
    vector<string> splitCSVLine(const string& line) {
        vector<string> result;
        stringstream ss(line);
        string cell;

        while (getline(ss, cell, ',')) {
            result.push_back(cell);
        }

        return result;
    }

};

//--------------------------------c o m m a n d -------------------
void handleCommand(Repository& repo) {
    char command[50];
    while (true) {
        cout << "> ";
        cin >> command;

        if (strcmp(command, "init") == 0) {
            string csvFile;
            cout << "Enter path to CSV file: ";
            cin >> csvFile;
            repo.init(csvFile);
        }
        else if (strcmp(command, "branch") == 0) {
            string branchName;
            cin >> branchName;
            repo.createBranch(branchName);
        }
        else if (strcmp(command, "checkout") == 0) {
            string branchName;
            cin >> branchName;
            repo.checkout(branchName);
        }

        else if (strcmp(command, "commit") == 0) {
            string message;
            cout << "Enter commit message: ";
            cin.ignore();
            getline(cin, message);
            repo.commit(message);
        }
        else if (strcmp(command, "branches") == 0) {
            repo.listBranches();
        }
        else if (strcmp(command, "delete-branch") == 0) {
            string branchName;
            cout << "Enter branch name: ";
            cin >> branchName;
            repo.deleteBranch(branchName);
        }
        else if (strcmp(command, "merge") == 0) {
            string sourceBranch, targetBranch;
            cout << "Enter source branch: ";
            cin >> sourceBranch;
            cout << "Enter target branch: ";
            cin >> targetBranch;
            repo.mergeBranches(sourceBranch, targetBranch);
        }
        else  if (strcmp(command, "add") == 0) {
            cin.ignore(); // Clear any leftover newline
            cout << "Enter values (separated by spaces, end with 'done'): ";
            string value, allValues;

            while (true) {
                cin >> value;
                if (value == "done") break;
                allValues += value + ",";
            }

            // Remove the trailing comma if it exists
            if (!allValues.empty() && allValues.back() == ',') {
                allValues.pop_back();
            }

            repo.addRecord(allValues);
        }

        //this command displays all the available cimmands and their funcionalities
        else if (strcmp(command, "help") == 0) {
            cout << "Available commands:" << endl;
            cout << "  init - Initialize repository with CSV file" << endl;
            cout << "  branch - Create new branch" << endl;
            cout << "  checkout - Switch to branch" << endl;
            cout << "  edit - Edit file in current branch" << endl;
            cout << "  commit - Commit changes" << endl;
            cout << "  branches - List all branches" << endl;
            cout << "  delete-branch - Delete a branch" << endl;
            cout << "  merge - Merge two branches" << endl;
            cout << "  add - Add new row to CSV" << endl;
            cout << "  delete - Delete row from CSV" << endl;
            cout << "  help - Show this help message" << endl;
        }
        else if (strcmp(command, "delete") == 0) {
            string key;
            cout << "Enter key to delete: ";
            cin >> key;
            repo.deleteRecord(key);
        }

        else if (strcmp(command, "edit") == 0) {
            repo.editFile(); // Call the new editFile method directly
        }
        else if (strcmp(command, "save") == 0) {
            string savePath;
            cout << "Enter save directory path: ";
            cin >> savePath;
            repo.saveRepository(savePath);
        }
        else if (strcmp(command, "load") == 0) {
            string loadPath;
            cout << "Enter load directory path: ";
            cin >> loadPath;
            repo.loadRepository(loadPath);
        }
        else if (strcmp(command, "select") == 0) {
            std::string column;
            int start, end;
            std::cout << "Enter column name: ";
            std::cin >> column;
            std::cout << "Enter range start: ";
            std::cin >> start;
            std::cout << "Enter range end: ";
            std::cin >> end;

            std::string fileName = repo.getCurrentBranch() + "/dataset2.csv";  // Use your actual file path
            selectRecordsWithinRange(column, start, end, fileName);
        }

        else if (strcmp(command, "update") == 0) {
            std::string targetColumn, targetValue, updateColumn, newValue;

            // Taking user input for the update command
            std::cout << "Enter target column name (for WHERE condition): ";
            std::cin >> targetColumn;

            std::cout << "Enter target value (for WHERE condition): ";
            std::cin >> targetValue;

            std::cout << "Enter column name to update (SET condition): ";
            std::cin >> updateColumn;

            std::cout << "Enter new value for the update: ";
            std::cin >> newValue;

            std::string fileName = repo.getCurrentBranch() + "/dataset2.csv"; // Use your actual file path
            updateRecords(targetColumn, targetValue, updateColumn, newValue, fileName);
        }

        else if (strcmp(command, "delete") == 0) {
            std::string column, value;
            bool limitOne;
            std::cout << "Enter column name: ";
            std::cin >> column;
            std::cout << "Enter value to delete: ";
            std::cin >> value;
            std::cout << "Limit deletion to first match? (1 for yes, 0 for no): ";
            std::cin >> limitOne;
            //   deleteRecords("C:\\path\\to\\your\\file.csv", column, value, limitOne);
        }
        else {
            cout << "Invalid command! Type 'help' for available commands." << endl;
            repo.logEvent("> Invalid command: " + string(command));
        }
    }

}


//------------------ m a i n   f u n c t i o n ----------------------------------------


int main() {
    Repository repo;

    // log starting
    repo.logEvent("> Program started.", true);

    //  handling commands
    handleCommand(repo);

    return 0;
}
