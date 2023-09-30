#ifndef _HASH_H
#define _HASH_H
// Avoid pulling in any other headers.
typedef unsigned int uint32_t;

// murmurhash2 from
// https://github.com/aappleby/smhasher/blob/92cf3702fcfaadc84eb7bef59825a23e0cd84f56/src/MurmurHash2.cpp
static __always_inline uint32_t murmur_hash2(const u32 *data, int len, uint32_t seed) {
  /* 'm' and 'r' are mixing constants generated offline.
     They're not really 'magic', they just happen to work well.  */

  const uint32_t m = 0x5bd1e995;
  const int r = 24;

  /* Initialize the hash to a 'random' value */

  uint32_t h = seed ^ len;

  /* Mix 4 bytes at a time into the hash */

  // MAX_STACK_DEPTH * 2 = 256 (because we hash 32 bits at a time).
  for (int i = 0; i < 256; i++) {
    if (len < 4) {
      break;
    }
    uint32_t k = *data;
    k *= m;
    k ^= k >> r;
    k *= m;

    h *= m;
    h ^= k;

    data++;
    len -= 4;
  }

  /* Do a few final mixes of the hash to ensure the last few
  // bytes are well-incorporated.  */

  h ^= h >> 13;
  h *= m;
  h ^= h >> 15;

  return h;
}

#endif /* _LINUX_JHASH_H */