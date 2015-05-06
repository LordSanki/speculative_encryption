#include <aes.h>
#include <assert.h>

void Ident_encrypt (const unsigned char *, unsigned char *, const AES_KEY *);
void Ident_decrypt (const unsigned char *, unsigned char *, const AES_KEY *);
void cbc2_encrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key,
                           unsigned char ivec[16], block128_f block);
void cbc2_decrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key,
                           unsigned char ivec[16], block128_f block);
void cbc8_encrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key,
                           unsigned char ivec[2], block128_f block)
{
    size_t n;
    const unsigned char *iv = ivec;

    assert(in && out && key && ivec);


    while (len) {
        for (n = 0; n < 2 && n < len; ++n)
            out[n] = in[n] ^ iv[n];
        for (; n < 2; ++n)
            out[n] = iv[n];
        (*block) (out, out, key);
        iv = out;
        if (len <= 2)
            break;
        len -= 2;
        in += 2;
        out += 2;
    }
    memcpy(ivec, iv, 2);
}

void cbc8_decrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key,
                           unsigned char ivec[2], block128_f block)
{
    size_t n;
    union {
        size_t t[2 / sizeof(size_t)];
        unsigned char c[2];
    } tmp;

    assert(in && out && key && ivec);

    while (len) {
        unsigned char c;
        (*block) (in, tmp.c, key);
        for (n = 0; n < 2 && n < len; ++n) {
            c = in[n];
            out[n] = tmp.c[n] ^ ivec[n];
            ivec[n] = c;
        }
        if (len <= 2) {
            for (; n < 2; ++n)
                ivec[n] = in[n];
            break;
        }
        len -= 2;
        in += 2;
        out += 2;
    }
}
void cbc2_encrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key,
                           unsigned char ivec[16], block128_f block)
{
    size_t n;
    const unsigned char *iv = ivec;

    assert(in && out && key && ivec);

    while (len) {
        for (n = 0; n < 16 && n < len; ++n)
            out[n] = in[n] ^ iv[n];
        for (; n < 16; ++n)
            out[n] = iv[n];
        (*block) (out, out, key);
        iv = out;
        if (len <= 16)
            break;
        len -= 16;
        in += 16;
        out += 16;
    }
    memcpy(ivec, iv, 16);
}

void cbc2_decrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key,
                           unsigned char ivec[16], block128_f block)
{
    size_t n;
    union {
        size_t t[16 / sizeof(size_t)];
        unsigned char c[16];
    } tmp;

    assert(in && out && key && ivec);

    while (len) {
        unsigned char c;
        (*block) (in, tmp.c, key);
        for (n = 0; n < 16 && n < len; ++n) {
            c = in[n];
            out[n] = tmp.c[n] ^ ivec[n];
            ivec[n] = c;
        }
        if (len <= 16) {
            for (; n < 16; ++n)
                ivec[n] = in[n];
            break;
        }
        len -= 16;
        in += 16;
        out += 16;
    }
}

void Ident_encrypt (const unsigned char *in, unsigned char *out, const AES_KEY *key)
{
  int i;
  for(i=0; i<16; i++)
    out[i] = in[i];
}

void Ident_decrypt (const unsigned char *in, unsigned char *out, const AES_KEY *key)
{
  int i;
  for(i=0; i<16; i++)
    out[i] = in[i];
}

void Ident8_encrypt (const unsigned char *in, unsigned char *out, const AES_KEY *key)
{
  int i=0;
    out[i] = in[i];
}

void Ident8_decrypt (const unsigned char *in, unsigned char *out, const AES_KEY *key)
{
  int i=0;
    out[i] = in[i];
}

void Ident_cbc_encrypt(const unsigned char *in, unsigned char *out,
                     size_t len, const AES_KEY *key,
                     unsigned char *ivec, const int enc)
{

    if (enc)
        cbc8_encrypt(in, out, len, key, ivec,
                              (block128_f) Ident8_encrypt);
    else
        cbc8_decrypt(in, out, len, key, ivec,
                              (block128_f) Ident8_decrypt);
}



