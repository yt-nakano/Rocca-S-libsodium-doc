# Authenticated Encryption with Additional Data using ROCCA-S

Rocca-S has been designed as an encryption algorithm for a high speed communication such as future internet and beyond 5G mobile communications.

It can provide 256-bit and 128-bit security against key recovery attacks in classical and quantum adversaries respectively.

## Example (combined mode)

``` c
#include <sodium.h>

#define MESSAGE (const unsigned char *) "test"
#define MESSAGE_LEN 4
#define ADDITIONAL_DATA (const unsigned char *) "123456"
#define ADDITIONAL_DATA_LEN 6

unsigned char nonce[crypto_aead_roccas_NPUBBYTES];
unsigned char key[crypto_aead_roccas_KEYBYTES];
unsigned char ciphertext[MESSAGE_LEN + crypto_aead_roccas_ABYTES];
unsigned long long ciphertext_len;

sodium_init();

crypto_aead_roccas_keygen(key);
randombytes_buf(nonce, sizeof nonce);

crypto_aead_roccas_encrypt(ciphertext, &ciphertext_len,
                              MESSAGE, MESSAGE_LEN,
                              ADDITIONAL_DATA, ADDITIONAL_DATA_LEN,
                              NULL, nonce, key);

unsigned char decrypted[MESSAGE_LEN];
unsigned long long decrypted_len;
if (ciphertext_len < crypto_aead_roccas_ABYTES ||
    crypto_aead_roccas_decrypt(decrypted, &decrypted_len,
                                  NULL,
                                  ciphertext, ciphertext_len,
                                  ADDITIONAL_DATA,
                                  ADDITIONAL_DATA_LEN,
                                  nonce, key) != 0) {
    /* message forged! */
}
```

## Purpose

This operation:

  - Encrypts a message with a key and a nonce to keep it confidential
  - Computes an authentication tag. This tag is used to make sure that the message, as well as optional, non-confidential (non-encrypted) data, haven’t been tampered with.

A typical use case for additional data is to store protocol-specific metadata about the message, such as its length and encoding.

It can also be used as a MAC, with an empty message.

Decryption will never be performed, even partially, before verification.

Rocca is also much faster than other efficient schemes with 256-bit key length, e.g. AEGIS-256 and AES-256-GCM. 

## Combined mode

In combined mode, the authentication tag is directly appended to the encrypted message. This is usually what you want.

``` c
int crypto_aead_roccas_encrypt(unsigned char *c,
                                  unsigned long long *clen_p,
                                  const unsigned char *m,
                                  unsigned long long mlen,
                                  const unsigned char *ad,
                                  unsigned long long adlen,
                                  const unsigned char *nsec,
                                  const unsigned char *npub,
                                  const unsigned char *k);
```

The function `crypto_aead_roccas_encrypt()` encrypts a message `m` whose length is `mlen` bytes using a secret key `k` (`crypto_aead_roccas_KEYBYTES` bytes) and a public nonce `npub` (`crypto_aead_roccas_NPUBBYTES` bytes).

The encrypted message, as well as a tag authenticating both the confidential message `m` and `adlen` bytes of non-confidential data `ad`, are put into `c`.

`ad` can also be a `NULL` pointer if no additional data are required.

At most `mlen + crypto_aead_roccas_ABYTES` bytes are put into `c`, and the actual number of bytes is stored into `clen` if `clen` is not a `NULL` pointer.

`nsec` is not used by this particular construction and should always be `NULL`.

The function always returns `0`.

The public nonce `npub` should never ever be reused with the same key. The recommended way to generate it is to use `randombytes_buf()` for the first message, and then to increment it for each subsequent message using the same key.

``` c
int crypto_aead_roccas_decrypt(unsigned char *m,
                                  unsigned long long *mlen_p,
                                  unsigned char *nsec,
                                  const unsigned char *c,
                                  unsigned long long clen,
                                  const unsigned char *ad,
                                  unsigned long long adlen,
                                  const unsigned char *npub,
                                  const unsigned char *k);
```

The function `crypto_aead_roccas_decrypt()` verifies that the ciphertext `c` (as produced by `crypto_aead_roccas_encrypt()`), includes a valid tag using a secret key `k`, a public nonce `npub`, and additional data `ad` (`adlen` bytes). `clen` is the ciphertext length in bytes with the authenticator, so it has to be at least `aead_roccas_ABYTES`.

`ad` can be a `NULL` pointer if no additional data are required.

`nsec` is not used by this particular construction and should always be `NULL`.

The function returns `-1` if the verification fails.

If the verification succeeds, the function returns `0`, puts the decrypted message into `m` and stores its actual number of bytes into `mlen` if `mlen` is not a `NULL` pointer.

At most `clen - crypto_aead_roccas_ABYTES` bytes will be put into `m`.

## Detached mode

Some applications may need to store the authentication tag and the encrypted message at different locations.

For this specific use case, “detached” variants of the functions above are available.

``` c
int crypto_aead_roccas_encrypt_detached(unsigned char *c,
                                           unsigned char *mac,
                                           unsigned long long *maclen_p,
                                           const unsigned char *m,
                                           unsigned long long mlen,
                                           const unsigned char *ad,
                                           unsigned long long adlen,
                                           const unsigned char *nsec,
                                           const unsigned char *npub,
                                           const unsigned char *k);
```

`crypto_aead_roccas_encrypt_detached()` encrypts a message `m` whose length is `mlen` bytes using a secret key `k` (`crypto_aead_roccas_KEYBYTES` bytes) and a public nonce `npub` (`crypto_aead_roccas_NPUBBYTES` bytes).

The encrypted message in put into `c`. A tag authenticating both the confidential message `m` and `adlen` bytes of non-confidential data `ad` is put into `mac`.

`ad` can also be a `NULL` pointer if no additional data are required.

`crypto_aead_roccas_ABYTES` bytes are put into `mac`, and the actual number of bytes required for verification is stored into `maclen_p`, unless `maclen_p` is `NULL` pointer.

`nsec` is not used by this particular construction and should always be `NULL`.

The function always returns `0`.

``` c
int crypto_aead_roccas_decrypt_detached(unsigned char *m,
                                           unsigned char *nsec,
                                           const unsigned char *c,
                                           unsigned long long clen,
                                           const unsigned char *mac,
                                           const unsigned char *ad,
                                           unsigned long long adlen,
                                           const unsigned char *npub,
                                           const unsigned char *k);
```

The function `crypto_aead_roccas_decrypt_detached()` verifies that the tag `mac` is valid for the ciphertext `c` using a secret key `k`, a public nonce `npub`, and additional data `ad` (`adlen` bytes).

`clen` is the ciphertext length in bytes.

`ad` can be a `NULL` pointer if no additional data are required.

`nsec` is not used by this particular construction and should always be `NULL`.

The function returns `-1` if the verification fails.

If the verification succeeds, the function returns `0`, and puts the decrypted message into `m`, whose length is equal to the length of the ciphertext.

``` c
void crypto_aead_roccas_keygen(unsigned char k[crypto_aead_roccas_KEYBYTES]);
```

This helper function introduced in libsodium 1.0.12 creates a random key `k`.

It is equivalent to calling `randombytes_buf()` but improves code clarity and can prevent misuse by ensuring that the provided key length is always be correct.

## Constants

  - `crypto_aead_roccas_KEYBYTES`
  - `crypto_aead_roccas_NPUBBYTES`
  - `crypto_aead_roccas_ABYTES`

## Notes

Inadvertent reuse of the same nonce by two invocations of the Rocca-S encryption operation, with the same key, undermines the security of the messages processed with those invocations. 

A loss of confidentiality ensues because an adversary will be able to reconstruct the bitwise exclusive-or of the two plaintext values.