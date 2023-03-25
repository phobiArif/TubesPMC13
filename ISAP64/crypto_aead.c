#include <stdio.h>
#include <string.h>
#include "api.h"
#include "isap.h"
#define MESSAGE_MAXLEN 1024
#define ADDITIONAL_DATA_MAXLEN 1024
#define KEY_LENGTH 32
#define NONCE_LENGTH 16


int crypto_aead_encrypt(
	unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k
){
    (void)nsec;  
    
	// Ciphertext length is mlen + tag length
	*clen = mlen+ISAP_TAG_SZ;

	// Encrypt plaintext
	if (mlen > 0) {
		isap_enc(k,npub,m,mlen,c);
	}

	// Generate tag
	unsigned char *tag = c+mlen;
	isap_mac(k,npub,ad,adlen,c,mlen,tag);
	return 0;
}

int crypto_aead_decrypt(
	unsigned char *m, unsigned long long *mlen,
	unsigned char *nsec,
	const unsigned char *c, unsigned long long clen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k
){
    (void)nsec;

	// Plaintext length is clen - tag length
	*mlen = clen-ISAP_TAG_SZ;

	// Generate tag
	unsigned char tag[ISAP_TAG_SZ];
	isap_mac(k,npub,ad,adlen,c,*mlen,tag);

	// Compare tag
	unsigned long eq_cnt = 0;
	for(unsigned int i = 0; i < ISAP_TAG_SZ; i++) {
		eq_cnt += (tag[i] == c[(*mlen)+i]);
	}

	// Perform decryption if tag is correct
	if(eq_cnt == (unsigned long)ISAP_TAG_SZ){
		if (*mlen > 0) {
			isap_enc(k,npub,c,*mlen,m);
		}
		return 0;
	} else {
		return -1;
	}
}


int main() {
    // Set key, nonce, plaintext, and additional data
    const unsigned char key[CRYPTO_KEYBYTES] = "kelompok13";
    const unsigned char nonce[CRYPTO_NPUBBYTES] = "133333";
    const unsigned char plaintext[10] = "hello";
    const unsigned long long plaintext_len = 5;
    const unsigned char ad[5] = "world";
    const unsigned long long ad_len = 5;

    // Encrypt plaintext
    unsigned char ciphertext[plaintext_len + CRYPTO_ABYTES];
    unsigned long long ciphertext_len;
    int ret = crypto_aead_encrypt(ciphertext, &ciphertext_len, plaintext, plaintext_len, ad, ad_len, NULL, nonce, key);
    if (ret != 0) {
        printf("Encryption failed\n");
        return 1;
    }

    // Print ciphertext and tag
    printf("Ciphertext: ");
    for (int i = 0; i < ciphertext_len - CRYPTO_ABYTES; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\nTag: ");
    for (int i = ciphertext_len - CRYPTO_ABYTES; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Decrypt ciphertext
    unsigned char decrypted[plaintext_len];
    unsigned long long decrypted_len;
    ret = crypto_aead_decrypt(decrypted, &decrypted_len, NULL, ciphertext, ciphertext_len, ad, ad_len, nonce, key);
    if (ret != 0) {
        printf("Decryption failed\n");
        return 1;
    }

    // Print decrypted plaintext
    printf("Decrypted: %s\n", decrypted);

    return 0;
}