#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <zmq.h>

#define MESSAGE (const unsigned char *) "password"
#define MESSAGE_LEN 8
#define CIPHERTEXT_LEN (crypto_box_MACBYTES + MESSAGE_LEN)

int main(void)
{
    if (sodium_init() < 0) {
        printf("panic! the library couldn't be initialized, it is not safe to use\n");
        return 1;
    }
    printf("Security wallet needs to share pwd with Agent 1: '%s'\n", MESSAGE);
    
    //On first start, security wallet generates a curve bi-key
    //crypto_box_PUBLICKEYBYTES means crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES
    //crypto_box_SECRETKEYBYTES means crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTE
    unsigned char securitywallet_publickey[crypto_box_PUBLICKEYBYTES];
    unsigned char securitywallet_secretkey[crypto_box_SECRETKEYBYTES];

    //crypto_box_keypair means crypto_box_curve25519xsalsa20poly1305_keypair
    crypto_box_keypair(securitywallet_publickey, securitywallet_secretkey);

    //On first start, Agent 1 generates a curve bi-key
    unsigned char trustedclient1_publickey[crypto_box_PUBLICKEYBYTES];
    unsigned char trustedclient1_secretkey[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(trustedclient1_publickey, trustedclient1_secretkey);

    //The Security wallet knows the pub key of Agent 1 and uses it in combinaison
    //with its own private key to cypher the password 
    //the cypher text also include poly1305 MAC for authentification purpose
    unsigned char nonce[crypto_box_NONCEBYTES];
    unsigned char ciphertext[CIPHERTEXT_LEN];
    randombytes_buf(nonce, sizeof nonce);
    if (crypto_box_easy(ciphertext, MESSAGE, MESSAGE_LEN, nonce,
                        trustedclient1_publickey, securitywallet_secretkey) != 0) {
        printf("error\n");
        return 1;
    }

    char z85_ciphertext [CIPHERTEXT_LEN];
    zmq_z85_encode (z85_ciphertext, ciphertext, CIPHERTEXT_LEN);
    printf("Security wallet cyphers the pwd for Agent 1 (Z85 encoding)  : '%s'\n",z85_ciphertext);

    unsigned char decrypted[MESSAGE_LEN+1];
    
    //We check that a second agent can't decrypt it
    unsigned char trustedclient2_publickey[crypto_box_PUBLICKEYBYTES];
    unsigned char trustedclient2_secretkey[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(trustedclient2_publickey, trustedclient2_secretkey);
    if (crypto_box_open_easy(decrypted, ciphertext, CIPHERTEXT_LEN, nonce,
                            securitywallet_publickey, trustedclient2_secretkey) != 0) {
        printf("Agent 2 failed to decrypt it!\n");
    }
    //The Agent 1 knows the pub key of Security Wallet and uses it in combinaison
    //with its own private key to decrypt the password 
    if (crypto_box_open_easy(decrypted, ciphertext, CIPHERTEXT_LEN, nonce,
                            securitywallet_publickey, trustedclient1_secretkey) != 0) {
        printf("message for trustedclient pretending to be from SecurityWallet has been forged!\n");
        return 1;
    }
    decrypted[MESSAGE_LEN]=0;
    printf("Agent 1 got clear pwd : '%s'\n", decrypted);
}