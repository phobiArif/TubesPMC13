#include <Arduino.h>
#include "isap.h" // Pastikan Anda memiliki library yang sesuai untuk isap
#include "api.h"
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

// OLED display configuration
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

typedef uint8_t u8;
typedef uint64_t u64;
typedef uint32_t u32;
typedef int64_t i64;

const u8 ISAP_IV1[] = {0x01, ISAP_K, ISAP_rH, ISAP_rB, ISAP_sH, ISAP_sB, ISAP_sE, ISAP_sK};
const u8 ISAP_IV2[] = {0x02, ISAP_K, ISAP_rH, ISAP_rB, ISAP_sH, ISAP_sB, ISAP_sE, ISAP_sK};
const u8 ISAP_IV3[] = {0x03, ISAP_K, ISAP_rH, ISAP_rB, ISAP_sH, ISAP_sB, ISAP_sE, ISAP_sK};


// Global variables
u8 key[CRYPTO_KEYBYTES] = {0x4B, 0x65, 0x6C, 0x6F, 0x6D, 0x70, 0x6F, 0x6B, 0x31, 0x33}; // Kelompok13 dalam bentuk heksadesimal
u8 nonce[CRYPTO_NPUBBYTES] = {0x6B, 0x6C, 0x31, 0x33}; // kl13 dalam bentuk heksadesimal
u8 ad[100] = "ISAP64"; // data tambahan
u8 plaintext[100]; // teks yang akan dienkripsi
u8 ciphertext[100]; // teks hasil enkripsi
u8 decrypted[100]; // teks hasil dekripsi
u8 tag[CRYPTO_ABYTES]; // tag MAC
u8 hasil[100]; // teks hasil enkripsi
u64 ad_len, plaintext_len, ciphertext_len;

static const int R[5][2] = {
    {19, 28}, {39, 61}, {1, 6}, {10, 17}, {7, 41}
};

#define RATE (64 / 8)
#define PA_ROUNDS 12
#define PB_ROUNDS 6

#define ROTR(x,n) (((x)>>(n))|((x)<<(64-(n))))
#define EXT_BYTE(x,n) ((u8)((u64)(x)>>(8*(7-(n)))))
#define INS_BYTE(x,n) ((u64)(x)<<(8*(7-(n))))

#define U64BIG(x) \
    ((ROTR(x, 8) & (0xFF000000FF000000ULL)) | \
     (ROTR(x,24) & (0x00FF000000FF0000ULL)) | \
     (ROTR(x,40) & (0x0000FF000000FF00ULL)) | \
     (ROTR(x,56) & (0x000000FF000000FFULL)))

#define ROUND(C) ({\
    x2 ^= C;\
    x0 ^= x4;\
    x4 ^= x3;\
    x2 ^= x1;\
    t0 = x0;\
    t4 = x4;\
    t3 = x3;\
    t1 = x1;\
    t2 = x2;\
    x0 = t0 ^ ((~t1) & t2);\
    x2 = t2 ^ ((~t3) & t4);\
    x4 = t4 ^ ((~t0) & t1);\
    x1 = t1 ^ ((~t2) & t3);\
    x3 = t3 ^ ((~t4) & t0);\
    x1 ^= x0;\
    t1  = x1;\
    x1 = ROTR(x1, R[1][0]);\
    x3 ^= x2;\
    t2  = x2;\
    x2 = ROTR(x2, R[2][0]);\
    t4  = x4;\
    t2 ^= x2;\
    x2 = ROTR(x2, R[2][1] - R[2][0]);\
    t3  = x3;\
    t1 ^= x1;\
    x3 = ROTR(x3, R[3][0]);\
    x0 ^= x4;\
    x4 = ROTR(x4, R[4][0]);\
    t3 ^= x3;\
    x2 ^= t2;\
    x1 = ROTR(x1, R[1][1] - R[1][0]);\
    t0  = x0;\
    x2 = ~x2;\
    x3 = ROTR(x3, R[3][1] - R[3][0]);\
    t4 ^= x4;\
    x4 = ROTR(x4, R[4][1] - R[4][0]);\
    x3 ^= t3;\
    x1 ^= t1;\
    x0 = ROTR(x0, R[0][0]);\
    x4 ^= t4;\
    t0 ^= x0;\
    x0 = ROTR(x0, R[0][1] - R[0][0]);\
    x0 ^= t0;\
})

#define P12 ({\
    ROUND(0xf0);\
    ROUND(0xe1);\
    ROUND(0xd2);\
    ROUND(0xc3);\
    ROUND(0xb4);\
    ROUND(0xa5);\
    ROUND(0x96);\
    ROUND(0x87);\
    ROUND(0x78);\
    ROUND(0x69);\
    ROUND(0x5a);\
    ROUND(0x4b);\
})

#define P6 ({\
    ROUND(0x96);\
    ROUND(0x87);\
    ROUND(0x78);\
    ROUND(0x69);\
    ROUND(0x5a);\
    ROUND(0x4b);\
})


#define P1 ({\
    ROUND(0x4b);\
})

#define ABSORB_MAC(src, len) ({ \
    u32 rem_bytes = len; \
    u64 *src64 = (u64 *)src; \
    u32 idx64 = 0; \
    while(1){ \
        if(rem_bytes>ISAP_rH_SZ){ \
            x0 ^= U64BIG(src64[idx64]); \
            idx64++; \
            P12; \
            rem_bytes -= ISAP_rH_SZ; \
        } else if(rem_bytes==ISAP_rH_SZ){ \
            x0 ^= U64BIG(src64[idx64]); \
            P12; \
            x0 ^= 0x8000000000000000ULL; \
            P12; \
            break; \
        } else { \
            u64 lane64; \
            u8 *lane8 = (u8 *)&lane64; \
            u32 idx8 = idx64*8; \
            for (u32 i = 0; i < 8; i++) { \
                if(i<(rem_bytes)){ \
                    lane8[i] = src[idx8]; \
                    idx8++; \
                } else if(i==rem_bytes){ \
                    lane8[i] = 0x80; \
                } else { \
                    lane8[i] = 0x00; \
                } \
            } \
            x0 ^= U64BIG(lane64); \
            P12; \
            break; \
        } \
    } \
})



void isap_rk(
    const uint8_t *k,
    const uint8_t *iv,
    const uint8_t *y,
    const uint64_t ylen,
    uint8_t *out,
    const uint64_t outlen
){
    const uint64_t *k64 = (uint64_t *)k;
    const uint64_t *iv64 = (uint64_t *)iv;
    uint64_t *out64 = (uint64_t *)out;
    uint64_t x0, x1, x2, x3, x4;
    uint64_t t0, t1, t2, t3, t4;

    // Init state
    t0 = t1 = t2 = t3 = t4 = 0;
    x0 = U64BIG(k64[0]);
    x1 = U64BIG(k64[1]);
    x2 = U64BIG(iv64[0]);
    x3 = x4 = 0;
    P12;

    // Absorb Y
    for (size_t i = 0; i < ylen*8-1; i++){
        size_t cur_byte_pos = i/8;
        size_t cur_bit_pos = 7-(i%8);
        uint8_t cur_bit = ((y[cur_byte_pos] >> (cur_bit_pos)) & 0x01) << 7;
        x0 ^= ((uint64_t)cur_bit) << 56;
        P12;
    }
    uint8_t cur_bit = ((y[ylen-1]) & 0x01) << 7;
    x0 ^= ((uint64_t)cur_bit) << 56;
    P12;

    // Extract K*
    out64[0] = U64BIG(x0);
    out64[1] = U64BIG(x1);
    if(outlen == 24){
        out64[2] = U64BIG(x2);
    }
}

void isap_mac(
    const uint8_t *k,
    const uint8_t *npub,
    const uint8_t *ad, const uint64_t adlen,
    const uint8_t *c, const uint64_t clen,
    uint8_t *tag
){
    uint8_t state[ISAP_STATE_SZ];
    const uint64_t *npub64 = (uint64_t *)npub;
    uint64_t *state64 = (uint64_t *)state;
    uint64_t x0, x1, x2, x3, x4;
    uint64_t t0, t1, t2, t3, t4;
    t0 = t1 = t2 = t3 = t4 = 0;

    // Init state
    x0 = U64BIG(npub64[0]);
    x1 = U64BIG(npub64[1]);
    x2 = U64BIG(((uint64_t *)ISAP_IV1)[0]);
    x3 = x4 = 0;
    P12;

    // Absorb AD
    ABSORB_MAC(ad,adlen);

    // Domain separation
    x4 ^= 0x0000000000000001ULL;

    // Absorb C
    ABSORB_MAC(c,clen);

    // Derive K*
    state64[0] = U64BIG(x0);
    state64[1] = U64BIG(x1);
    state64[2] = U64BIG(x2);
    state64[3] = U64BIG(x3);
    state64[4] = U64BIG(x4);
    isap_rk(k,ISAP_IV2,(uint8_t *)state64,CRYPTO_KEYBYTES,(uint8_t *)state64,CRYPTO_KEYBYTES);
    x0 = U64BIG(state64[0]);
    x1 = U64BIG(state64[1]);
    x2 = U64BIG(state64[2]);
    x3 = U64BIG(state64[3]);
    x4 = U64BIG(state64[4]);

    // Squeeze tag
    P12;
    unsigned long long *tag64 = (uint64_t *)tag;
    tag64[0] = U64BIG(x0);
    tag64[1] = U64BIG(x1);
}

void isap_enc(
    const uint8_t *k,
    const uint8_t *npub,
    const uint8_t *m,
    const uint64_t mlen,
    uint8_t *c
){
    uint8_t state[ISAP_STATE_SZ];

    // Init state
    uint64_t *state64 = (uint64_t *)state;
    uint64_t *npub64 = (uint64_t *)npub;
    isap_rk(k,ISAP_IV3,npub,CRYPTO_NPUBBYTES,state,ISAP_STATE_SZ-CRYPTO_NPUBBYTES);
    uint64_t x0, x1, x2, x3, x4;
    uint64_t t0, t1, t2, t3, t4;
    t0 = t1 = t2 = t3 = t4 = 0;
    x0 = U64BIG(state64[0]);
    x1 = U64BIG(state64[1]);
    x2 = U64BIG(state64[2]);
    x3 = U64BIG(npub64[0]);
    x4 = U64BIG(npub64[1]);
    P12;

    // Squeeze key stream
    uint64_t rem_bytes = mlen;
    uint64_t *m64 = (uint64_t *)m;
    uint64_t *c64 = (uint64_t *)c;
    uint32_t idx64 = 0;
    while(1){
        if(rem_bytes>ISAP_rH_SZ){
            // Squeeze full lane
            c64[idx64] = U64BIG(x0) ^ m64[idx64];
            idx64++;
            P12;
            rem_bytes -= ISAP_rH_SZ;
        } else if(rem_bytes==ISAP_rH_SZ){
            // Squeeze full lane and stop
            c64[idx64] = U64BIG(x0) ^ m64[idx64];
            break;
        } else {
            // Squeeze partial lane and stop
            uint64_t lane64 = U64BIG(x0);
            uint8_t *lane8 = (uint8_t *)&lane64;
            uint32_t idx8 = idx64*8;
            for (uint32_t i = 0; i < rem_bytes; i++) {
                c[idx8] = lane8[i] ^ m[idx8];
                idx8++;
            }
            break;
        }
    }
}

int isap_dec(const uint8_t *key, const uint8_t *nonce,
             const uint8_t *ciphertext, uint64_t ciphertext_len,
             const uint8_t *mac, const uint8_t *ad, uint64_t ad_len,
             uint8_t *plaintext) {
  uint8_t computed_mac[CRYPTO_ABYTES];
  uint64_t plaintext_len;
  int i, ret;

  // INI BUAT NGITUNG MACCCCCCC
  isap_mac(key, nonce, ad, ad_len, ciphertext, ciphertext_len, computed_mac);

  // BUAT PERIPikasi
  ret = 0;
  for (i = 0; i < CRYPTO_ABYTES; i++) {
    ret |= computed_mac[i] ^ mac[i];
  }
  if (ret != 0) {
    return -1; // MAC tidak cocok
  }

  // Lakukan dekripsi plaintext menggunakan kunci dan nonce yang sama dengan ketika dilakukan enkripsi
  isap_enc(key, nonce, ciphertext, ciphertext_len, plaintext);
  plaintext_len = ciphertext_len;

  return plaintext_len;
}


void setup() {
  Serial.begin(115200);
  while (!Serial);
  Wire.begin(5, 4); // Initialize I2C communication with SDA=5 and SCL=4 pins
  display.begin(SSD1306_SWITCHCAPVCC, 0x3C); // Initialize the OLED display
  display.clearDisplay(); // Clear the display buffer
  display.setTextSize(1); // Set text size
  display.setTextColor(SSD1306_WHITE); // Set text color

  ad_len = strlen(reinterpret_cast<const char*>(ad));

  // minta user untuk memasukkan plaintext
  display.println(F("Masukkan plaintext: "));
  display.display();
  
  while (Serial.available() == 0) {
    delay(100); // Add a delay to give time for user input
  }

  plaintext_len = Serial.readBytesUntil('\n', plaintext, 100);
  plaintext[plaintext_len] = '\0';

  // Print the input plaintext
  display.println(reinterpret_cast<const char*>(plaintext));
  display.display();

  // enkripsi plaintext menggunakan kunci dan nonce
  isap_enc(key, nonce, plaintext, plaintext_len, ciphertext);
  ciphertext_len = strlen(reinterpret_cast<const char*>(ciphertext));

  // buat tag MAC dari kunci, nonce, dan data tambahan
  isap_mac(key, nonce, ad, ad_len, ciphertext, ciphertext_len, tag);

  // tampilkan ciphertext dan tag MAC
  display.print(F("Ciphertext: "));
  for (int i = 0; i < ciphertext_len; i++) {
    display.print(ciphertext[i], HEX);
  }
  display.println();
  display.print(F("Tag MAC: "));
  for (int i = 0; i < CRYPTO_ABYTES; i++) {
    display.print(tag[i], HEX);
  }
  display.println();
  display.display();

  // TODO: Implement isap_dec function
  if (isap_dec(key, nonce, ciphertext, ciphertext_len, tag, ad, ad_len, decrypted) == 0) {
    display.println(F("Pesan tidak dapat didekripsi."));
  }
  else {
    display.print(F("Plaintext: "));
    for (int i = 0; i < plaintext_len; i++) {
      display.write(decrypted[i]);
    }
    display.println();
    display.display();
  }
}

void loop() {
  // Nothing to do here
}