#include <Arduino.h>
#include <Crypto.h>
#include <AES.h>
#include <CBC.h>
#include <ChaCha.h>
#include <Ascon128.h>

#define TEST_ROUNDS 200

HardwareSerial mySerial(2);

CBC<AES128> cbc;
ChaCha chacha;
Ascon128 ascon;

byte key[16] = {0};
byte nonce[16] = {0};
byte iv[16] = {0};

byte original[64];
byte ciphertext[64];
byte decrypted[64];
byte tag[16];

// ===== GLOBAL =====
int total = 0;

// ===== AES =====
int aes_correct = 0;
int aes_valid = 0;
int aes_tampered = 0;

long aes_byte_error = 0;
long aes_bit_error = 0;

// ===== ChaCha =====
int cha_correct = 0;
int cha_valid = 0;
int cha_tampered = 0;

long cha_byte_error = 0;
long cha_bit_error = 0;

// ===== Ascon =====
int ascon_detected = 0;
int ascon_correct = 0;
int ascon_valid = 0;
int ascon_tampered = 0;

long ascon_byte_error = 0;
long ascon_bit_error = 0;

// ===== WAIT =====
bool waitBytes(int n) {

  unsigned long t0 = millis();

  while (mySerial.available() < n) {

    if (millis() - t0 > 1000) {
      return false;
    }
  }

  return true;
}

// ===== BYTE ERROR =====
int countByteErrors(byte *a, byte *b, int len) {

  int err = 0;

  for (int i = 0; i < len; i++) {

    if (a[i] != b[i]) {
      err++;
    }
  }

  return err;
}

// ===== BIT ERROR =====
int countBitErrors(byte *a, byte *b, int len) {

  int err = 0;

  for (int i = 0; i < len; i++) {

    byte x = a[i] ^ b[i];

    for (int b = 0; b < 8; b++) {

      if (x & (1 << b)) {
        err++;
      }
    }
  }

  return err;
}

// ===== SETUP =====
void setup() {

  Serial.begin(115200);

  mySerial.begin(115200, SERIAL_8N1, 16, 17);

  cbc.setKey(key, sizeof(key));
}

// ===== LOOP =====
void loop() {

  if (total >= TEST_ROUNDS * 3) {

    Serial.println("\n===== FINAL SUMMARY =====");

    // ===== AES =====
    Serial.println("\n--- AES-128-CBC ---");

    Serial.print("Accepted: ");
    Serial.println(aes_valid);

    Serial.print("Correct: ");
    Serial.println(aes_correct);

    Serial.print("Integrity: ");

    Serial.println(
      aes_valid ?
      (float)aes_correct / aes_valid : 0
    );

    Serial.print("Availability: ");

    Serial.println(
      (float)aes_valid / TEST_ROUNDS
    );

    Serial.print("Average Byte Error: ");

    Serial.println(
      aes_tampered ?
      (float)aes_byte_error / aes_tampered : 0
    );

    Serial.print("Average Bit Error: ");

    Serial.println(
      aes_tampered ?
      (float)aes_bit_error / aes_tampered : 0
    );

    // ===== ChaCha20 =====
    Serial.println("\n--- ChaCha20 ---");

    Serial.print("Accepted: ");
    Serial.println(cha_valid);

    Serial.print("Correct: ");
    Serial.println(cha_correct);

    Serial.print("Integrity: ");

    Serial.println(
      cha_valid ?
      (float)cha_correct / cha_valid : 0
    );

    Serial.print("Availability: ");

    Serial.println(
      (float)cha_valid / TEST_ROUNDS
    );

    Serial.print("Average Byte Error: ");

    Serial.println(
      cha_tampered ?
      (float)cha_byte_error / cha_tampered : 0
    );

    Serial.print("Average Bit Error: ");

    Serial.println(
      cha_tampered ?
      (float)cha_bit_error / cha_tampered : 0
    );

    // ===== Ascon =====
    Serial.println("\n--- Ascon-128 ---");

    Serial.print("Detected: ");
    Serial.println(ascon_detected);

    Serial.print("Accepted: ");
    Serial.println(ascon_valid);

    Serial.print("Correct: ");
    Serial.println(ascon_correct);

    Serial.print("Detection Rate: ");

    Serial.println(
      ascon_tampered ?
      (float)ascon_detected / ascon_tampered : 0
    );

    Serial.print("Integrity: ");

    Serial.println(
      ascon_valid ?
      (float)ascon_correct / ascon_valid : 0
    );

    Serial.print("Availability: ");

    Serial.println(
      (float)ascon_valid / TEST_ROUNDS
    );

    Serial.print("Average Byte Error: ");

    Serial.println(
      ascon_valid ?
      (float)ascon_byte_error / ascon_valid : 0
    );

    Serial.print("Average Bit Error: ");

    Serial.println(
      ascon_valid ?
      (float)ascon_bit_error / ascon_valid : 0
    );

    while (1);
  }

  if (!waitBytes(3)) return;

  byte alg = mySerial.read();

  byte len = mySerial.read();

  bool tampered = mySerial.read();

  if (!waitBytes(len * 2)) return;

  mySerial.readBytes(original, len);

  mySerial.readBytes(ciphertext, len);

  if (alg == 2) {

    if (!waitBytes(16)) return;

    mySerial.readBytes(tag, 16);
  }

  // ===== AES =====
  if (alg == 0) {

    aes_valid++;

    if (tampered) {
      aes_tampered++;
    }

    cbc.setIV(iv, sizeof(iv));

    cbc.decrypt(decrypted, ciphertext, len);

    int byteErr =
      countByteErrors(original, decrypted, len);

    int bitErr =
      countBitErrors(original, decrypted, len);

    aes_byte_error += byteErr;

    aes_bit_error += bitErr;

    if (byteErr == 0) {

      aes_correct++;
    }
  }

  // ===== ChaCha20 =====
  else if (alg == 1) {

    cha_valid++;

    if (tampered) {
      cha_tampered++;
    }

    chacha.clear();

    chacha.setKey(key, 16);

    chacha.setIV(nonce, 12);

    chacha.decrypt(decrypted, ciphertext, len);

    int byteErr =
      countByteErrors(original, decrypted, len);

    int bitErr =
      countBitErrors(original, decrypted, len);

    cha_byte_error += byteErr;

    cha_bit_error += bitErr;

    if (byteErr == 0) {

      cha_correct++;
    }
  }

  // ===== Ascon =====
  else {

    if (tampered) {
      ascon_tampered++;
    }

    ascon.clear();

    ascon.setKey(key, 16);

    ascon.setIV(nonce, 16);

    ascon.decrypt(decrypted, ciphertext, len);

    bool tagOK =
      ascon.checkTag(tag, 16);

    if (!tagOK) {

      ascon_detected++;
    }
    else {

      ascon_valid++;

      int byteErr =
        countByteErrors(original, decrypted, len);

      int bitErr =
        countBitErrors(original, decrypted, len);

      ascon_byte_error += byteErr;

      ascon_bit_error += bitErr;

      if (byteErr == 0) {

        ascon_correct++;
      }
    }
  }

  total++;
}