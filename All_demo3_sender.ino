#include <Arduino.h>
#include <DHT.h>
#include <Crypto.h>
#include <AES.h>
#include <CBC.h>
#include <ChaCha.h>
#include <Ascon128.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#define DHTPIN 4
#define DHTTYPE DHT22

#define DATA_SIZE 32
#define ERROR_RATE 0.005
#define TEST_ROUNDS 200

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

DHT dht(DHTPIN, DHTTYPE);
HardwareSerial mySerial(2);

CBC<AES128> cbc;
ChaCha chacha;
Ascon128 ascon;

uint32_t totalPackets = 0;
uint32_t aesErrorCount = 0;
uint32_t chachaErrorCount = 0;
uint32_t asconErrorCount = 0;

byte key[16] = {0};
byte nonce[16] = {0};
byte iv[16] = {0};

byte plaintext[DATA_SIZE];
byte ciphertext[64];
byte tag[16];

int send_count = 0;

// ===== READ DHT =====
bool readDHT() {

  float temp = dht.readTemperature();
  float hum  = dht.readHumidity();

  if (isnan(temp) || isnan(hum)) {

    Serial.println("DHT ERROR");
    return false;
  }

  int t = temp * 100;
  int h = hum * 100;

  memset(plaintext, 0, DATA_SIZE);

  plaintext[0] = (t >> 8);
  plaintext[1] = t;

  plaintext[2] = (h >> 8);
  plaintext[3] = h;

  Serial.print("SEND T=");
  Serial.print(temp);

  Serial.print(" H=");
  Serial.println(hum);

  return true;
}

// ===== ERROR INJECTION =====
bool injectError(byte *data, int len) {

  bool injected = false;

  for (int i = 0; i < len; i++) {

    if (random(1000) < ERROR_RATE * 1000) {

      data[i] ^= (1 << random(0, 8));

      injected = true;
    }
  }

  return injected;
}

// ===== SEND FRAME =====
void sendFrame(byte alg,
               byte *plain,
               byte *cipher,
               int len,
               bool tampered,
               byte *tagPtr = NULL) {

  mySerial.write(alg);

  mySerial.write(len);

  mySerial.write(tampered);

  mySerial.write(plain, len);

  mySerial.write(cipher, len);

  if (alg == 2) {

    mySerial.write(tagPtr, 16);
  }
}

void updateOLED()
{
  display.clearDisplay();

  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);

  // ===== DÒNG 1 =====
  display.setCursor(0,0);
  display.print("Packets: ");
  display.println(totalPackets);

  // ===== DÒNG 2 =====
  display.setCursor(0,16);
  display.print("AES Err: ");
  display.println(aesErrorCount);

  // ===== DÒNG 3 =====
  display.setCursor(0,32);
  display.print("Cha Err: ");
  display.println(chachaErrorCount);

  // ===== DÒNG 4 =====
  display.setCursor(0,48);
  display.print("Asc Err: ");
  display.println(asconErrorCount);

  display.display();
}

void setup() {

  Serial.begin(115200);

  mySerial.begin(115200, SERIAL_8N1, 16, 17);

  Wire.begin(22,21);

  Wire.setClock(400000);

  if(!display.begin(SSD1306_SWITCHCAPVCC, 0x3C))
  {
    Serial.println("OLED INIT FAILED");

    while(true);
  }

  display.clearDisplay();

  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);

  display.setCursor(0,0);
  display.println("SYSTEM START");

  display.display();

  dht.begin();

  randomSeed(analogRead(0));

  cbc.setKey(key, sizeof(key));
}

void loop() {

  if (send_count >= TEST_ROUNDS) {

    Serial.println("=== DONE ===");

    while (1);
  }

  if (!readDHT()) {

    delay(1000);

    return;
  }

  bool tampered;

  // ===== AES =====
  cbc.setIV(iv, sizeof(iv));

  cbc.encrypt(ciphertext, plaintext, DATA_SIZE);

  tampered = injectError(ciphertext, DATA_SIZE);
  if(tampered)
  {
    aesErrorCount++;
  }

  sendFrame(0, plaintext, ciphertext, DATA_SIZE, tampered);

  delay(50);

  // ===== ChaCha20 =====
  chacha.clear();

  chacha.setKey(key, 16);

  chacha.setIV(nonce, 12);

  chacha.encrypt(ciphertext, plaintext, DATA_SIZE);

  tampered = injectError(ciphertext, DATA_SIZE);
  if(tampered)
  {
    chachaErrorCount++;
  }

  sendFrame(1, plaintext, ciphertext, DATA_SIZE, tampered);

  delay(50);

  // ===== Ascon =====
  ascon.clear();

  ascon.setKey(key, 16);

  ascon.setIV(nonce, 16);

  ascon.encrypt(ciphertext, plaintext, DATA_SIZE);

  ascon.computeTag(tag, 16);

  tampered = injectError(ciphertext, DATA_SIZE);
  if(tampered)
  {
    asconErrorCount++;
  }

  sendFrame(2,
            plaintext,
            ciphertext,
            DATA_SIZE,
            tampered,
            tag);

  send_count++;
  totalPackets += 3;

  updateOLED();

  delay(200);
}
