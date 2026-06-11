#include <Arduino.h>
#include <Crypto.h>
#include <Ascon128.h>

#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#define DATA_SIZE 32
#define TEST_DURATION 180000   

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

HardwareSerial mySerial(2);

Ascon128 ascon;

byte key[16]   = {0};
byte nonce[16] = {0};

byte buffer[DATA_SIZE];
byte tag[16];   
uint32_t packetID = 0;
unsigned long startTime;
unsigned long lastOLEDUpdate = 0;

// ===== GỬI HEX =====
void sendHex(byte *data, int len)
{
  for(int i = 0; i < len; i++)
  {
    if(data[i] < 16) mySerial.print("0");
    mySerial.print(data[i], HEX);
  }
}


void updateOLED(unsigned long elapsedMs)
{
  uint32_t totalSec = elapsedMs / 1000;

  uint32_t minutes = totalSec / 60;
  uint32_t seconds = totalSec % 60;

  display.clearDisplay();

  display.setCursor(0,0);
  display.println("ASCON128");

  display.setCursor(0,16);
  display.print("Time: ");

  if(minutes < 10) display.print("0");
  display.print(minutes);

  display.print(":");

  if(seconds < 10) display.print("0");
  display.println(seconds);

  display.setCursor(0,36);
  display.print("Packets:");

  display.setCursor(0,50);
  display.println(packetID);

  display.display();
}

void setup()
{
  Serial.begin(115200);
  mySerial.begin(115200, SERIAL_8N1, 16, 17);

  Wire.begin(22, 21);
  Wire.setClock(400000);
  if(!display.begin(SSD1306_SWITCHCAPVCC, 0x3C))
  {
    Serial.println("OLED init failed");

    while(true);
  }

  display.clearDisplay();

  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);

  display.setCursor(0,0);
  display.println("ASCON128");

  display.setCursor(0,16);
  display.println("System Starting");

  display.display();

  startTime = millis();

  Serial.println("=== ASCON Sender START ===");
}

void loop()
{
  unsigned long currentTime = millis();
  if(currentTime - startTime >= TEST_DURATION)
  {
    Serial.println("=== DONE ===");

    display.clearDisplay();

    display.setCursor(0,0);
    display.println("TEST FINISHED");

    display.setCursor(0,16);
    display.print("Total Packet:");

    display.setCursor(0,32);
    display.println(packetID);

    display.display();

    while(1);
  }

  // ===== TẠO DỮ LIỆU GIẢ =====
  float temp = random(2000,3500)/100.0;
  float hum  = random(4000,8000)/100.0;

  char payload[DATA_SIZE] = {0};
  snprintf(payload, DATA_SIZE, "T=%.2f,H=%.2f", temp, hum);

  memcpy(buffer, payload, DATA_SIZE);

  // ===== RESET + SET KEY =====
  ascon.clear();
  ascon.setKey(key, sizeof(key));
  ascon.setIV(nonce, sizeof(nonce));

  // ===== ENCRYPT + TAG =====
  uint32_t t1 = micros();

  ascon.encrypt(buffer, buffer, DATA_SIZE);
  ascon.computeTag(tag, sizeof(tag));

  uint32_t encTime = micros() - t1;

  // ===== GỬI UART =====
  mySerial.print(packetID++);
  mySerial.print("|");
  mySerial.print(encTime);
  mySerial.print("|");

  // ciphertext
  sendHex(buffer, DATA_SIZE);

  mySerial.print("|");

  // TAG
  sendHex(tag, 16);

  mySerial.println();
  if(currentTime - lastOLEDUpdate >= 10000)
  {
    updateOLED(currentTime - startTime);

    lastOLEDUpdate = currentTime;
  }
}