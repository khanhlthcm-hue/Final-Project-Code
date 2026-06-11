#include <Arduino.h>
#include <DHT.h>

#include <Crypto.h>
#include <AES.h>
#include <CBC.h>

#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#define DHTPIN 4
#define DHTTYPE DHT22

#define DATA_SIZE 32
#define TEST_ROUNDS 200
#define TRANSMIT_INTERVAL 2000

// OLED
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

DHT dht(DHTPIN, DHTTYPE);

// UART2
HardwareSerial mySerial(2);

// AES
CBC<AES128> cbc;

byte key[16] = {0};
byte iv[16]  = {0};

byte buffer[DATA_SIZE];

uint32_t encTimes[TEST_ROUNDS];

void sendHex(byte *data, int len)
{
  for(int i=0;i<len;i++)
  {
    if(data[i] < 16) mySerial.print("0");
    mySerial.print(data[i], HEX);
  }
}

void setup()
{
  Serial.begin(115200); // debug
  mySerial.begin(115200, SERIAL_8N1, 16, 17);

  dht.begin();

  Wire.begin(22,21);
  Wire.setClock(400000);
  if(!display.begin(SSD1306_SWITCHCAPVCC, 0x3C))
  {
    Serial.println("OLED failed");
    while(true);
  }

  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);

  display.setCursor(0,0);
  display.println("AES NODE");

  display.setCursor(0,16);
  display.println("System Starting");
  display.display();

  delay(2000);

  Serial.println("=== SENSOR NODE START ===");

  for(int i=0;i<TEST_ROUNDS;i++)
  {
    float t = dht.readTemperature();
    float h = dht.readHumidity();

    char payload[DATA_SIZE] = {0};
    snprintf(payload, DATA_SIZE, "T=%.2f,H=%.2f", t, h);

    memcpy(buffer, payload, DATA_SIZE);

    Serial.print("REAL: ");
    Serial.println(payload);

    cbc.setKey(key, sizeof(key));
    cbc.setIV(iv, sizeof(iv));

    noInterrupts();
    uint32_t start = micros();
    cbc.encrypt(buffer, buffer, DATA_SIZE);
    uint32_t encTime = micros() - start;
    interrupts();

    encTimes[i] = encTime;


    // ===== UART SEND =====
    mySerial.print(i);
    mySerial.print("|");
    mySerial.print(encTime);
    mySerial.print("|");

    sendHex(buffer, DATA_SIZE);
    mySerial.println();

    Serial.print("Sent Round: ");
    Serial.println(i);

     // ===== OLED DISPLAY =====
    display.clearDisplay();

    display.setCursor(0,0);
    display.println("AES NODE");

    display.setCursor(0,16);
    display.print("Round: ");
    display.println(i);

    display.setCursor(0,30);
    display.print("Temp : ");
    display.print(t);
    display.println(" C");

    display.setCursor(0,44);
    display.print("Hum  : ");
    display.print(h);
    display.println(" %");

    display.display();

    delay(TRANSMIT_INTERVAL);
  }

  Serial.println("=== SENSOR DONE ===");
}

void loop(){}