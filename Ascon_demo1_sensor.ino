#include <Arduino.h>
#include <DHT.h>

#include <Crypto.h>
#include <Ascon128.h>

#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#define DHTPIN 4
#define DHTTYPE DHT22

#define DATA_SIZE 32
#define TAG_SIZE 16
#define TEST_ROUNDS 200
#define TRANSMIT_INTERVAL 2000

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

DHT dht(DHTPIN, DHTTYPE);

HardwareSerial mySerial(2);

Ascon128 ascon;

byte key[16] = {0};
byte nonce[16] = {0};

byte buffer[DATA_SIZE];
byte tag[TAG_SIZE]; 

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
  Serial.begin(115200);
  mySerial.begin(115200, SERIAL_8N1, 16, 17);

  dht.begin();

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
  display.println("ASCON128 NODE");

  display.setCursor(0,16);
  display.println("System Starting");

  display.display();

  delay(2000);

  for(int i=0;i<TEST_ROUNDS;i++)
  {
    float t = dht.readTemperature();
    float h = dht.readHumidity();

    char payload[DATA_SIZE] = {0};
    snprintf(payload, DATA_SIZE, "T=%.2f,H=%.2f", t, h);

    memcpy(buffer, payload, DATA_SIZE);

    ascon.clear();
    ascon.setKey(key, sizeof(key));
    ascon.setIV(nonce, sizeof(nonce));

    noInterrupts();
    uint32_t start = micros();
    ascon.encrypt(buffer, buffer, DATA_SIZE);
    ascon.computeTag(tag, TAG_SIZE);
    uint32_t encTime = micros() - start;
    interrupts();

    mySerial.print(i);
    mySerial.print("|");
    mySerial.print(encTime);
    mySerial.print("|");

    sendHex(buffer, DATA_SIZE);
    mySerial.print("|");
    sendHex(tag, TAG_SIZE);
    mySerial.println();

    display.clearDisplay();

    display.setCursor(0,0);
    display.println("ASCON128 NODE");

    display.setCursor(0,16);
    display.print("Round : ");
    display.println(i);

    display.setCursor(0,28);
    display.print("Temp  : ");
    display.print(t);
    display.println(" C");

    display.setCursor(0,42);
    display.print("Hum   : ");
    display.print(h);
    display.println(" %");

    display.display();

    delay(TRANSMIT_INTERVAL);
  }
}

void loop(){}