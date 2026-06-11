#include <Arduino.h>
#include <Crypto.h>
#include <Ascon128.h>

#define DATA_SIZE 32
#define TEST_DURATION 180000
#define TAG_SIZE 16

HardwareSerial mySerial(2);

Ascon128 ascon;

byte key[16] = {0};
byte iv[16]  = {0};

byte ciphertext[DATA_SIZE];
byte decrypted[DATA_SIZE];
byte tag[16];   // nhận TAG

uint32_t totalEnc=0,totalDec=0,totalUART=0,totalE2E=0;
uint32_t minEnc=999999,maxEnc=0;
uint32_t minDec=999999,maxDec=0;
uint32_t minUART=999999,maxUART=0;
uint32_t minE2E=999999,maxE2E=0;

uint32_t packetCount=0,totalBytes=0;
uint32_t errorCount=0;  

String input="";
bool receiving=false;
uint32_t t_start_rx=0;

unsigned long startTime;

void hexToBytes(String hex, byte *output, int len)
{
  for(int i=0;i<len;i++)
  {
    String byteStr = hex.substring(i*2, i*2+2);
    output[i] = (byte) strtol(byteStr.c_str(), NULL, 16);
  }
}

void processData(String data, uint32_t uart_time)
{
  int p1=data.indexOf('|');
  int p2=data.indexOf('|',p1+1);
  int p3=data.indexOf('|',p2+1);

  if(p1<0||p2<0||p3<0) return;

  uint32_t encTime=data.substring(p1+1,p2).toInt();
  String hexCipher=data.substring(p2+1,p3);
  String hexTag=data.substring(p3+1);

  // convert
  hexToBytes(hexCipher,ciphertext,DATA_SIZE);
  hexToBytes(hexTag,tag,16);

  // ===== RESET + SET KEY =====
  ascon.clear();
  ascon.setKey(key,sizeof(key));
  ascon.setIV(iv,sizeof(iv));

  uint32_t t1=micros();

  ascon.decrypt(decrypted,ciphertext,DATA_SIZE);

  bool isValid = ascon.checkTag(tag, sizeof(tag)); 

  uint32_t decTime=micros()-t1;

  if(!isValid)
  {
    errorCount++;
  }

  uint32_t e2e=uart_time+encTime+decTime;

  packetCount++;
  totalBytes += (DATA_SIZE + TAG_SIZE);

  totalEnc+=encTime;
  totalDec+=decTime;
  totalUART+=uart_time;
  totalE2E+=e2e;

  if(encTime<minEnc) minEnc=encTime;
  if(encTime>maxEnc) maxEnc=encTime;

  if(decTime<minDec) minDec=decTime;
  if(decTime>maxDec) maxDec=decTime;

  if(uart_time<minUART) minUART=uart_time;
  if(uart_time>maxUART) maxUART=uart_time;

  if(e2e<minE2E) minE2E=e2e;
  if(e2e>maxE2E) maxE2E=e2e;
}

void setup()
{
  Serial.begin(115200);
  mySerial.begin(115200, SERIAL_8N1, 16, 17);
  startTime=millis();
}

void loop()
{
  if(millis()-startTime>=TEST_DURATION)
  {
    unsigned long endTime = millis();
    float duration = (endTime - startTime) / 1000.0;

    float avgEnc=totalEnc/(float)packetCount;
    float avgDec=totalDec/(float)packetCount;
    float avgUART=totalUART/(float)packetCount;
    float avgE2E=totalE2E/(float)packetCount;
    float encPerByte = avgEnc / DATA_SIZE;
    float decPerByte = avgDec / DATA_SIZE;

    // ===== THROUGHPUT =====
    float cryptoThroughput = (DATA_SIZE * 1000000.0) / avgEnc / 1024.0;
    float systemThroughput = ((DATA_SIZE + TAG_SIZE) * 1000000.0) / avgE2E / 1024.0;
    float empiricalThroughput = (totalBytes / 1024.0) / duration;

    Serial.println("\n========= FINAL RESULT =========");

    Serial.print("Total Packets: "); Serial.println(packetCount);
    
    Serial.print("Duration(s): ");
    Serial.println(duration);

    Serial.print("Total Data(KB): ");
    Serial.println(totalBytes / 1024.0);

    Serial.println();
    Serial.print("Avg Enc(us): "); Serial.println(avgEnc);
    Serial.print("Min Enc(us): "); Serial.println(minEnc);
    Serial.print("Max Enc(us): "); Serial.println(maxEnc);

    Serial.println();

    Serial.print("Avg Dec(us): "); Serial.println(avgDec);
    Serial.print("Min Dec(us): "); Serial.println(minDec);
    Serial.print("Max Dec(us): "); Serial.println(maxDec);

    Serial.println();

    Serial.print("Avg UART(us): "); Serial.println(avgUART);
    Serial.print("Min UART(us): "); Serial.println(minUART);
    Serial.print("Max UART(us): "); Serial.println(maxUART);

    Serial.println();

    Serial.print("Avg E2E(us): "); Serial.println(avgE2E);
    Serial.print("Min E2E(us): "); Serial.println(minE2E);
    Serial.print("Max E2E(us): "); Serial.println(maxE2E);

    Serial.println();

    Serial.print("Crypto Throughput - Encrypt (KB/s): ");
    Serial.println(cryptoThroughput);

    Serial.print("System Throughput - E2E (KB/s): ");
    Serial.println(systemThroughput);

    Serial.print("Empirical Throughput (KB/s): ");
    Serial.println(empiricalThroughput);

    Serial.print("Enc Cost (us/byte): ");
    Serial.println(encPerByte);

    Serial.print("Dec Cost (us/byte): ");
    Serial.println(decPerByte);

    Serial.println();

    Serial.print("Error Packets: ");
    Serial.println(errorCount);

    float errorRate = (errorCount * 100.0) / packetCount;

    Serial.print("Error Rate (%): ");
    Serial.println(errorRate);

    while(1);
  }

  while(mySerial.available())
  {
    char c=mySerial.read();

    if(!receiving)
    {
      receiving=true;
      t_start_rx=micros();
    }

    if(c=='\n')
    {
      uint32_t uart_time=micros()-t_start_rx;
      processData(input,uart_time);

      input="";
      receiving=false;
    }
    else input+=c;
  }
}