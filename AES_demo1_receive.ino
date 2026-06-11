#include <Arduino.h>

#include <Crypto.h>
#include <AES.h>
#include <CBC.h>

#define DATA_SIZE 32
#define TEST_ROUNDS 200

HardwareSerial mySerial(2);

CBC<AES128> cbc;

byte key[16] = {0};
byte iv[16]  = {0};

byte ciphertext[DATA_SIZE];
byte decrypted[DATA_SIZE];

uint32_t encTimes[TEST_ROUNDS];
uint32_t decTimes[TEST_ROUNDS];
uint32_t uartTimes[TEST_ROUNDS];
uint32_t e2eTimes[TEST_ROUNDS];

String input = "";
int receivedCount = 0;

// ===== UART TIMING =====
uint32_t t_start_rx = 0;
bool receiving = false;

void hexToBytes(String hex, byte *output)
{
  for(int i=0;i<DATA_SIZE;i++)
  {
    String byteStr = hex.substring(i*2, i*2+2);
    output[i] = (byte) strtol(byteStr.c_str(), NULL, 16);
  }
}

void processData(String data, uint32_t uart_time)
{
  int p1 = data.indexOf('|');
  int p2 = data.indexOf('|', p1+1);

  if(p1 < 0 || p2 < 0) return;

  int round = data.substring(0, p1).toInt();
  uint32_t encTime = data.substring(p1+1, p2).toInt();
  String hexCipher = data.substring(p2+1);

  hexToBytes(hexCipher, ciphertext);

  // ===== DECRYPT =====
  cbc.setKey(key, sizeof(key));
  cbc.setIV(iv, sizeof(iv));

  uint32_t start = micros();
  cbc.decrypt(decrypted, ciphertext, DATA_SIZE);
  uint32_t decTime = micros() - start;

  // ===== E2E =====
  uint32_t e2e = uart_time + encTime + decTime;

  encTimes[round] = encTime;
  decTimes[round] = decTime;
  uartTimes[round] = uart_time;
  e2eTimes[round] = e2e;

  Serial.println("\n--- RECEIVED ---");
  Serial.print("Round: "); Serial.println(round);
  Serial.print("Data: "); Serial.println((char*)decrypted);

  Serial.print("Enc(us): "); Serial.println(encTime);
  Serial.print("Dec(us): "); Serial.println(decTime);
  Serial.print("UART(us): "); Serial.println(uart_time);
  Serial.print("E2E(us): "); Serial.println(e2e);

  receivedCount++;

  if(receivedCount == TEST_ROUNDS)
  {
    printBenchmark();
  }
}

void printBenchmark()
{
  uint32_t minEnc=999999,maxEnc=0,totalEnc=0;
  uint32_t minDec=999999,maxDec=0,totalDec=0;
  uint32_t minUART=999999,maxUART=0,totalUART=0;
  uint32_t minE2E=999999,maxE2E=0,totalE2E=0;

  for(int i=0;i<TEST_ROUNDS;i++)
  {
    totalEnc += encTimes[i];
    totalDec += decTimes[i];
    totalUART += uartTimes[i];
    totalE2E += e2eTimes[i];

    if(encTimes[i] < minEnc) minEnc = encTimes[i];
    if(encTimes[i] > maxEnc) maxEnc = encTimes[i];

    if(decTimes[i] < minDec) minDec = decTimes[i];
    if(decTimes[i] > maxDec) maxDec = decTimes[i];

    if(uartTimes[i] < minUART) minUART = uartTimes[i];
    if(uartTimes[i] > maxUART) maxUART = uartTimes[i];

    if(e2eTimes[i] < minE2E) minE2E = e2eTimes[i];
    if(e2eTimes[i] > maxE2E) maxE2E = e2eTimes[i];
  }

  float avgEnc = totalEnc / (float)TEST_ROUNDS;
  float avgDec = totalDec / (float)TEST_ROUNDS;
  float avgUART = totalUART / (float)TEST_ROUNDS;
  float avgE2E = totalE2E / (float)TEST_ROUNDS;

  // ===== CRYPTO THROUGHPUT =====
  float cryptoThroughput = (DATA_SIZE * 1000000.0) / avgEnc / 1024.0;

  // ===== SYSTEM THROUGHPUT =====
  float systemThroughput = (DATA_SIZE * 1000000.0) / avgE2E / 1024.0;

  Serial.println("\n========= FINAL RESULT =========");

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

  Serial.print("Crypto Throughput (KB/s): ");
  Serial.println(cryptoThroughput);

  Serial.print("System Throughput (KB/s): ");
  Serial.println(systemThroughput);
}

void setup()
{
  Serial.begin(115200);
  mySerial.begin(115200, SERIAL_8N1, 16, 17);

  Serial.println("=== RECEIVER START ===");
}

void loop()
{
  while(mySerial.available())
  {
    char c = mySerial.read();

    if(!receiving)
    {
      receiving = true;
      t_start_rx = micros(); // bắt đầu nhận
    }

    if(c == '\n')
    {
      uint32_t t_end_rx = micros();
      uint32_t uart_time = t_end_rx - t_start_rx;

      processData(input, uart_time);

      input = "";
      receiving = false;
    }
    else
    {
      input += c;
    }
  }
}