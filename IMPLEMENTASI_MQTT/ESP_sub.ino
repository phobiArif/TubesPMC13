#include <Arduino.h>
#include <string.h>
#include "encrypt.h"
#include <PubSubClient.h>
//#include "read_image.c"
#include <SPIFFS.h>
#include "WiFi.h"
#include "esp_camera.h"
#include "esp_timer.h"
#include "img_converters.h"
#include "Arduino.h"
#include "soc/soc.h"           // Disable brownour problems
#include "soc/rtc_cntl_reg.h"  // Disable brownour problems
#include "driver/rtc_io.h"
#include <ESPAsyncWebServer.h>
#include <StringArray.h>
#include <FS.h>
#include "Base64.h"
#include <stdio.h>
#include <stdlib.h>
#include <Wire.h>
#include <WiFiClient.h>
#include <Adafruit_SSD1306.h>
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);

#define KEY_SIZE 16
#define NONCE_SIZE 16
#define TAG_SIZE 16
#define BLOCK_SIZE 64
#define KEYBYTES 32
#define NONCEBYTES 12
#define TAGBYTES 8


const char* ssid = "Xiaomi 11T Pro";
const char* password = "arif57840";
//const char* mqtt_server = "broker.mqtt-dashboard.com";

// Port to listen for incoming connections
const int serverPort = 8888;

WiFiServer server(serverPort);
WiFiClient client;

unsigned char key[KEY_SIZE] = "kelompok13";      // use a random key instead of all zeros
unsigned char nonce[NONCEBYTES] = "ISAP64";  // use a random nonce instead of all zeros
unsigned char ad[] = { 0 };               // no associated data
unsigned long adlen = 0;


void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);
  Wire.begin(5, 4); // Initialize Wire library with SDA pin 5 and SCL pin 4
  display.begin(SSD1306_SWITCHCAPVCC, 0x3C); // Initialize the display with I2C address 0x3C
  display.clearDisplay(); // Clear the display buffer
  display.setTextSize(1); // Set text size (optional)
  display.setTextColor(SSD1306_WHITE); // Set text color (optional)
  // Connect to Wi-Fi
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Connecting to WiFi...");
  }
  

  server.begin();
  
  Serial.println("Server started");
  Serial.print("IP Addr :");
  Serial.println(WiFi.localIP());
  

}

void loop() {
if (!client.connected()) {
    client = server.available();
    if (client) {
      Serial.println("Client connected");
      
      // Receive the array size
      unsigned long long ciphertext_len;
      if (client.available() >= sizeof(ciphertext_len)) {
        client.readBytes((char*)&ciphertext_len, sizeof(ciphertext_len));
        // Create a buffer to hold the received data
        unsigned char* ciphertext = new unsigned char[ciphertext_len];
        // Receive the array data
          client.readBytes((char*)ciphertext, ciphertext_len);
          Serial.println("titikakhir");
          // Process the received array data
//          for (int i = 0; i < ciphertext_len; i++) {
//            Serial.print(ciphertext[i]);
//            Serial.print(" ");
//          }
          Serial.printf("%s", ciphertext);
          Serial.printf("%d\n", ciphertext_len);
          Serial.println();

          // Dekripsi ciphertext dan mencetak decrypted_plaintext sebagai string
  unsigned long long plaintext_len = ciphertext_len - TAGBYTES;
  unsigned char* decrypt = (unsigned char*) malloc (plaintext_len);
  
  int inv = crypto_aead_decrypt(decrypt, &plaintext_len, NULL, ciphertext, ciphertext_len, ad, adlen, nonce, key);
  
  if (inv != 0) {
     Serial.printf("Decrypt failed \n");
     Serial.println(inv);
     free(ciphertext);
     free(decrypt);
     return;
   }
   decrypt[plaintext_len]= (unsigned char)'\0';
  display.clearDisplay(); // Clear the display buffer before writing new text
  display.setCursor(0, 0); // Set the cursor position (optional)
  display.print("Berhasil didekrip"); // Print the desired message
  display.display(); // Display the content on the OLED screen
   Serial.printf("%s", decrypt);
          
          // Clean up the dynamically allocated memory
          delete[] ciphertext;
        

      }
    }
  }
  
  delay(1);
}
