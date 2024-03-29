#include <ArduinoJson.h>
#include <ArduinoJson.hpp>
#include <WiFiClient.h>
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

#define KEY_SIZE 16
#define NONCE_SIZE 16
#define TAG_SIZE 16
#define BLOCK_SIZE 64

#define KEYBYTES 32
#define NONCEBYTES 12
#define TAGBYTES 8


const char* host = "192.168.209.23"; // IP address of the receiver ESP32
const uint16_t port = 8888; // Port number to send data

//AsyncWebServer server(80);
WiFiClient client;

#define FILE_PHOTO "/photo.jpg"

// OV2640 camera module pins (CAMERA_MODEL_AI_THINKER)
#define PWDN_GPIO_NUM 32
#define RESET_GPIO_NUM -1
#define XCLK_GPIO_NUM 0
#define SIOD_GPIO_NUM 26
#define SIOC_GPIO_NUM 27
#define Y9_GPIO_NUM 35
#define Y8_GPIO_NUM 34
#define Y7_GPIO_NUM 39
#define Y6_GPIO_NUM 36
#define Y5_GPIO_NUM 21
#define Y4_GPIO_NUM 19
#define Y3_GPIO_NUM 18
#define Y2_GPIO_NUM 5
#define VSYNC_GPIO_NUM 25
#define HREF_GPIO_NUM 23
#define PCLK_GPIO_NUM 22

// Replace with your network credentials
//const char* ssid = "tselhome-60D6";
//const char* password = "0F4R4R1L8AE";
const char* ssid = "Xiaomi 11T Pro";
const char* password = "arif57840";
//const char* mqtt_server = "broker.mqtt-dashboard.com";

unsigned char key[KEY_SIZE] = "kelompok13";      // use a random key instead of all zeros
unsigned char nonce[NONCEBYTES] = "ISAP64";  // use a random nonce instead of all zeros
unsigned char ad[] = { 0 };               // no associated data
unsigned long adlen = 0;


// Check if photo capture was successful
bool checkPhoto(fs::FS& fs) {
  File f_pic = fs.open(FILE_PHOTO);
  unsigned int pic_sz = f_pic.size();
  return (pic_sz > 100);
}


// Capture Photo and Save it to SPIFFS
void capturePhotoSaveSpiffs(void) {
  camera_fb_t* fb = NULL;  // pointer
  bool ok = 0;             // Boolean indicating if the picture has been taken correctly

  do {
    // Take a photo with the camera
    Serial.println("Taking a photo...");

    fb = esp_camera_fb_get();
    if (!fb) {
      Serial.println("Camera capture failed");
      ok = 0;
    }
  
  
    Serial.printf("Picture file name: %s\n", FILE_PHOTO);
    File file = SPIFFS.open(FILE_PHOTO, FILE_WRITE);

    // Insert the data in the photo file
    if (!file) {
      Serial.println("Failed to open file in writing mode");
    } else {
      file.write(fb->buf, fb->len);  // payload (image), payload length
      Serial.print("The picture has been saved in ");
      Serial.print(FILE_PHOTO);
      Serial.print(" - Size: ");
      Serial.print(file.size());
      Serial.println(" bytes");
    }
    // Close the file
    file.close();
    esp_camera_fb_return(fb);

    // check if file has been correctly saved in SPIFFS
    ok = checkPhoto(SPIFFS);
  } while (!ok);
}

unsigned char* read_image(void){
  File file = SPIFFS.open(FILE_PHOTO, "r");
  if (!file) {
    Serial.println("Failed to open file");
    exit(1);
  }

  size_t fileSize = file.size();
  std::unique_ptr<uint8_t[]> imageData(new uint8_t[fileSize]);
  if (file.readBytes(reinterpret_cast<char*>(imageData.get()), fileSize) != fileSize) {
    Serial.println("Error reading file");
    exit(2);
  }
  file.close();

  String base64Image = base64::encode(imageData.get(), fileSize);
  unsigned char* buffer = (unsigned char*) malloc (base64Image.length() + 1);
  //new unsigned char[base64Image.length() + 1];
  Serial.println("DEbug 1");
  Serial.println(base64Image.length());

  // Serial.println("Base64 Image:");
  // Serial.println(base64Image);
  
  Serial.println("DEbug 2");
  // Copy the string to the unsigned char buffer
  mystrlcpy((char*)buffer, base64Image.c_str(), fileSize);

  return(buffer);
}

void mystrlcpy(char* dst, const char* src, size_t size) {
  size_t srcLen = strlen(src);
  Serial.println(srcLen);
  //size_t copyLen = srcLen >= size ? size - 1 : srcLen;
  //Serial.println(copyLen);
  memcpy(dst, src, srcLen);
  Serial.println("DEbug 5");
  dst[srcLen] = '\0';
}



void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);

  // Connect to Wi-Fi
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Connecting to WiFi...");
  }
  
  // client.setServer(mqtt_server, 1883);
  // client.setCallback(callback);

  if (!SPIFFS.begin(true)) {
    Serial.println("An Error has occurred while mounting SPIFFS");
    ESP.restart();
  } else {
    delay(500);
    Serial.println("SPIFFS mounted successfully");
  }

  // Turn-off the 'brownout detector'
  WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0);

  // OV2640 camera module
  camera_config_t config;
  config.ledc_channel = LEDC_CHANNEL_0;
  config.ledc_timer = LEDC_TIMER_0;
  config.pin_d0 = Y2_GPIO_NUM;
  config.pin_d1 = Y3_GPIO_NUM;
  config.pin_d2 = Y4_GPIO_NUM;
  config.pin_d3 = Y5_GPIO_NUM;
  config.pin_d4 = Y6_GPIO_NUM;
  config.pin_d5 = Y7_GPIO_NUM;
  config.pin_d6 = Y8_GPIO_NUM;
  config.pin_d7 = Y9_GPIO_NUM;
  config.pin_xclk = XCLK_GPIO_NUM;
  config.pin_pclk = PCLK_GPIO_NUM;
  config.pin_vsync = VSYNC_GPIO_NUM;
  config.pin_href = HREF_GPIO_NUM;
  config.pin_sscb_sda = SIOD_GPIO_NUM;
  config.pin_sscb_scl = SIOC_GPIO_NUM;
  config.pin_pwdn = PWDN_GPIO_NUM;
  config.pin_reset = RESET_GPIO_NUM;
  config.xclk_freq_hz = 20000000;
  config.pixel_format = PIXFORMAT_JPEG;

  if (psramFound()) {
    config.frame_size = FRAMESIZE_HVGA;
    config.jpeg_quality = 10;
    config.fb_count = 2;
  } else {
    config.frame_size = FRAMESIZE_CIF;
    config.jpeg_quality = 12;
    config.fb_count = 1;
  }
  // Camera init
  esp_err_t err = esp_camera_init(&config);
  if (err != ESP_OK) {
    Serial.printf("Camera init failed with error 0x%x", err);
    ESP.restart();
  } else {
    Serial.printf("Camera init success!");
  }


}

void loop() {

  capturePhotoSaveSpiffs();
  unsigned char* plaintext = read_image();
  Serial.println("DEbug 6");
  unsigned long long plaintext_len = strlen((char*)plaintext);
  Serial.println("DEbug 7");
  Serial.printf("%d", plaintext_len);
  unsigned char* ciphertext = (unsigned char*) malloc (plaintext_len + TAGBYTES);
  //new unsigned char[plaintext_len];
  Serial.println("DEbug 8");
  unsigned long long ciphertext_len = 0;
  unsigned char tag[TAGBYTES] = { 0 };
  
  Serial.printf("\n%s \n", plaintext);
  Serial.printf("Image converted to string successfully\n");

  int ret = crypto_aead_encrypt(ciphertext, &ciphertext_len,
                                plaintext, plaintext_len,
                                ad, adlen,
                                NULL,  // no additional authenticated data
                                nonce,
                                key);

  if (ret != 0) {
    Serial.printf("Encryption failed\n");
  }
  //delete[] plaintext;
  free(plaintext);

  Serial.printf("Encrypt success\n");
  Serial.printf("%d\n", plaintext_len);
  Serial.printf("%d\n", ciphertext_len);
  Serial.printf("%s", ciphertext);
  

  if (!client.connected()) {
    Serial.println("Connecting to server...");
    if (client.connect(host, port)) {
      Serial.println("Connected to server");
      

      // Send the array size
      client.write((const uint8_t*)&ciphertext_len, sizeof(ciphertext_len));
      
      // Send the array data
      client.write(ciphertext, ciphertext_len);
      
      
    }
  }
  free(ciphertext);
  delay(10000); 
  
}

String createMessageFrame(int chunkIndex, int totalChunks, const unsigned char* data, int ciphertext_len) {
  // Create a message frame with metadata
  String frame = String(chunkIndex) + ":" + String(totalChunks) + ":";

  // Append the data to the frame
  for (int i = 0; i < ciphertext_len; i++) {
    frame += char(data[i]);
  }

  return frame;
}






