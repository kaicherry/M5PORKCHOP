#include <Arduino.h>
struct Detection {
  char  ssid[33];
  uint8_t bssid[6];
  int8_t  rssi;
  uint32_t firstSeen;
  uint32_t lastSeen;
  uint8_t  hitCount;
  bool     fresh;
  uint8_t  type;  // 0=FLOCK, 1=BODYCAM
};

struct DetectedNet {
  char ssid[33];
  int8_t rssi;
  uint8_t channel;
  uint8_t authmode;
};

class PorkPatrol {
public:
static void init();
    static void start();
    static void stop();
    static void update();
    static bool isRunning();
    static uint32_t getDetections();
    static uint8_t getHitCount();
    static uint8_t getHitType(uint8_t i);
    static int8_t  getHitRssi(uint8_t i);
    static void    getHitSSID(uint8_t i, char* buf, uint8_t len);
    static void    getHitMAC(uint8_t i, uint8_t* out);


private: 
// ── Detection signatures from deflock.me / flock-you research ──
// SSID substrings: case-insensitive match on beacon/probe SSIDs


};