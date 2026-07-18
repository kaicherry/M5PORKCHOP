// ============================================================
// PORK PATROL — Flock Safety ALPR camera detector
// The pig goes undercover. Sniffs WiFi for surveillance cams.
// Detection via SSID patterns + MAC OUI prefix matching.
// Based on research from deflock.me and the flock-you project.
// ============================================================
#include "pork_patrol.h"
#include "../core/xp.h"
#include "../core/network_recon.h"
#include "../gps/gps.h"
#include "../ui/display.h"
#include "../audio/sfx.h"
#include "../piglet/mood.h"
#include "../piglet/avatar.h"

// DetectedNetwork: used by NetworkRecon, OinkMode, DNHMode, WarhogMode, Display
struct DetectedNetwork {
  uint8_t  bssid[6];
  char     ssid[33];
  int8_t   rssi;
  int8_t   rssiAvg;
  uint8_t  channel;
  wifi_auth_mode_t authmode;
  uint32_t firstSeen;
  uint32_t lastSeen;
  uint32_t lastBeaconSeen;
  uint16_t beaconCount;
  uint16_t beaconIntervalEmaMs;
  bool     isTarget;
  bool     hasPMF;
  bool     hasHandshake;
  uint8_t  attackAttempts;
  bool     isHidden;
  uint32_t lastDataSeen;
  uint32_t cooldownUntil;
  uint64_t clientBitset;
};



#define MAX_NETS 64
DetectedNet nets[MAX_NETS];

static bool _running = false;
static uint32_t _lastScan = 0;
static uint32_t _totalDetected = 0;
static Detection _hits[8];
static uint8_t   _hitCount = 0;
static uint32_t lm=0;
// ── Detection signatures from deflock.me / flock-you research ──
// SSID substrings: case-insensitive match on beacon/probe SSIDs
static const char* SSID_PATTERNS[] = {
  "flock",       // Flock-XXXXXX AP names
  "fs ext",      // FS Ext Battery module
  "pigvision",   // older Flock firmware
  "penguin",     // Raven/Penguin naming
  "flockca",     // FlockCamera variants
};
static const uint8_t SSID_PATTERN_COUNT = 5;

// Bodycam SSID patterns — Axon/Motorola BWC networks
static const char* BWC_SSID_PATTERNS[] = {
  "axon",        // AXON-XXXXXXXX serial SSIDs, Axon networks
  "bwcviewer",   // Axon BWC Viewer AP
  "evidence",    // Evidence.com sync networks
  "taser",       // older Taser/Axon branding
  "motorola bwc",// Motorola BWC upload networks
  "vievu",       // VIEVU (acquired by Motorola)
  "v300",        // Motorola V300 series
  "v500",        // Motorola V500 series
  "ibr",         // Cradlepoint IBR in-car routers (law enforcement)
};
static const uint8_t BWC_SSID_PATTERN_COUNT = 9;

// Known Flock Safety OUI prefixes (first 3 bytes of MAC)
// Sources: deflock.me dataset, flock-you project
static const uint8_t FLOCK_OUIS[][3] = {
  {0x00,0x17,0xF2}, {0x00,0x1D,0xC9}, {0x18,0x0F,0x76},
  {0x20,0x02,0xAF}, {0x24,0xA4,0x3C}, {0x2C,0xCF,0x67},
  {0x34,0xE8,0x94}, {0x3C,0x5A,0xB4}, {0x40,0x9F,0x38},
  {0x44,0xD9,0xE7}, {0x48,0x2C,0x6A}, {0x50,0xC7,0xBF},
  {0x54,0xAF,0x97}, {0x5C,0xBA,0xEF}, {0x60,0x38,0xE0},
  {0x6C,0x40,0x08}, {0x70,0x3A,0xCB}, {0x74,0xDA,0x38},
  {0x78,0x8A,0x20}, {0x7C,0x1E,0xB3},
};
static const uint8_t FLOCK_OUI_COUNT = 20;

// Axon Enterprise OUI prefixes — bodycam WiFi modules
// Source: IEEE OUI database, WiGLE research (vertex.link/blogs/wigle)
static const uint8_t AXON_OUIS[][3] = {
  {0x00,0x25,0xDF},  // Axon Enterprise (primary — confirmed bodycam OUI)
  {0x00,0x17,0xF2},  // Axon Networks legacy
  {0xB4,0xE6,0x2D},  // Axon Enterprise (newer hardware)
};
static const uint8_t AXON_OUI_COUNT = 3;

static bool _ssidMatch(const char* ssid, uint8_t& typeOut) {
  if (!ssid || !ssid[0]) return false;
  char lower[33]; int i=0;
  while (ssid[i] && i<32) { lower[i]=(char)tolower((uint8_t)ssid[i]); i++; }
  lower[i]=0;
  for (uint8_t p=0; p<SSID_PATTERN_COUNT; p++)
    if (strstr(lower, SSID_PATTERNS[p])) { typeOut=0; return true; }
  for (uint8_t p=0; p<BWC_SSID_PATTERN_COUNT; p++)
    if (strstr(lower, BWC_SSID_PATTERNS[p])) { typeOut=1; return true; }
  return false;
}

static bool _ouiMatch(const uint8_t* bssid, uint8_t& typeOut) {
  for (uint8_t i=0; i<FLOCK_OUI_COUNT; i++)
    if (bssid[0]==FLOCK_OUIS[i][0] && bssid[1]==FLOCK_OUIS[i][1] && bssid[2]==FLOCK_OUIS[i][2])
    
      { Avatar::attackHop();
        typeOut=0; return true; }
  for (uint8_t i=0; i<AXON_OUI_COUNT; i++)
    if (bssid[0]==AXON_OUIS[i][0] && bssid[1]==AXON_OUIS[i][1] && bssid[2]==AXON_OUIS[i][2])
      {
        Avatar::cuteJump();
         typeOut=1; return true; }
  return false;
}

static void _addHit(const char* ssid, const uint8_t* bssid, int8_t rssi, uint8_t type) {
  for (uint8_t i=0; i<_hitCount; i++) {
    if (memcmp(_hits[i].bssid, bssid, 6)==0) {
      _hits[i].rssi = rssi;
      _hits[i].lastSeen = millis();
      _hits[i].hitCount++;
      return;
    }
  }
  if (_hitCount >= 8) return;
  Detection& d = _hits[_hitCount++];
  strncpy(d.ssid, ssid, 32); d.ssid[32]=0;
  memcpy(d.bssid, bssid, 6);
  d.rssi = rssi;
  d.firstSeen = d.lastSeen = millis();
  d.hitCount = 1;
  d.fresh = true;
  d.type = type;
  _totalDetected++;
  SFX::play(SFX::ACHIEVEMENT);
  const char* label = (type==1) ? "BODYCAM" : "FLOCK CAM";
  char msg[24]; snprintf(msg,sizeof(msg),"%s SPOTTED",label);
  Mood::setStatusMessage(msg);
  Serial.printf("[PATROL] %s: %s [%02X:%02X:%02X:%02X:%02X:%02X] rssi=%d\n",
    label, ssid, bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5], rssi);
//   if (GPS::hasFix())
//     Serial.printf("[PATROL] GPS: %.6f,%.6f\n", GPS::gpsLat, gpsLon);
  //WarTales::logDetection(label, ssid[0] ? ssid : "hidden");
}

static void _scanNetworks() {
  NetworkRecon::enterCritical();
  const auto& nets = NetworkRecon::getNetworks();
  if (&nets == nullptr) {
    // Log the error or handle it safely to prevent the crash
    Serial.println("Error: nets reference is null!"); 
    NetworkRecon::exitCritical();
    return; 
  }
  for (const auto& n : nets) {
    uint8_t type = 0;
    bool hit = _ssidMatch(n.ssid, type) || _ouiMatch(n.bssid, type);
    if (hit) _addHit(n.ssid, n.bssid, n.rssi, type);
  }
  NetworkRecon::exitCritical();
}

void PorkPatrol::start() {
  if (_running) return;
  //Avatar::setNinja(true);
  _running = true;
  _hitCount = 0;
  _totalDetected = 0;
  _lastScan = 0;
  if (!NetworkRecon::isRunning()) NetworkRecon::start();
  Avatar::setState(AvatarState::HUNTING);
 // Avatar::setNinja(true);
  Avatar::setGrassMoving(true);
  Avatar::setGrassSpeed(80);
  Avatar::waveRipple(WaveMode::INCOMING);
  Mood::setStatusMessage("oink oink oink");
  Display::showToast("PORK PATROL ON", 1500);
  Serial.println("[PATROL] started — sniffing for fed cams");
}

void PorkPatrol::stop() {
  if (!_running) return;
  _running = false;
  Avatar::setNinja(true);
  Avatar::setGrassMoving(false);
  Avatar::setState(AvatarState::NEUTRAL);
    Avatar::waveRipple(WaveMode::NONE);
  Display::showToast("PATROL ENDED", 1500);
  Serial.printf("[PATROL] stopped. %lu flock cams detected\n", _totalDetected);
}


void PorkPatrol::update() {
    Serial.println("IN::PATUPDT");

  if (!_running) return;
   char buf[32];
  //Avatar::setGrassMoving(true);
Serial.println("RN::PATUPDT");
  uint32_t now = millis();
  if (now - _lastScan > 2000) { _scanNetworks(); _lastScan = now;}
  
Serial.printf("LASTSCAN:::%d",_lastScan);
  if (now-lm > 5000) {
   Serial.println("BEEN5SECS");
   if(_hitCount > 0) { 
    strncpy(buf,"Hit mate!!!",sizeof(buf));
    }else {
     strncpy(buf,"oi, got nuffin mate...",sizeof(buf));
   }
  // Mood::setStatusMessage(buf); lm=now;
  }
}

uint32_t PorkPatrol::getDetections() { return _totalDetected; }

bool PorkPatrol::isRunning() { return _running; }
uint8_t PorkPatrol::getHitCount()    { return _hitCount; }
uint8_t PorkPatrol::getHitType(uint8_t i) { if(i>=_hitCount)return 0; return _hits[i].type; }
int8_t  PorkPatrol::getHitRssi(uint8_t i) { if(i>=_hitCount)return 0; return _hits[i].rssi; }
void    PorkPatrol::getHitSSID(uint8_t i, char* buf, uint8_t len) { if(i<_hitCount) strncpy(buf,_hits[i].ssid,len); else buf[0]=0; }
void    PorkPatrol::getHitMAC(uint8_t i, uint8_t* out) { if(i<_hitCount) memcpy(out,_hits[i].bssid,6); else memset(out,0,6); }

 // namespace PorkPatrol