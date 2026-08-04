// flock_signatures.h
// ---------------------------------------------------------------------------
// Signature data tables for passive surveillance-device detection.
//
// This is a clean-room, original implementation written for M5PORKCHOP (MIT).
// The *signature data* below (OUIs, BLE manufacturer IDs, service UUIDs) is
// crowdsourced / research-derived fact, not copied source. Attribution:
//   - OUI list & addr1 receiver technique .... @NitekryDPaul, DeFlockJoplin
//   - 31st OUI (82:6B:F2) ...................... DeFlockJoplin
//   - BLE manufacturer ID 0x09C8 (XUNTONG) .... @wgreenberg's research
//   - Raven BLE service UUIDs .................. deflock.me / community datasets
//   - Crowdsourced camera locations ........... deflock.me (FoggedLens/deflock)
//
// NOTE: Before shipping, pull the *complete* 31-OUI table and the Raven
// service-UUID values from the authoritative deflock.me dataset and confirm
// that dataset's license permits redistribution. The table below intentionally
// contains only the OUIs explicitly documented in public writeups, each tagged
// with a vendor class so the detector can weight them correctly.
// ---------------------------------------------------------------------------
#pragma once
#include <stdint.h>

namespace flockdet {

// How trustworthy a given OUI is on its own.
//   GENERIC_ESP  -> matches ANY Espressif device (incl. the Cardputer itself!).
//                   Weak signal. Must be corroborated before alerting.
//   FLOCK_LINKED -> OUI observed specifically in Flock deployments and not a
//                   generic vendor block. Stronger signal.
enum class OuiClass : uint8_t {
    GENERIC_ESP  = 0,
    FLOCK_LINKED = 1,
};

struct OuiEntry {
    uint8_t  oui[3];      // first three bytes of the MAC (big-endian, as on air)
    OuiClass cls;
    const char* note;
};

// Only OUIs with public documentation are included. Extend from the
// deflock.me dataset (with attribution) via community PRs.
static const OuiEntry kFlockOuis[] = {
    { {0xD4, 0xAD, 0xFC}, OuiClass::GENERIC_ESP,  "Espressif ESP32-S3"     },
    { {0xAC, 0x67, 0xB2}, OuiClass::GENERIC_ESP,  "Espressif ESP32-WROOM"  },
    { {0x84, 0xF3, 0xEB}, OuiClass::GENERIC_ESP,  "Espressif ESP32-S3 var" },
    { {0xB4, 0xE6, 0x2D}, OuiClass::GENERIC_ESP,  "Espressif ESP32-C3"     },
    { {0xCC, 0xDB, 0xA7}, OuiClass::GENERIC_ESP,  "Espressif"              },
    { {0x82, 0x6B, 0xF2}, OuiClass::FLOCK_LINKED, "DeFlockJoplin 31st OUI" },
    // TODO(community): append remaining OUIs from the deflock.me 31-OUI set.
};
static const uint8_t kFlockOuiCount = sizeof(kFlockOuis) / sizeof(kFlockOuis[0]);

// ---- BLE signatures -------------------------------------------------------

// Manufacturer-specific data company identifier (little-endian on air).
// 0x09C8 == XUNTONG, observed in Flock/Raven BLE advertisements.
static const uint16_t kFlockBleCompanyId = 0x09C8;

// BLE advertised-name substrings worth flagging (case-insensitive match).
static const char* const kFlockBleNameHints[] = {
    "flock",
    "raven",
    "falcon",   // common Flock camera model family
};
static const uint8_t kFlockBleNameHintCount =
    sizeof(kFlockBleNameHints) / sizeof(kFlockBleNameHints[0]);

// Raven (SoundThinking/ShotSpotter) BLE service UUIDs.
// Populate the 128-bit values from the community raven_configurations.json
// (fw 1.1.7 / 1.2.0 / 1.3.1). Left empty here rather than fabricated.
struct BleServiceUuid128 { uint8_t bytes[16]; const char* note; };
static const BleServiceUuid128 kRavenServiceUuids[] = {
    // { { /* 16 bytes, MSB..LSB */ }, "Raven fw1.3.1 svc" },
};
static const uint8_t kRavenServiceUuidCount =
    sizeof(kRavenServiceUuids) / sizeof(kRavenServiceUuids[0]);

} // namespace flockdet
