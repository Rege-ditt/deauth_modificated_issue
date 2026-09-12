#ifndef HANDSHAKE_CAPTURE_H
#define HANDSHAKE_CAPTURE_H

#include "FS.h"
#include "LittleFS.h"

// ========== ГЛОБАЛЬНІ ЗМІННІ ==========
extern bool pcap_initialized;
extern File pcap_file;
extern uint32_t eapol_count;

// PCAP Global Header (24 bytes)
const uint8_t PCAP_GLOBAL_HEADER[24] = {
  0xd4, 0xc3, 0xb2, 0xa1, // magic number
  0x02, 0x00,             // version major
  0x04, 0x00,             // version minor
  0x00, 0x00, 0x00, 0x00, // timezone offset
  0x00, 0x00, 0x00, 0x00, // timestamp accuracy
  0xff, 0xff, 0x00, 0x00, // snaplen
  0x7f, 0x00, 0x00, 0x00  // network type (DLT_IEEE802_11)
};

// ========== ФУНКЦІЇ ==========

// Ініціалізація PCAP файлу
inline void initPCAP() {
  if (!LittleFS.begin()) {
    Serial.println("LittleFS failed!");
    return;
  }
  
  pcap_file = LittleFS.open("/handshakes.pcap", "w");
  if (!pcap_file) {
    Serial.println("Failed to create PCAP file");
    return;
  }
  
  pcap_file.write(PCAP_GLOBAL_HEADER, 24);
  pcap_initialized = true;
  eapol_count = 0;
  Serial.println("[PCAP] File initialized!");
}

// Швидка перевірка EAPOL БЕЗ затримок
inline bool isEAPOL(uint8_t *buf, uint16_t len) {
  // Безпосередньо перевіряємо байти БЕЗ розгалужень
  return (len > 25 && buf[24] == 0x88 && buf[25] == 0x8e);
}

// Оптимізований запис БЕЗ flush на кожен пакет
inline void saveToPCAP(uint8_t *buf, uint16_t len) {
  if (!pcap_initialized || !pcap_file) return;
  
  // Миттєвий запис без перевірок
  uint32_t ts_sec = (uint32_t)(millis() / 1000);
  uint32_t ts_usec = (uint32_t)((millis() % 1000) * 1000);
  uint32_t incl_len = len;
  uint32_t orig_len = len;
  
  pcap_file.write((uint8_t*)&ts_sec, 4);
  pcap_file.write((uint8_t*)&ts_usec, 4);
  pcap_file.write((uint8_t*)&incl_len, 4);
  pcap_file.write((uint8_t*)&orig_len, 4);
  pcap_file.write(buf, len);
  
  eapol_count++;
  
  // Flush тільки кожні 10 пакетів, щоб не гальмувати
  if (eapol_count % 10 == 0) {
    pcap_file.flush();
  }
}

// Закриття з обов'язковим flush
inline void closePCAP() {
  if (pcap_file) {
    pcap_file.flush();
    pcap_file.close();
    pcap_initialized = false;
    Serial.printf("[PCAP] Saved %u EAPOL frames\n", eapol_count);
  }
}

// Отримання розміру
inline size_t getPCAPFileSize() {
  File f = LittleFS.open("/handshakes.pcap", "r");
  if (!f) return 0;
  size_t size = f.size();
  f.close();
  return size;
}

#endif