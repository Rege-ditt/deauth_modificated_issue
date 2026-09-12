#include "handshake_capture.h"

// ========== ГЛОБАЛЬНІ ЗМІННІ ==========
bool pcap_initialized = false;
File pcap_file;
uint32_t eapol_count = 0;

// Додатково для діагностики
void printPCAPStatus() {
    Serial.printf("[PCAP] Status: initialized=%d, frames=%u, filesize=%u bytes\n", 
                  pcap_initialized, eapol_count, getPCAPFileSize());
}