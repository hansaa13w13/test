// AP+STA Captive Portal — RTL8720dn (AmebaD)
// GÜNCELLEME: IP Kilitlenmesini Önleyen Non-Destructive Soft-Switch Mimarisi

#include "WiFi.h"
#include "WiFiServer.h"
#include "WiFiClient.h"
#include "DNSServer.h"
#include "FlashMemory.h"
#include "wifi_conf.h"
#include "wifi_structures.h"
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "vector"
#include "lwip/netif.h"

#ifndef ENC_TYPE_TKIP
#define ENC_TYPE_TKIP  2
#endif
#ifndef ENC_TYPE_CCMP
#define ENC_TYPE_CCMP  4
#endif

extern "C" {
  extern struct netif xnetif[];
  void dhcps_init(struct netif *pnetif);
  void dhcps_deinit(void);
  int  LwIP_DHCP(uint8_t idx, uint8_t action);
  int  wext_set_mode(const char *ifname, int mode);
  int  wifi_disconnect(void);
  void LwIP_Init(void);
}

#define DHCP_START   1
#define DHCP_STOP    0
#define IW_MODE_INFRA 2
#define WLAN0_NAME   "wlan0"

// ─── AP Ayarları ─────────────────────────────────────────────────────────────
#define AP_INITIAL_SSID  "X"
#define AP_INITIAL_PASS  "20192019"
#define AP_IP_ADDR       "192.168.4.1"
#define SERVER_PORT      80

// ─── Flash & Hafıza Ayarları ─────────────────────────────────────────────────
#define FLASH_MAGIC_NUM  0xA1
#define MAX_SSID_LEN     64
#define MAX_PASS_LEN     64
#define FLASH_BUF_SIZE   256

struct SavedCredentials {
  uint8_t magic;
  char    ssid[MAX_SSID_LEN];
  char    pass[MAX_PASS_LEN];
};

SavedCredentials creds;

struct NetworkInfo {
  String  ssid;
  int32_t rssi;
  uint8_t enc;
  int32_t channel; 
};

typedef enum { CS_IDLE = 0, CS_RUNNING = 1, CS_DONE_OK = 2, CS_DONE_FAIL = 3 } ConnStatus;
volatile ConnStatus conn_status = CS_IDLE;

typedef enum { SCAN_IDLE = 0, SCAN_RUNNING = 1, SCAN_DONE = 2 } ScanStatus;
volatile ScanStatus scan_status = SCAN_IDLE;

// ─── Global Değişkenler ──────────────────────────────────────────────────────
bool ap_switched = false;
bool pending_ap_switch = false;
char target_ssid[MAX_SSID_LEN] = {0};
int32_t target_channel = 6;
uint8_t target_enc = ENC_TYPE_CCMP;

WiFiServer server(SERVER_PORT);
DNSServer  dnsServer;
std::vector<NetworkInfo> networks;
SemaphoreHandle_t networks_mutex;

char saved_ssid[MAX_SSID_LEN]   = {0};
char saved_pass[MAX_PASS_LEN]   = {0};
char pending_ssid[MAX_SSID_LEN] = {0};
char pending_pass[MAX_PASS_LEN] = {0};
uint8_t pending_enc             = ENC_TYPE_CCMP;
bool sta_connected  = false;
String conn_result  = "";

unsigned long last_scan_ms = 0;
#define RESCAN_INTERVAL_MS  30000UL

// ─── URL Decode ──────────────────────────────────────────────────────────────
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

// ─── Flash İşlemleri ─────────────────────────────────────────────────────────
void loadCredentials() {
  FlashMemory.read();
  memcpy(&creds, FlashMemory.buf, sizeof(creds));
  if (creds.magic == FLASH_MAGIC_NUM) {
    strncpy(saved_ssid, creds.ssid, MAX_SSID_LEN - 1);
    strncpy(saved_pass, creds.pass, MAX_PASS_LEN - 1);
  } else {
    memset(&creds, 0, sizeof(creds));
    creds.magic = FLASH_MAGIC_NUM;
  }
}

void saveCredentials(const char *ssid, const char *pass) {
  strncpy(creds.ssid, ssid, MAX_SSID_LEN - 1);
  strncpy(creds.pass, pass, MAX_PASS_LEN - 1);
  memcpy(FlashMemory.buf, &creds, sizeof(creds));
  FlashMemory.update();
}

// ─── Şifreleme Eşleme ────────────────────────────────────────────────────────
rtw_security_t mapSecurity(uint8_t enc) {
  switch (enc) {
    case ENC_TYPE_NONE: return RTW_SECURITY_OPEN;
    case ENC_TYPE_WEP:  return RTW_SECURITY_WEP_PSK;
    case ENC_TYPE_TKIP: return RTW_SECURITY_WPA_TKIP_PSK;
    default:            return RTW_SECURITY_WPA2_AES_PSK;
  }
}

// ─── Arka Plan Wi-Fi Tarama Görevi ───────────────────────────────────────────
static std::vector<NetworkInfo> scan_temp;
SemaphoreHandle_t raw_scan_sem = NULL;

rtw_result_t raw_scan_handler(rtw_scan_handler_result_t *malloced_scan_result) {
  if (malloced_scan_result->scan_complete != RTW_TRUE) {
    rtw_scan_result_t *record = &malloced_scan_result->ap_details;
    NetworkInfo net;
    char ssid_str[33] = {0};
    memcpy(ssid_str, record->SSID.val, record->SSID.len);
    net.ssid = String(ssid_str);
    net.rssi = record->signal_strength;
    net.channel = record->channel; 
    
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
  if (scan_status == SCAN_RUNNING || conn_status == CS_RUNNING) return;
  scan_status = SCAN_RUNNING;
  xTaskCreate(scanNetworkTask, "scan", 4096, NULL, tskIDLE_PRIORITY + 1, NULL);
}

// ─── Arka Plan İstasyon Bağlantı Görevi ──────────────────────────────────────
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
    LwIP_DHCP(0, DHCP_START);
    vTaskDelay(pdMS_TO_TICKS(3000));
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

// ─── Görsel Yardımcılar ──────────────────────────────────────────────────────
String rssiBar(int32_t rssi) {
  if (rssi > -50) return "&#9608;&#9608;&#9608;&#9608; Mukemmel";
  if (rssi > -65) return "&#9608;&#9608;&#9608;&#9617; Iyi";
  if (rssi > -75) return "&#9608;&#9608;&#9617;&#9617; Orta";
  return "&#9608;&#9617;&#9617;&#9617; Zayif";
}

String buildRedirect() {
  return String("HTTP/1.1 302 Found\r\nLocation: http://") + AP_IP_ADDR + "/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
}

String parsePostParam(const String &body, const String &key) {
  int idx = body.indexOf(key + "=");
  if (idx == -1) return "";
  int start = idx + key.length() + 1;
  int end   = body.indexOf('&', start);
  if (end == -1) end = body.length();
  return urlDecode(body.substring(start, end));
}

// ─── Arayüz CSS Tasarımı ─────────────────────────────────────────────────────
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

// ─── SAYFALAR ────────────────────────────────────────────────────────────────
void sendStartPage(WiFiClient &client) {
  client.print("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n");
  client.print("<!DOCTYPE html><html lang='tr'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Guvenli Kurulum - Ag Secimi</title>");
  client.print(CSS_STR);
  client.print("</head><body><div class='card'><h1>&#128274; Guvenli Kurulum</h1><p class='sub'>Lutfen hedef aginizi listeden secin</p>");

  if (scan_status == SCAN_RUNNING) client.print("<div class='status-box wait'>&#128225; Çevredeki ağlar aranıyor...</div>");

  if (networks_mutex) xSemaphoreTake(networks_mutex, portMAX_DELAY);
  client.print("<h2>&#128225; Kullanilabilir Aglar ("); client.print(networks.size()); client.print(")</h2><form method='POST' action='/start_ap'><ul class='net-list'>");

  for (int i = 0; i < (int)networks.size(); i++) {
    String safe = networks[i].ssid;
    safe.replace("&", "&amp;"); safe.replace("<", "&lt;"); safe.replace("'", "&#39;"); safe.replace("\"", "&quot;");
    client.print("<li class='net-item' onclick=\"document.getElementById('r"); client.print(i); client.print("').checked=true\"><input type='radio' name='ssid' id='r"); client.print(i);
    client.print("' value='"); client.print(safe); client.print("' required><div class='net-info'><div class='net-name'>"); client.print(safe);
    client.print("</div><div class='net-meta'>"); client.print(rssiBar(networks[i].rssi)); client.print(" &nbsp;|&nbsp; Kanal: "); client.print(networks[i].channel); client.print("</div></div></li>");
  }
  if (networks.empty() && scan_status != SCAN_RUNNING) client.print("<li style='padding:16px;text-align:center;color:#aaa;'>Ag bulunamadi.</li>");
  if (networks_mutex) xSemaphoreGive(networks_mutex);

  client.print("</ul><button type='submit'>Kurulumu Baslat</button></form>");
  client.print("<form method='POST' action='/rescan'><button type='submit' class='btn-blue'>&#8635; Yeniden Ara</button></form><div class='footer'>Mevcut Yonetim Agi: X</div></div></body></html>");
}

void sendSwitchingPage(WiFiClient &client) {
  client.print("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nConnection: close\r\n\r\n");
  client.print("<!DOCTYPE html><html lang='tr'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Ag Klonlaniyor</title><style>body{font-family:Arial,sans-serif;background:#1a1a2e;color:#eee;text-align:center;padding:50px 20px;} b{color:#e94560;}</style></head><body>");
  client.print("<h2 style='color:#e94560;'>&#128225; Ag Degistiriliyor...</h2><p style='color:#aaa;font-size:18px;margin-top:20px;line-height:1.6'>Islem tamamlandi! Lutfen Wi-Fi ayarlariniza gidin ve yeni acilan <b>sifresiz</b> <br><br><b style='font-size:24px;'>");
  client.print(target_ssid);
  client.print("</b><br><br>agina baglanin.</p></body></html>");
}

void sendPortalPage(WiFiClient &client, bool show_result) {
  client.print("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n");
  client.print("<!DOCTYPE html><html lang='tr'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>WiFi Sifre Onayi</title>");
  client.print(CSS_STR);
  client.print("</head><body><div class='card'><h1>&#128273; WiFi Sifre Dogrulamasi</h1><p class='sub'>Lutfen taklit edilen bu agin gercek anahtarini girin</p>");

  if (conn_status == CS_RUNNING) client.print("<div class='status-box wait'><span class='spinner'></span>Istasyona Baglaniliyor...</div>");
  else if (show_result) {
    if (conn_result == "ok") client.print("<div class='status-box ok'>&#10003; Baglanti basarili! Kurulum tamamlandi.</div>");
    else if (conn_result == "fail") client.print("<div class='status-box err'>&#10007; Baglanti basarisiz. Sifreyi kontrol edin.</div>");
  }

  client.print("<div class='conn-status'>Secilen Baglanti Agi: <b>"); client.print(target_ssid);
  client.print("</b><br><small style='color:#aaa'>Frekans Eslemesi (Kanal): "); client.print(target_channel); client.print("</small></div>");
  client.print("<form method='POST' action='/connect'><div class='pass-wrap'><label for='pass'>Sifre Giriniz</label><input type='password' id='pass' name='pass' placeholder='Sifreyi buraya yazin...' autocomplete='off' required><div class='show-pass' onclick=\"var p=document.getElementById('pass');p.type=p.type=='password'?'text':'password'\">&#128065; Goster/Gizle</div></div><button type='submit'>&#128273; Onayla ve Baglan</button></form>");
  
  if (conn_status == CS_RUNNING) client.print("<script>function tryR(){fetch('/',{cache:'no-store',signal:AbortSignal.timeout(3000)}).then(function(r){if(r.ok){window.location.href='/';}else{setTimeout(tryR,2000);}}).catch(function(){setTimeout(tryR,2000);});}setTimeout(tryR,3000);</script>");
  client.print("<div class='footer'>Hedef Maskeleme Aktif</div></div></body></html>");
}

// ─── HTTP İstek İşleyicisi ───────────────────────────────────────────────────
void handleClient(WiFiClient &client) {
  unsigned long timeout = millis() + 3000;
  String request = ""; request.reserve(512);

  while (client.connected() && millis() < timeout) {
    if (client.available()) { char c = client.read(); request += c; if (request.endsWith("\r\n\r\n")) break; } else delay(1);
  }
  if (request.length() == 0) return;

  String body = ""; int content_len = 0; int cl_idx = request.indexOf("Content-Length: ");
  if (cl_idx != -1) content_len = request.substring(cl_idx + 16, request.indexOf("\r\n", cl_idx)).toInt();
  if (content_len > 0) {
    body.reserve(content_len); int br = 0; timeout = millis() + 2000;
    while (br < content_len && millis() < timeout) { if (client.available()) { body += (char)client.read(); br++; } else delay(1); }
  }

  String path = "";
  int ps = request.indexOf(' ') + 1; int pe = request.indexOf(' ', ps);
  if (ps > 0 && pe > ps) path = request.substring(ps, pe);
  if (path.indexOf('?') != -1) path = path.substring(0, path.indexOf('?'));

  String hostHeader = ""; int hi = request.indexOf("Host: ");
  if (hi != -1) {
    hostHeader = request.substring(hi + 6, request.indexOf("\r\n", hi + 6)); hostHeader.trim();
    if (hostHeader.indexOf(':') != -1) hostHeader = hostHeader.substring(0, hostHeader.indexOf(':'));
  }

  bool path_is_captive = path.indexOf("hotspot-detect") != -1 || path.indexOf("generate_204") != -1 || path.indexOf("redirect") != -1;
  bool host_is_foreign = (hostHeader.length() > 0 && hostHeader != AP_IP_ADDR);

  if (path_is_captive || host_is_foreign) { client.print(buildRedirect()); return; }

  // ─── AŞAMA 1 (Şifreli X Ağı) YÖNETİMİ ───
  if (!ap_switched) {
    if (request.startsWith("POST") && path == "/rescan") {
      if (scan_status != SCAN_RUNNING) startScan();
      sendStartPage(client); return;
    }
    if (request.startsWith("POST") && path == "/start_ap") {
      String sel_ssid = parsePostParam(body, "ssid");
      if (sel_ssid.length() == 0) { sendStartPage(client); return; }
      
      strncpy(target_ssid, sel_ssid.c_str(), MAX_SSID_LEN - 1);
      target_channel = 6; target_enc = ENC_TYPE_CCMP;
      
      if (networks_mutex) xSemaphoreTake(networks_mutex, portMAX_DELAY);
      for (auto &net : networks) {
        if (net.ssid == sel_ssid) { target_channel = net.channel; target_enc = net.enc; break; }
      }
      if (networks_mutex) xSemaphoreGive(networks_mutex);
      
      if (target_channel <= 0 || target_channel > 13) target_channel = 6;

      // Ekrana geçiş yapılıyor sayfasını gönder
      sendSwitchingPage(client);
      
      // Döngü içerisinde arka planda ağ geçişini tetikle
      pending_ap_switch = true; 
      return;
    }
    sendStartPage(client); return;
  }

  // ─── AŞAMA 2 (Açık İkiz Ağ) YÖNETİMİ ───
  if (request.startsWith("POST") && path == "/connect") {
    if (conn_status == CS_RUNNING) { sendPortalPage(client, false); return; }
    String sel_pass = parsePostParam(body, "pass");
    strncpy(pending_ssid, target_ssid, MAX_SSID_LEN - 1);
    strncpy(pending_pass, sel_pass.c_str(), MAX_PASS_LEN - 1);
    pending_enc = target_enc;
    
    conn_result = "";
    startConnectTask();
    sendPortalPage(client, false); return;
  }

  sendPortalPage(client, conn_result.length() > 0);
}

// ─── Setup ───────────────────────────────────────────────────────────────────
void setup() {
  Serial.begin(115200); delay(500);
  Serial.println("\n[Boot] Cihaz Aciliyor (Non-Destructive AP Switch Mode)");

  networks_mutex = xSemaphoreCreateMutex();
  FlashMemory.begin(0x00, FLASH_BUF_SIZE);
  loadCredentials();
  
  LwIP_Init();
  wifi_on(RTW_MODE_STA_AP); delay(500);

  ap_switched = false;
  Serial.println("[Boot] X Agi (Kurulum) Baslatiliyor.");
  wifi_start_ap((char *)AP_INITIAL_SSID, RTW_SECURITY_WPA2_AES_PSK, (char *)AP_INITIAL_PASS, strlen(AP_INITIAL_SSID), strlen(AP_INITIAL_PASS), 6);

  ip4_addr_t ip, mask, gw;
  IP4_ADDR(&ip,   192, 168, 4, 1);
  IP4_ADDR(&mask, 255, 255, 255, 0);
  IP4_ADDR(&gw,   192, 168, 4, 1);
  netif_set_addr(&xnetif[1], &ip, &mask, &gw);
  netif_set_up(&xnetif[1]); 
  netif_set_link_up(&xnetif[1]);
  
  // DHCP IP Dağıtıcısını Cihaz Açıldığında SADECE 1 KERE Başlatıyoruz!
  dhcps_init(&xnetif[1]); delay(500);
  
  server.begin();
  dnsServer.setResolvedIP(192, 168, 4, 1);
  dnsServer.begin();
  
  startScan();

  if (strlen(saved_ssid) > 0) {
    strncpy(pending_ssid, saved_ssid, MAX_SSID_LEN - 1);
    strncpy(pending_pass, saved_pass, MAX_PASS_LEN - 1);
    pending_enc = ENC_TYPE_CCMP;
    startConnectTask();
  }
}

// ─── Loop ────────────────────────────────────────────────────────────────────
void loop() {
  // DINAMIK AG GECIS TETIKLEYICISI
  if (pending_ap_switch) {
    pending_ap_switch = false;
    ap_switched = true;
    
    delay(1500); // İstemciye HTML yanıtının ulaşması için kısa bekleme

    Serial.println("\n[Switch] Dinamik Ag Gecisi Basliyor...");
    
    // 1. DİKKAT: DHCP, IP ve LwIP SERVİSLERİNE KESİNLİKLE DOKUNULMUYOR!
    // Sadece Wi-Fi donanımını kısaca kapatıp (STA moduna alıp) açarak WPA2 hafızasını uçuruyoruz.
    wifi_set_mode(RTW_MODE_STA);
    delay(1000);

    // AP modunu taze şekilde geri açıyoruz
    wifi_set_mode(RTW_MODE_STA_AP);
    delay(1000);

    Serial.print("[Switch] Yeni Sifresiz Ag Aciliyor: "); Serial.println(target_ssid);
    
    // 2. KESİN ŞİFRESİZ YAYIN BAŞLAT (Burada boşluk "" yerine NULL kullanılması Realtek için ŞARTTIR)
    wifi_start_ap((char *)target_ssid, RTW_SECURITY_OPEN, NULL, strlen(target_ssid), 0, target_channel);
    delay(1500);

    // 3. Wi-Fi donanımı kapanıp açıldığı için ağ arabirimini uyanık tutmaya zorluyoruz
    // (Böylece IP dağıtıcı soketler çalışmaya devam eder)
    netif_set_up(&xnetif[1]); 
    netif_set_link_up(&xnetif[1]);

    Serial.println("[Switch] Islem Tamam! Kilitlenme onlendi ve IP dagitimi suruyor.");
  }

  if (scan_status == SCAN_DONE) scan_status = SCAN_IDLE;

  if (conn_status == CS_DONE_OK) {
    sta_connected = true;
    strncpy(saved_ssid, pending_ssid, MAX_SSID_LEN - 1);
    strncpy(saved_pass, pending_pass, MAX_PASS_LEN - 1);
    saveCredentials(saved_ssid, saved_pass);
    conn_result = "ok"; conn_status = CS_IDLE;
  } else if (conn_status == CS_DONE_FAIL) {
    sta_connected = false; conn_result = "fail"; conn_status = CS_IDLE;
  }

  if (conn_status == CS_IDLE && scan_status == SCAN_IDLE && !ap_switched && (millis() - last_scan_ms > RESCAN_INTERVAL_MS)) {
    startScan();
  }

  WiFiClient client = server.available();
  if (client) { handleClient(client); client.stop(); }
  delay(1);
}