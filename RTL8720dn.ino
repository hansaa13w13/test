// AP+STA Captive Portal — RTL8720dn (AmebaD)
// BUG FIX v2:
//   1. scanNetworks() artık FreeRTOS arka plan görevi — loop() hiç bloklanmaz
//   2. handleClient() busy-wait döngülerine delay(1) eklendi — TCP stack starvation önlendi
//   3. buildPortalPage() büyük tek String yerine çoklu client.print() ile chunk gönderim
//   4. Tüm busy-wait döngülerinde yield/delay eklendi
//   5. lwIP stack manuel başlatıldı (Soket ve udp_new hatalarını çözer)
//   6. FreeRTOS Mutex eklendi (Tarama ve web sunucusu eşzamanlı çakışmalarını önler)

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
  void LwIP_Init(void); // EKSİK OLAN LWIP BAŞLATMA FONKSİYONU
}

#define DHCP_START   1
#define DHCP_STOP    0
#define IW_MODE_INFRA 2
#define WLAN0_NAME   "wlan0"

// ─── AP Ayarları ─────────────────────────────────────────────────────────────
#define AP_SSID          "WiFi-Setup"
#define AP_IP_ADDR       "192.168.4.1"
#define SERVER_PORT      80

// ─── Flash ───────────────────────────────────────────────────────────────────
#define FLASH_MAGIC      0xAB
#define MAX_SSID_LEN     64
#define MAX_PASS_LEN     64
#define FLASH_BUF_SIZE   256

struct SavedCredentials {
  uint8_t magic;
  char    ssid[MAX_SSID_LEN];
  char    pass[MAX_PASS_LEN];
};

struct NetworkInfo {
  String  ssid;
  int32_t rssi;
  uint8_t enc;
};

typedef enum { CS_IDLE = 0, CS_RUNNING = 1, CS_DONE_OK = 2, CS_DONE_FAIL = 3 } ConnStatus;
volatile ConnStatus conn_status = CS_IDLE;

typedef enum { SCAN_IDLE = 0, SCAN_RUNNING = 1, SCAN_DONE = 2 } ScanStatus;
volatile ScanStatus scan_status = SCAN_IDLE;

WiFiServer server(SERVER_PORT);
DNSServer  dnsServer;
std::vector<NetworkInfo> networks;

// Eşzamanlı okuma/yazma çakışmalarını (crash) önlemek için Mutex
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
    if (input[i] == '+') {
      output += ' ';
    } else if (input[i] == '%' && i + 2 < (int)input.length()) {
      char hex[3] = { input[i + 1], input[i + 2], 0 };
      output += (char)strtol(hex, nullptr, 16);
      i += 2;
    } else {
      output += input[i];
    }
  }
  return output;
}

// ─── Flash ───────────────────────────────────────────────────────────────────
void loadCredentials() {
  FlashMemory.read();
  SavedCredentials creds;
  memcpy(&creds, FlashMemory.buf, sizeof(creds));
  if (creds.magic == FLASH_MAGIC && creds.ssid[0] != 0) {
    strncpy(saved_ssid, creds.ssid, MAX_SSID_LEN - 1);
    strncpy(saved_pass, creds.pass, MAX_PASS_LEN - 1);
    Serial.print("[Flash] Kayitli: "); Serial.println(saved_ssid);
  } else {
    Serial.println("[Flash] Bilgi yok.");
  }
}

void saveCredentials(const char *ssid, const char *pass) {
  SavedCredentials creds;
  creds.magic = FLASH_MAGIC;
  memset(creds.ssid, 0, MAX_SSID_LEN);
  memset(creds.pass, 0, MAX_PASS_LEN);
  strncpy(creds.ssid, ssid, MAX_SSID_LEN - 1);
  strncpy(creds.pass, pass, MAX_PASS_LEN - 1);
  memcpy(FlashMemory.buf, &creds, sizeof(creds));
  FlashMemory.update();
  Serial.print("[Flash] Kaydedildi: "); Serial.println(ssid);
}

// ─── Şifreleme ───────────────────────────────────────────────────────────────
rtw_security_t mapSecurity(uint8_t enc) {
  switch (enc) {
    case ENC_TYPE_NONE: return RTW_SECURITY_OPEN;
    case ENC_TYPE_WEP:  return RTW_SECURITY_WEP_PSK;
    case ENC_TYPE_TKIP: return RTW_SECURITY_WPA_TKIP_PSK;
    default:            return RTW_SECURITY_WPA2_AES_PSK;
  }
}

// ─── BUG FIX #1: Tarama FreeRTOS Arka Plan Görevi ───────────────────────────
static std::vector<NetworkInfo> scan_temp;

void scanNetworkTask(void *param) {
  (void)param;
  scan_temp.clear();
  int n = WiFi.scanNetworks();
  for (int i = 0; i < n; i++) {
    NetworkInfo net;
    net.ssid = WiFi.SSID(i);
    net.rssi = WiFi.RSSI(i);
    net.enc  = WiFi.encryptionType(i);
    scan_temp.push_back(net);
  }
  
  // Atomik kopyalama: Mutex ile korundu
  if (networks_mutex) {
    xSemaphoreTake(networks_mutex, portMAX_DELAY);
    networks = scan_temp;
    xSemaphoreGive(networks_mutex);
  }
  
  scan_temp.clear();
  last_scan_ms = millis();
  Serial.print("[Scan] Ag sayisi: "); Serial.println(n);
  scan_status = SCAN_DONE;
  vTaskDelete(NULL);
}

void startScan() {
  if (scan_status == SCAN_RUNNING) return;
  if (conn_status == CS_RUNNING) return;
  scan_status = SCAN_RUNNING;
  xTaskCreate(scanNetworkTask, "scan", 4096, NULL, tskIDLE_PRIORITY + 1, NULL);
}

// ─── FreeRTOS: Bağlantı Görevi ───────────────────────────────────────────────
void wifiConnectTask(void *param) {
  (void)param;

  bool is_open = (mapSecurity(pending_enc) == RTW_SECURITY_OPEN);
  int  pass_len = is_open ? 0 : (int)strlen(pending_pass);

  rtw_security_t try_sec[] = {
    mapSecurity(pending_enc),
    RTW_SECURITY_WPA2_AES_PSK,
    RTW_SECURITY_WPA2_MIXED_PSK,
#ifdef RTW_SECURITY_WPA3_AES_PSK
    RTW_SECURITY_WPA3_AES_PSK,
#endif
  };
  int try_count = is_open ? 1 : (int)(sizeof(try_sec) / sizeof(try_sec[0]));

  Serial.print("[Task] Baslaniyor: "); Serial.println(pending_ssid);

  int ret = RTW_ERROR;
  for (int t = 0; t < try_count; t++) {
    bool dup = false;
    for (int j = 0; j < t; j++) {
      if (try_sec[j] == try_sec[t]) { dup = true; break; }
    }
    if (dup) continue;

    Serial.print("[Task] Deneme "); Serial.print(t + 1);
    Serial.print(" sec=");
    Serial.println((int)try_sec[t]);

    wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(300));

    int mode_ret = wext_set_mode(WLAN0_NAME, IW_MODE_INFRA);
    Serial.print("[Task] wext_set_mode ret="); Serial.println(mode_ret);
    vTaskDelay(pdMS_TO_TICKS(200));
    
    ret = wifi_connect(
      (char *)pending_ssid,
      try_sec[t],
      (char *)pending_pass,
      (int)strlen(pending_ssid),
      pass_len,
      -1,
      NULL
    );
    Serial.print("[Task] wifi_connect ret="); Serial.println(ret);

    if (ret == RTW_SUCCESS) {
      vTaskDelay(pdMS_TO_TICKS(500));
      if (wifi_is_connected_to_ap() == RTW_SUCCESS) {
        Serial.println("[Task] Baglanti dogrulandi.");
        break;
      } else {
        Serial.println("[Task] wifi_connect OK ama is_connected FAIL.");
        ret = RTW_ERROR;
      }
    }

    if (t < try_count - 1) vTaskDelay(pdMS_TO_TICKS(2000));
  }

  if (ret == RTW_SUCCESS) {
    Serial.println("[Task] DHCP baslatiliyor (WLAN0)...");
    LwIP_DHCP(0, DHCP_START);
    vTaskDelay(pdMS_TO_TICKS(3000));
    Serial.println("[Task] STA OK — AP HALA AYAKTA.");
    conn_status = CS_DONE_OK;
  } else {
    Serial.println("[Task] STA FAIL.");
    conn_status = CS_DONE_FAIL;
  }

  vTaskDelete(NULL);
}

void startConnectTask() {
  if (conn_status == CS_RUNNING) return;
  conn_status = CS_RUNNING;
  xTaskCreate(wifiConnectTask, "wconn", 8192, NULL, tskIDLE_PRIORITY + 2, NULL);
}

// ─── RSSI / Enc Etiketleri ───────────────────────────────────────────────────
String rssiBar(int32_t rssi) {
  if (rssi > -50) return "&#9608;&#9608;&#9608;&#9608; Mukemmel";
  if (rssi > -65) return "&#9608;&#9608;&#9608;&#9617; Iyi";
  if (rssi > -75) return "&#9608;&#9608;&#9617;&#9617; Orta";
  if (rssi > -85) return "&#9608;&#9617;&#9617;&#9617; Zayif";
  return "&#9617;&#9617;&#9617;&#9617; Cok Zayif";
}

String encLabel(uint8_t enc) {
  if (enc == ENC_TYPE_NONE) return "<span style='color:#27ae60'>Acik</span>";
  return "<span style='color:#e67e22'>Sifreli</span>";
}

// ─── Captive Portal Yönlendirme ──────────────────────────────────────────────
String buildRedirect() {
  String r = "HTTP/1.1 302 Found\r\nLocation: http://";
  r += AP_IP_ADDR;
  r += "/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
  return r;
}

// ─── POST Parametre Ayrıştır ─────────────────────────────────────────────────
String parsePostParam(const String &body, const String &key) {
  int idx = body.indexOf(key + "=");
  if (idx == -1) return "";
  int start = idx + key.length() + 1;
  int end   = body.indexOf('&', start);
  if (end == -1) end = body.length();
  return urlDecode(body.substring(start, end));
}

// ─── HTTP Chunk Yanıt Gönderimi ──────────────────────────────────────────────
static const char CSS_STR[] PROGMEM =
  "<style>"
  "*{box-sizing:border-box;margin:0;padding:0}"
  "body{font-family:Arial,sans-serif;background:#1a1a2e;color:#eee;"
       "min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}"
  ".card{background:#16213e;border-radius:14px;padding:24px;width:100%;"
  "max-width:500px;box-shadow:0 8px 32px rgba(0,0,0,.4)}"
  "h1{font-size:1.4rem;color:#e94560;text-align:center;margin-bottom:6px}"
  ".sub{text-align:center;font-size:.85rem;color:#aaa;margin-bottom:20px}"
  ".status-box{border-radius:8px;padding:10px 14px;margin-bottom:18px;"
  "font-size:.9rem;font-weight:bold}"
  ".ok{background:#0a3d2e;border:1px solid #27ae60;color:#2ecc71}"
  ".err{background:#3d0a0a;border:1px solid #e74c3c;color:#e74c3c}"
  ".wait{background:#0a2040;border:1px solid #3498db;color:#5dade2}"
  ".conn-status{border-radius:8px;padding:8px 14px;margin-bottom:16px;"
  "font-size:.85rem;background:#0d1b2e;border:1px solid #2980b9}"
  "h2{font-size:1rem;color:#ccc;margin-bottom:10px;"
      "border-bottom:1px solid #2c3e50;padding-bottom:6px}"
  ".net-list{list-style:none;margin-bottom:18px;max-height:280px;overflow-y:auto}"
  ".net-item{display:flex;align-items:center;padding:10px 12px;border-radius:8px;"
             "margin-bottom:6px;cursor:pointer;border:2px solid transparent;"
  "background:#0f3460;transition:border-color .2s}"
  ".net-item:hover{border-color:#e94560}"
  ".net-item input[type=radio]{margin-right:10px;accent-color:#e94560;"
                                "width:18px;height:18px;flex-shrink:0}"
  ".net-info{flex:1;min-width:0}"
  ".net-name{font-weight:bold;font-size:.95rem;overflow:hidden;"
  "text-overflow:ellipsis;white-space:nowrap}"
  ".net-meta{font-size:.75rem;color:#aaa;margin-top:2px}"
  ".pass-wrap{margin-bottom:16px}"
  "label{display:block;font-size:.85rem;color:#aaa;margin-bottom:6px}"
  "input[type=password],input[type=text]{width:100%;padding:10px 12px;"
  "border-radius:7px;border:1px solid #2c3e50;background:#0d1b2e;"
  "color:#eee;font-size:.95rem;outline:none}"
  "input:focus{border-color:#e94560}"
  ".show-pass{font-size:.8rem;color:#aaa;margin-top:6px;cursor:pointer;user-select:none}"
  "button{width:100%;padding:13px;border:none;border-radius:8px;"
  "background:#e94560;color:#fff;font-size:1rem;font-weight:bold;"
          "cursor:pointer;margin-bottom:10px}"
  ".btn-blue{background:#2980b9}"
  ".spinner{display:inline-block;width:16px;height:16px;"
            "border:3px solid #5dade2;border-top:3px solid transparent;"
            "border-radius:50%;animation:spin 1s linear infinite;"
  "vertical-align:middle;margin-right:6px}"
  "@keyframes spin{to{transform:rotate(360deg)}}"
  ".footer{text-align:center;font-size:.75rem;color:#555;margin-top:8px}"
  "</style>";

void sendPortalPage(WiFiClient &client, bool show_result) {
  client.print("HTTP/1.1 200 OK\r\n"
               "Content-Type: text/html; charset=UTF-8\r\n"
               "Cache-Control: no-store\r\n"
               "Connection: close\r\n\r\n");

  client.print("<!DOCTYPE html><html lang='tr'><head>"
               "<meta charset='UTF-8'>"
               "<meta name='viewport' content='width=device-width,initial-scale=1'>"
               "<title>WiFi Kurulum</title>");
  client.print(CSS_STR);
  client.print("</head><body><div class='card'>"
               "<h1>&#128268; WiFi Kurulum</h1>"
               "<p class='sub'>Agi secin, sifreyi girin</p>");

  if (conn_status == CS_RUNNING) {
    client.print("<div class='status-box wait'>"
                 "<span class='spinner'></span>Baglaniliyor...</div>");
  } else if (show_result) {
    if (conn_result == "ok") {
      client.print("<div class='status-box ok'>&#10003; Baglanti basarili!</div>");
    } else if (conn_result == "fail") {
      client.print("<div class='status-box err'>&#10007; Basarisiz. Sifre yanlis veya ag yok.</div>");
    }
  }

  if (scan_status == SCAN_RUNNING) {
    client.print("<div class='status-box wait'>&#128225; Aglar taranıyor...</div>");
  }

  if (sta_connected && strlen(saved_ssid) > 0) {
    client.print("<div class='conn-status'>&#128994; Bagli: <b>");
    client.print(saved_ssid);
    client.print("</b></div>");
  }

  // Mutex ile güvenli döngü erişimi
  if (networks_mutex) xSemaphoreTake(networks_mutex, portMAX_DELAY);
  
  client.print("<h2>&#128225; WiFi Aglari (");
  client.print(networks.size());
  client.print(")</h2><form method='POST' action='/connect'><ul class='net-list'>");
  
  for (int i = 0; i < (int)networks.size(); i++) {
    String safe = networks[i].ssid;
    safe.replace("&", "&amp;");
    safe.replace("<", "&lt;");
    safe.replace("'", "&#39;"); safe.replace("\"", "&quot;");

    client.print("<li class='net-item' onclick=\"document.getElementById('r");
    client.print(i);
    client.print("').checked=true\"><input type='radio' name='ssid' id='r");
    client.print(i);
    client.print("' value='");
    client.print(safe);
    client.print("'");
    if (networks[i].ssid == String(saved_ssid)) client.print(" checked");
    client.print("><div class='net-info'><div class='net-name'>");
    client.print(safe);
    client.print("</div><div class='net-meta'>");
    client.print(rssiBar(networks[i].rssi));
    client.print(" &nbsp;|&nbsp; ");
    client.print(encLabel(networks[i].enc));
    client.print(" &nbsp;|&nbsp; ");
    client.print(networks[i].rssi);
    client.print(" dBm</div></div></li>");
  }

  if (networks.empty()) {
    client.print("<li style='padding:16px;text-align:center;color:#aaa;'>Ag bulunamadi.</li>");
  }
  
  if (networks_mutex) xSemaphoreGive(networks_mutex);

  client.print("</ul><div class='pass-wrap'><label for='pass'>WiFi Sifresi</label>"
               "<input type='password' id='pass' name='pass' "
               "placeholder='Sifreyi girin...' autocomplete='off'>"
               "<div class='show-pass' onclick=\"var p=document.getElementById('pass');"
               "p.type=p.type=='password'?'text':'password'\">&#128065; Goster/Gizle</div>"
               "</div><button type='submit'>&#128273; Baglan ve Kaydet</button></form>");

  client.print("<form method='POST' action='/rescan'>"
               "<button type='submit' class='btn-blue'>&#8635; Aglari Yenile</button></form>");

  if (conn_status == CS_RUNNING) {
    client.print("<script>"
                 "function tryR(){"
                   "fetch('/',{cache:'no-store',signal:AbortSignal.timeout(3000)})"
                   ".then(function(r){if(r.ok){window.location.href='/';}"
                   "else{setTimeout(tryR,2000);}}).catch(function(){setTimeout(tryR,2000);});}"
                 "setTimeout(tryR,3000);"
                 "</script>");
  }

  client.print("<div class='footer'>AP: WiFi-Setup &bull; Hic kapanmaz</div>"
               "</div></body></html>");
}

// ─── HTTP İstemci Yöneticisi ─────────────────────────────────────────────────
void handleClient(WiFiClient &client) {
  unsigned long timeout = millis() + 3000;
  String request = "";
  request.reserve(512);

  while (client.connected() && millis() < timeout) {
    if (client.available()) {
      char c = client.read();
      request += c;
      if (request.endsWith("\r\n\r\n")) break;
    } else {
      delay(1);
    }
  }
  if (request.length() == 0) return;

  String body = "";
  int content_len = 0;
  int cl_idx = request.indexOf("Content-Length: ");
  if (cl_idx != -1) {
    int cl_end = request.indexOf("\r\n", cl_idx);
    content_len = request.substring(cl_idx + 16, cl_end).toInt();
    if (content_len > 256) content_len = 256;
  }
  
  if (content_len > 0) {
    body.reserve(content_len);
    int br = 0;
    timeout = millis() + 2000;
    while (br < content_len && millis() < timeout) {
      if (client.available()) {
        body += (char)client.read();
        br++;
      } else {
        delay(1);
      }
    }
  }

  String path = "";
  int ps = request.indexOf(' ') + 1;
  int pe = request.indexOf(' ', ps);
  if (ps > 0 && pe > ps) path = request.substring(ps, pe);
  int qm = path.indexOf('?');
  if (qm != -1) path = path.substring(0, qm);

  String hostHeader = "";
  {
    int hi = request.indexOf("Host: ");
    if (hi != -1) {
      int he = request.indexOf("\r\n", hi + 6);
      hostHeader = request.substring(hi + 6, he);
      hostHeader.trim();
      int cp = hostHeader.indexOf(':');
      if (cp != -1) hostHeader = hostHeader.substring(0, cp);
    }
  }

  Serial.print("[HTTP] ");
  if (request.startsWith("POST")) Serial.print("POST "); else Serial.print("GET  ");
  Serial.print(path);
  Serial.print(" Host="); Serial.println(hostHeader);

  bool path_is_captive =
    path.indexOf("hotspot-detect") != -1 ||
    path.indexOf("generate_204")   != -1 ||
    path.indexOf("ncsi.txt")       != -1 ||
    path.indexOf("success.txt")    != -1 ||
    path.indexOf("connecttest")    != -1 || path.indexOf("canonical.html") != -1 ||
    path.indexOf("redirect")       != -1 ||
    path.indexOf("portal")         != -1;
  
  bool host_is_foreign = (hostHeader.length() > 0 && hostHeader != AP_IP_ADDR);

  if (path_is_captive || host_is_foreign) {
    client.print(buildRedirect());
    Serial.print("[Captive] Redirect -> "); Serial.println(AP_IP_ADDR);
    return;
  }

  if (request.startsWith("POST") && path == "/connect") {
    if (conn_status == CS_RUNNING) {
      sendPortalPage(client, false);
      return;
    }
    String sel_ssid = parsePostParam(body, "ssid");
    String sel_pass = parsePostParam(body, "pass");
    
    if (sel_ssid.length() == 0) {
      conn_result = "fail";
      sendPortalPage(client, true); return;
    }
    
    strncpy(pending_ssid, sel_ssid.c_str(), MAX_SSID_LEN - 1);
    pending_ssid[MAX_SSID_LEN - 1] = '\0';
    strncpy(pending_pass, sel_pass.c_str(), MAX_PASS_LEN - 1);
    pending_pass[MAX_PASS_LEN - 1] = '\0';
    
    pending_enc = ENC_TYPE_CCMP;
    
    if (networks_mutex) xSemaphoreTake(networks_mutex, portMAX_DELAY);
    for (auto &net : networks) {
      if (net.ssid == sel_ssid) { pending_enc = net.enc; break; }
    }
    if (networks_mutex) xSemaphoreGive(networks_mutex);
    
    conn_result = "";
    startConnectTask();
    sendPortalPage(client, false);
    return;
  }

  if (request.startsWith("POST") && path == "/rescan") {
    if (conn_status != CS_RUNNING && scan_status != SCAN_RUNNING) {
      startScan();
      conn_result = "";
    }
    sendPortalPage(client, false); return;
  }

  sendPortalPage(client, conn_result.length() > 0);
}

// ─── Setup ───────────────────────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("\n[Boot] Captive Portal — AP hic kapanmaz");

  networks_mutex = xSemaphoreCreateMutex();

  FlashMemory.begin(0x00, FLASH_BUF_SIZE);
  loadCredentials();
  
  // ÖNEMLİ DÜZELTME: LwIP Stack başlatılıyor!
  LwIP_Init();
  
  // Adım 1: STA+AP modu
  wifi_on(RTW_MODE_STA_AP);
  delay(500);

  // Adım 2: AP başlat (WLAN1)
  int ap_ret = wifi_start_ap(
    (char *)AP_SSID,
    RTW_SECURITY_OPEN,
    NULL,
    (int)strlen(AP_SSID),
    0,
    6
  );
  Serial.print("[AP] wifi_start_ap ret="); Serial.println(ap_ret);
  delay(1000);

  // Adım 3: WLAN1'e statik IP ata
  {
    ip4_addr_t ip, mask, gw;
    IP4_ADDR(&ip,   192, 168, 4, 1);
    IP4_ADDR(&mask, 255, 255, 255, 0);
    IP4_ADDR(&gw,   192, 168, 4, 1);
    netif_set_addr(&xnetif[1], &ip, &mask, &gw);
    netif_set_up(&xnetif[1]);
    netif_set_link_up(&xnetif[1]);
    Serial.println("[AP] WLAN1 IP: 192.168.4.1");
  }
  delay(1000);

  // Adım 4: DHCP sunucusu
  dhcps_init(&xnetif[1]);
  delay(1000);
  Serial.println("[AP] DHCP server WLAN1'de baslatildi.");

  // Adım 5: HTTP sunucusu başlat
  delay(500);
  server.begin();
  Serial.println("[Server] Port 80 hazir.");

  // Adım 6: DNS sunucusu
  dnsServer.setResolvedIP(192, 168, 4, 1);
  dnsServer.begin();
  
  // Adım 7: İlk taramayı arka planda başlat
  startScan();
  
  // Adım 8: Kayıtlı ağa bağlan
  if (strlen(saved_ssid) > 0) {
    strncpy(pending_ssid, saved_ssid, MAX_SSID_LEN - 1);
    strncpy(pending_pass, saved_pass, MAX_PASS_LEN - 1);
    pending_enc = ENC_TYPE_CCMP;
    Serial.print("[STA] Arka plan gorevi: "); Serial.println(saved_ssid);
    startConnectTask();
  }

  Serial.println("[Hazir] http://192.168.4.1");
}

// ─── Loop ────────────────────────────────────────────────────────────────────
void loop() {
  if (scan_status == SCAN_DONE) {
    scan_status = SCAN_IDLE;
  }

  if (conn_status == CS_DONE_OK) {
    sta_connected = true;
    strncpy(saved_ssid, pending_ssid, MAX_SSID_LEN - 1);
    strncpy(saved_pass, pending_pass, MAX_PASS_LEN - 1);
    saveCredentials(saved_ssid, saved_pass);
    conn_result = "ok";
    conn_status = CS_IDLE;
    Serial.print("[OK] Baglandi: "); Serial.println(saved_ssid);
    Serial.print("[OK] STA IP  : "); Serial.println(WiFi.localIP());
  } else if (conn_status == CS_DONE_FAIL) {
    sta_connected = false;
    conn_result = "fail";
    conn_status = CS_IDLE;
    Serial.println("[FAIL] Baglanamadi.");
  }

  if (conn_status == CS_IDLE &&
      scan_status == SCAN_IDLE &&
      millis() - last_scan_ms > RESCAN_INTERVAL_MS) {
    startScan();
  }

  if (conn_status == CS_IDLE && sta_connected &&
      wifi_is_connected_to_ap() != RTW_SUCCESS) {
    Serial.println("[STA] Kesildi, yeniden baslatiliyor...");
    sta_connected = false;
    if (strlen(saved_ssid) > 0) {
      strncpy(pending_ssid, saved_ssid, MAX_SSID_LEN - 1);
      strncpy(pending_pass, saved_pass, MAX_PASS_LEN - 1);
      pending_enc = ENC_TYPE_CCMP;
      startConnectTask();
    }
  }

  WiFiClient client = server.available();
  if (client) {
    handleClient(client);
    client.stop();
  }

  delay(1);
}