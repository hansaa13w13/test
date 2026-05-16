// AP+STA Captive Portal — RTL8720dn (AmebaD)
// wifi_connect() FREERTOS ARKA PLAN GÖREVİ olarak çalışır.
// Ana loop() hiç bloklanmaz → AP + HTTP sunucusu her zaman aktif kalır.

#include "WiFi.h"
#include "WiFiServer.h"
#include "WiFiClient.h"
#include "DNSServer.h"
#include "FlashMemory.h"
#include "wifi_conf.h"
#include "wifi_structures.h"
#include "FreeRTOS.h"
#include "task.h"
#include "vector"
#include "lwip/netif.h"    // struct netif, netif_set_addr, IP4_ADDR

// AmebaD 3.1.7 eksik enc sabitleri
#ifndef ENC_TYPE_TKIP
#define ENC_TYPE_TKIP  2
#endif
#ifndef ENC_TYPE_CCMP
#define ENC_TYPE_CCMP  4
#endif

// ─── Gerçek Concurrent Mode — WLAN0=STA, WLAN1=AP ───────────────────────────
// WiFi.apbegin() AP'yi her zaman WLAN0'a kurar. wifi_connect() da WLAN0 kullanır
// → çakışma → AP ölür. Çözüm: AP'yi WLAN1'e kur, wifi_connect() WLAN0'ı kullansın.
//
// Realtek AmebaD SDK fonksiyonları:
//   xnetif[]         : lwIP netif dizisi  [0]=WLAN0/STA, [1]=WLAN1/AP
//   dhcps_init()     : belirtilen netif üzerinde DHCP sunucusu başlatır
//   dhcps_deinit()   : mevcut DHCP sunucusunu durdurur
//   wifi_start_ap()  : wifi_conf.h'da tanımlı, AP beacon'larını başlatır
extern "C" {
  extern struct netif xnetif[];           // [0]=WLAN0/STA  [1]=WLAN1/AP
  void dhcps_init(struct netif *pnetif);  // Realtek DHCP server başlat
  void dhcps_deinit(void);               // Realtek DHCP server durdur
  int  LwIP_DHCP(uint8_t idx, uint8_t action); // STA DHCP istemcisi (0=WLAN0)

  // Concurrent mode STA bağlantısı için kritik:
  //   wext_set_mode → WLAN0'ı açıkça STA (infrastructure) moduna alır.
  //   Tarama sonrası WLAN0 belirsiz modda kalır; bu çağrı olmadan
  //   wifi_connect() çoğunlukla başarısız olur.
  int  wext_set_mode(const char *ifname, int mode);

  // Her yeni bağlantı denemesi öncesi temiz slate için:
  int  wifi_disconnect(void);
}

#define DHCP_START   1
#define DHCP_STOP    0
#define IW_MODE_INFRA 2        // Linux wireless ext: infrastructure (STA) modu
#define WLAN0_NAME   "wlan0"   // AmebaD STA arayüz adı


// ─── AP Ayarları ─────────────────────────────────────────────────────────────
#define AP_SSID          "WiFi-Setup"
#define AP_CHANNEL_STR   "6"
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

// ─── Ağ Yapısı ───────────────────────────────────────────────────────────────
struct NetworkInfo {
  String  ssid;
  int32_t rssi;
  uint8_t enc;
};

// ─── Bağlantı Durumu (volatile — FreeRTOS görevinden yazılır) ────────────────
typedef enum { CS_IDLE = 0, CS_RUNNING = 1, CS_DONE_OK = 2, CS_DONE_FAIL = 3 } ConnStatus;
volatile ConnStatus conn_status = CS_IDLE;

// ─── Global Değişkenler ──────────────────────────────────────────────────────
WiFiServer server(SERVER_PORT);
DNSServer  dnsServer;
std::vector<NetworkInfo> networks;

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

// ─── Flash: Yükle / Kaydet ───────────────────────────────────────────────────
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

// ─── Şifreleme Eşleştirme ────────────────────────────────────────────────────
rtw_security_t mapSecurity(uint8_t enc) {
  switch (enc) {
    case ENC_TYPE_NONE: return RTW_SECURITY_OPEN;
    case ENC_TYPE_WEP:  return RTW_SECURITY_WEP_PSK;
    case ENC_TYPE_TKIP: return RTW_SECURITY_WPA_TKIP_PSK;
    default:            return RTW_SECURITY_WPA2_AES_PSK;
  }
}

// ─── FreeRTOS: Arka Plan Bağlantı Görevi ────────────────────────────────────
// AP WLAN1'de kurulu — wifi_connect() sadece WLAN0'ı kullanır, AP dokunulmaz.
//
// CONCURRENT MODE BAĞLANTI SIRASI (AmebaD SDK zorunluluğu):
//   1. wifi_disconnect()              → önceki association temizle
//   2. wext_set_mode(wlan0, STA)      → WLAN0'ı açıkça STA moduna al
//      * Tarama sonrası WLAN0 belirsiz modda kalır; bu adım atlanırsa
//        wifi_connect() çoğunlukla başarısız olur (en sık kök neden).
//   3. vTaskDelay(200ms)              → mod değişikliğinin settle etmesi için
//   4. wifi_connect(...)              → bağlan
//   5. LwIP_DHCP(0, DHCP_START)      → WLAN0'a IP ata (otomatik atanmaz)
void wifiConnectTask(void *param) {
  (void)param;

  bool is_open = (mapSecurity(pending_enc) == RTW_SECURITY_OPEN);
  int  pass_len = is_open ? 0 : (int)strlen(pending_pass);

  // Güvenlik türü deneme sırası — önce tespit edilen, sonra geniş uyumluluk
  // WPA3: bazı SDK sürümlerinde RTW_SECURITY_WPA3_AES_PSK mevcut olmayabilir,
  // ifdef ile korunuyor.
  rtw_security_t try_sec[] = {
    mapSecurity(pending_enc),    // 1. Taramanın tespit ettiği
    RTW_SECURITY_WPA2_AES_PSK,   // 2. WPA2 AES (en yaygın)
    RTW_SECURITY_WPA2_MIXED_PSK, // 3. WPA2 AES+TKIP karma
#ifdef RTW_SECURITY_WPA3_AES_PSK
    RTW_SECURITY_WPA3_AES_PSK,   // 4. WPA3 (modern router)
#endif
  };
  int try_count = is_open ? 1 : (int)(sizeof(try_sec) / sizeof(try_sec[0]));

  Serial.print("[Task] Baslaniyor: "); Serial.println(pending_ssid);
  Serial.print("[Task] pass_len="); Serial.print(pass_len);
  Serial.print(" enc="); Serial.println((int)pending_enc);

  int ret = RTW_ERROR;

  for (int t = 0; t < try_count; t++) {
    // Aynı güvenlik türünü tekrar deneme
    bool dup = false;
    for (int j = 0; j < t; j++) {
      if (try_sec[j] == try_sec[t]) { dup = true; break; }
    }
    if (dup) continue;

    Serial.print("[Task] --- Deneme "); Serial.print(t + 1);
    Serial.print(" sec="); Serial.println((int)try_sec[t]);

    // Adım 1: Önceki bağlantıyı temizle
    wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(300));

    // Adım 2: WLAN0'ı açıkça STA (infrastructure) moduna al
    // Bu adım concurrent mode'da wifi_connect() başarısı için kritik!
    int mode_ret = wext_set_mode(WLAN0_NAME, IW_MODE_INFRA);
    Serial.print("[Task] wext_set_mode ret="); Serial.println(mode_ret);
    vTaskDelay(pdMS_TO_TICKS(200)); // mod settle etsin

    // Adım 3: Bağlan
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
      // Gerçekten bağlandı mı doğrula
      vTaskDelay(pdMS_TO_TICKS(500));
      if (wifi_is_connected_to_ap() == RTW_SUCCESS) {
        Serial.println("[Task] Baglanti dogrulandi.");
        break;
      } else {
        Serial.println("[Task] wifi_connect OK ama is_connected FAIL, tekrar denenecek.");
        ret = RTW_ERROR;
      }
    }

    if (t < try_count - 1) vTaskDelay(pdMS_TO_TICKS(2000));
  }

  if (ret == RTW_SUCCESS) {
    // WLAN0 üzerinde DHCP istemcisini başlat → STA IP adresi alır
    // wifi_connect() başarılı olsa bile IP otomatik atanmaz!
    Serial.println("[Task] DHCP baslatiliyor (WLAN0)...");
    LwIP_DHCP(0, DHCP_START);
    vTaskDelay(pdMS_TO_TICKS(3000)); // DHCP sunucusundan IP alınması için bekle
    Serial.println("[Task] STA OK — AP HALA AYAKTA.");
    conn_status = CS_DONE_OK;
  } else {
    Serial.println("[Task] STA FAIL — tum denemeler basarisiz.");
    conn_status = CS_DONE_FAIL;
  }

  vTaskDelete(NULL);
}

// ─── Bağlantı Başlat ─────────────────────────────────────────────────────────
void startConnectTask() {
  if (conn_status == CS_RUNNING) return;
  conn_status = CS_RUNNING;
  xTaskCreate(
    wifiConnectTask,   // Görev fonksiyonu
    "wconn",           // İsim
    8192,              // Stack boyutu — wifi_connect() + LwIP_DHCP için yeterli
    NULL,              // Parametre
    tskIDLE_PRIORITY + 2,
    NULL               // Task handle (kullanmıyoruz)
  );
}

// ─── WiFi Tarama ─────────────────────────────────────────────────────────────
void scanNetworks() {
  if (conn_status == CS_RUNNING) return;
  networks.clear();
  int n = WiFi.scanNetworks();
  for (int i = 0; i < n; i++) {
    NetworkInfo net;
    net.ssid = WiFi.SSID(i);
    net.rssi = WiFi.RSSI(i);
    net.enc  = WiFi.encryptionType(i);
    networks.push_back(net);
  }
  last_scan_ms = millis();
  Serial.print("[Scan] Ag: "); Serial.println(n);
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

// ─── Ortak CSS ───────────────────────────────────────────────────────────────
String buildCSS() {
  return "<style>"
    "*{box-sizing:border-box;margin:0;padding:0}"
    "body{font-family:Arial,sans-serif;background:#1a1a2e;color:#eee;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}"
    ".card{background:#16213e;border-radius:14px;padding:24px;width:100%;max-width:500px;box-shadow:0 8px 32px rgba(0,0,0,.4)}"
    "h1{font-size:1.4rem;color:#e94560;text-align:center;margin-bottom:6px}"
    ".sub{text-align:center;font-size:.85rem;color:#aaa;margin-bottom:20px}"
    ".status-box{border-radius:8px;padding:10px 14px;margin-bottom:18px;font-size:.9rem;font-weight:bold}"
    ".ok{background:#0a3d2e;border:1px solid #27ae60;color:#2ecc71}"
    ".err{background:#3d0a0a;border:1px solid #e74c3c;color:#e74c3c}"
    ".wait{background:#0a2040;border:1px solid #3498db;color:#5dade2}"
    ".conn-status{border-radius:8px;padding:8px 14px;margin-bottom:16px;font-size:.85rem;background:#0d1b2e;border:1px solid #2980b9}"
    "h2{font-size:1rem;color:#ccc;margin-bottom:10px;border-bottom:1px solid #2c3e50;padding-bottom:6px}"
    ".net-list{list-style:none;margin-bottom:18px;max-height:280px;overflow-y:auto}"
    ".net-item{display:flex;align-items:center;padding:10px 12px;border-radius:8px;margin-bottom:6px;cursor:pointer;border:2px solid transparent;background:#0f3460;transition:border-color .2s}"
    ".net-item:hover{border-color:#e94560}"
    ".net-item input[type=radio]{margin-right:10px;accent-color:#e94560;width:18px;height:18px;flex-shrink:0}"
    ".net-info{flex:1;min-width:0}"
    ".net-name{font-weight:bold;font-size:.95rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}"
    ".net-meta{font-size:.75rem;color:#aaa;margin-top:2px}"
    ".pass-wrap{margin-bottom:16px}"
    "label{display:block;font-size:.85rem;color:#aaa;margin-bottom:6px}"
    "input[type=password],input[type=text]{width:100%;padding:10px 12px;border-radius:7px;border:1px solid #2c3e50;background:#0d1b2e;color:#eee;font-size:.95rem;outline:none}"
    "input:focus{border-color:#e94560}"
    ".show-pass{font-size:.8rem;color:#aaa;margin-top:6px;cursor:pointer;user-select:none}"
    "button{width:100%;padding:13px;border:none;border-radius:8px;background:#e94560;color:#fff;font-size:1rem;font-weight:bold;cursor:pointer;margin-bottom:10px}"
    ".btn-blue{background:#2980b9}"
    ".spinner{display:inline-block;width:16px;height:16px;border:3px solid #5dade2;border-top:3px solid transparent;border-radius:50%;animation:spin 1s linear infinite;vertical-align:middle;margin-right:6px}"
    "@keyframes spin{to{transform:rotate(360deg)}}"
    ".footer{text-align:center;font-size:.75rem;color:#555;margin-top:8px}"
    "</style>";
}

// ─── Portal Sayfası ──────────────────────────────────────────────────────────
String buildPortalPage(bool show_result) {
  String html = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
  html += "<!DOCTYPE html><html lang='tr'><head><meta charset='UTF-8'>"
          "<meta name='viewport' content='width=device-width,initial-scale=1'>"
          "<title>WiFi Kurulum</title>";
  html += buildCSS();
  html += "</head><body><div class='card'>"
          "<h1>&#128268; WiFi Kurulum</h1>"
          "<p class='sub'>Agi secin, sifreyi girin</p>";

  if (conn_status == CS_RUNNING) {
    html += "<div class='status-box wait'><span class='spinner'></span>Baglaniliyor...</div>";
  } else if (show_result) {
    if (conn_result == "ok") {
      html += "<div class='status-box ok'>&#10003; Baglanti basarili! Sifre kaydedildi.</div>";
    } else if (conn_result == "fail") {
      html += "<div class='status-box err'>&#10007; Basarisiz. Sifre yanlis veya ag yok.</div>";
    }
  }

  if (sta_connected && strlen(saved_ssid) > 0) {
    html += "<div class='conn-status'>&#128994; Bagli: <b>";
    html += String(saved_ssid);
    html += "</b></div>";
  }

  html += "<h2>&#128225; WiFi Aglari (";
  html += String(networks.size());
  html += ")</h2><form method='POST' action='/connect'><ul class='net-list'>";

  for (int i = 0; i < (int)networks.size(); i++) {
    String safe = networks[i].ssid;
    safe.replace("&","&amp;"); safe.replace("<","&lt;");
    safe.replace("'","&#39;"); safe.replace("\"","&quot;");
    html += "<li class='net-item' onclick=\"document.getElementById('r"; html += String(i); html += "').checked=true\">";
    html += "<input type='radio' name='ssid' id='r"; html += String(i); html += "' value='"; html += safe; html += "'";
    if (networks[i].ssid == String(saved_ssid)) html += " checked";
    html += "><div class='net-info'><div class='net-name'>"; html += safe; html += "</div>";
    html += "<div class='net-meta'>"; html += rssiBar(networks[i].rssi);
    html += " &nbsp;|&nbsp; "; html += encLabel(networks[i].enc);
    html += " &nbsp;|&nbsp; "; html += String(networks[i].rssi); html += " dBm";
    html += "</div></div></li>";
  }

  if (networks.empty()) {
    html += "<li style='padding:16px;text-align:center;color:#aaa;'>Ag bulunamadi.</li>";
  }

  html += "</ul><div class='pass-wrap'><label for='pass'>WiFi Sifresi</label>"
          "<input type='password' id='pass' name='pass' placeholder='Sifreyi girin...' autocomplete='off'>"
          "<div class='show-pass' onclick=\"var p=document.getElementById('pass');p.type=p.type=='password'?'text':'password'\">&#128065; Goster/Gizle</div>"
          "</div><button type='submit'>&#128273; Baglan ve Kaydet</button></form>";

  html += "<form method='POST' action='/rescan'>"
          "<button type='submit' class='btn-blue'>&#8635; Aglari Yenile</button></form>";

  // Bağlanılıyor ise: AP kapanıp açılana kadar 2s'de bir dene (retry loop)
  // Tek seferlik reload AP kapalıyken çakışır → "bu siteye ulaşılamıyor"
  // fetch() başarısız olursa 2s sonra tekrar dener, AP gelince sayfayı yükler
  if (conn_status == CS_RUNNING) {
    html += "<script>"
            "function tryR(){"
              "fetch('/',{cache:'no-store',signal:AbortSignal.timeout(3000)})"
              ".then(function(r){if(r.ok){window.location.href='/';}"
              "else{setTimeout(tryR,2000);}}).catch(function(){setTimeout(tryR,2000);});}"
            "setTimeout(tryR,3000);"
            "</script>";
  }

  html += "<div class='footer'>AP: WiFi-Setup &bull; Hic kapanmaz</div></div></body></html>";
  return html;
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

// ─── HTTP İstek Yöneticisi ───────────────────────────────────────────────────
void handleClient(WiFiClient &client) {
  unsigned long timeout = millis() + 3000;
  String request = "";
  while (client.connected() && millis() < timeout) {
    if (client.available()) {
      char c = client.read();
      request += c;
      if (request.endsWith("\r\n\r\n")) break;
    }
  }
  if (request.length() == 0) return;

  String body = "";
  int content_len = 0;
  int cl_idx = request.indexOf("Content-Length: ");
  if (cl_idx != -1) {
    int cl_end = request.indexOf("\r\n", cl_idx);
    content_len = request.substring(cl_idx + 16, cl_end).toInt();
  }
  if (content_len > 0) {
    int br = 0;
    timeout = millis() + 2000;
    while (br < content_len && millis() < timeout) {
      if (client.available()) { body += (char)client.read(); br++; }
    }
  }

  String path = "";
  int ps = request.indexOf(' ') + 1;
  int pe = request.indexOf(' ', ps);
  if (ps > 0 && pe > ps) path = request.substring(ps, pe);
  int qm = path.indexOf('?');
  if (qm != -1) path = path.substring(0, qm);

  // Host başlığını oku
  String hostHeader = "";
  {
    int hi = request.indexOf("Host: ");
    if (hi != -1) {
      int he = request.indexOf("\r\n", hi + 6);
      hostHeader = request.substring(hi + 6, he);
      hostHeader.trim();
      // Port varsa kaldır (:80 gibi)
      int cp = hostHeader.indexOf(':');
      if (cp != -1) hostHeader = hostHeader.substring(0, cp);
    }
  }

  Serial.print("[HTTP] ");
  if (request.startsWith("POST")) Serial.print("POST "); else Serial.print("GET  ");
  Serial.print(path);
  Serial.print(" Host="); Serial.println(hostHeader);

  // Captive portal tespiti:
  //   1) Bilinen kontrol URL'leri (path bazlı)
  //   2) Host, AP IP'sine gitmiyorsa → büyük olasılıkla captive portal kontrolü
  bool path_is_captive =
    path.indexOf("hotspot-detect") != -1 || path.indexOf("generate_204")   != -1 ||
    path.indexOf("ncsi.txt")       != -1 || path.indexOf("success.txt")    != -1 ||
    path.indexOf("connecttest")    != -1 || path.indexOf("canonical.html") != -1 ||
    path.indexOf("redirect")       != -1 || path.indexOf("portal")         != -1;

  bool host_is_foreign = (hostHeader.length() > 0 && hostHeader != AP_IP_ADDR);

  if (path_is_captive || host_is_foreign) {
    // iOS: captive.apple.com/hotspot-detect.html — boş HTML döndürünce popup açar
    // Android: generate_204 — 302 alınca captive portal bildirimi çıkar
    // Windows: ncsi.txt / connecttest.txt — redirect görünce portal popup açar
    client.print(buildRedirect());
    Serial.print("[Captive] Redirect -> "); Serial.println(AP_IP_ADDR);
    return;
  }

  // POST /connect — görevi başlat, hemen cevap ver, loop() hiç durmaz
  if (request.startsWith("POST") && path == "/connect") {
    if (conn_status == CS_RUNNING) {
      client.print(buildPortalPage(false)); return;
    }
    String sel_ssid = parsePostParam(body, "ssid");
    String sel_pass = parsePostParam(body, "pass");
    if (sel_ssid.length() == 0) {
      conn_result = "fail";
      client.print(buildPortalPage(true)); return;
    }
    strncpy(pending_ssid, sel_ssid.c_str(), MAX_SSID_LEN - 1);
    strncpy(pending_pass, sel_pass.c_str(), MAX_PASS_LEN - 1);
    pending_enc = ENC_TYPE_CCMP;
    for (auto &net : networks) {
      if (net.ssid == sel_ssid) { pending_enc = net.enc; break; }
    }
    conn_result = "";
    startConnectTask();  // ← Arka plan görevi başlatılır, bu satır anında döner
    client.print(buildPortalPage(false));
    return;
  }

  // POST /rescan
  if (request.startsWith("POST") && path == "/rescan") {
    if (conn_status != CS_RUNNING) { scanNetworks(); conn_result = ""; }
    client.print(buildPortalPage(false)); return;
  }

  // GET /
  client.print(buildPortalPage(conn_result.length() > 0));
}

// ─── Setup ───────────────────────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("\n[Boot] Captive Portal — AP hic kapanmaz, FreeRTOS STA");

  FlashMemory.begin(0x00, FLASH_BUF_SIZE);
  loadCredentials();

  // ── Gerçek Concurrent AP+STA — AP ASLA KAPANMAZ ────────────────────────────
  //
  // WLAN0 = STA arayüzü  (router'a bağlanmak için)
  // WLAN1 = AP arayüzü   (telefona servis vermek için)
  //
  // YANLIŞ yol: WiFi.apbegin() → AP WLAN0'a kurulur.
  //             wifi_connect() → WLAN0'ı STA için kullanır → AP ölür.
  //
  // DOĞRU yol:
  //   1. wifi_on(STA_AP)      → her iki arayüz hazır, WLAN0=STA, WLAN1=AP
  //   2. wifi_start_ap()      → AP beacon'ları WLAN1'de başlar
  //   3. netif_set_addr()     → WLAN1'e 192.168.4.1 IP'si atanır
  //   4. dhcps_init(xnetif[1])→ DHCP sunucusu WLAN1'de başlar
  //   5. wifi_connect()       → YALNIZCA WLAN0 kullanır, WLAN1 dokunulmaz

  // Adım 1: STA+AP modunu başlat
  wifi_on(RTW_MODE_STA_AP);
  delay(500);

  // Adım 2: AP beacon'larını WLAN1'de başlat (wifi_start_ap STA_AP modunda WLAN1'i kullanır)
  // Güvenlik: RTW_SECURITY_OPEN (şifresiz), kanal: 6
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

  // Adım 3: WLAN1 (AP arayüzü) için statik IP ata — 192.168.4.1
  {
    ip4_addr_t ip, mask, gw;
    IP4_ADDR(&ip,   192, 168, 4, 1);
    IP4_ADDR(&mask, 255, 255, 255, 0);
    IP4_ADDR(&gw,   192, 168, 4, 1);
    netif_set_addr(&xnetif[1], &ip, &mask, &gw);
    // netif_set_up  : "admin up" — arayüz yönetimsel olarak aktif
    // netif_set_link_up : "link up" — fiziksel bağlantı aktif
    // Her ikisi de gerekli; sadece birisi DHCP server'ın çalışması için yetmez.
    netif_set_up(&xnetif[1]);
    netif_set_link_up(&xnetif[1]);
    Serial.println("[AP] WLAN1 IP: 192.168.4.1 (netif up + link up)");
  }

  // Adım 4: DHCP sunucusunu WLAN1'de başlat
  // NOT: dhcps_deinit() burada ÇAĞRILMIYOR — ilk boot'ta çalışan sunucu yok,
  // dhcps_deinit() NULL pointer erişimi yaparak watchdog reset'e yol açabilir.
  // dhcps_init() zaten önceki başlatılmamış durumu handle eder.
  dhcps_init(&xnetif[1]);
  delay(500);
  Serial.println("[AP] DHCP server WLAN1'de baslatildi.");

  Serial.print("[AP] SSID: "); Serial.println(AP_SSID);
  Serial.print("[AP] IP  : "); Serial.println(AP_IP_ADDR);

  scanNetworks();

  // Kayıtlı ağa arka planda bağlan
  if (strlen(saved_ssid) > 0) {
    strncpy(pending_ssid, saved_ssid, MAX_SSID_LEN - 1);
    strncpy(pending_pass, saved_pass, MAX_PASS_LEN - 1);
    pending_enc = ENC_TYPE_CCMP;
    Serial.print("[STA] Arka plan gorevi baslatiliyor: "); Serial.println(saved_ssid);
    startConnectTask();
  }

  server.begin();
  Serial.println("[Server] Port 80 hazir.");

  // DNS sunucusu başlat — tüm hostname sorgularını 192.168.4.1'e yönlendirir
  // Bu olmadan telefon captive.apple.com / connectivitycheck.gstatic.com'u çözemez
  // → captive portal popup açılmaz.
  // lwIP native udp_pcb kullanır (WiFiUDP wrapper'ından çok daha güvenilir AmebaD'de)
  dnsServer.setResolvedIP(192, 168, 4, 1);
  dnsServer.begin();
  Serial.println("[DNS] Port 53 hazir (lwIP native).");

  Serial.println("[Hazir] http://192.168.4.1");
}

// ─── Loop ────────────────────────────────────────────────────────────────────
void loop() {
  // Arka plan görevinin sonucunu kontrol et
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

  // Periyodik tarama
  if (conn_status == CS_IDLE && millis() - last_scan_ms > RESCAN_INTERVAL_MS) {
    scanNetworks();
  }

  // STA bağlantısı koptu → yeniden bağlan
  if (conn_status == CS_IDLE && sta_connected && wifi_is_connected_to_ap() != RTW_SUCCESS) {
    Serial.println("[STA] Kesildi, yeniden baslatiliyor...");
    sta_connected = false;
    if (strlen(saved_ssid) > 0) {
      strncpy(pending_ssid, saved_ssid, MAX_SSID_LEN - 1);
      strncpy(pending_pass, saved_pass, MAX_PASS_LEN - 1);
      pending_enc = ENC_TYPE_CCMP;
      startConnectTask();
    }
  }

  // HTTP istemci yönet
  WiFiClient client = server.available();
  if (client) {
    handleClient(client);
    client.stop();
  }
}
