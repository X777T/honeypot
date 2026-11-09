#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>

#define MAX_LOGS 60
#define NUM_HONEY 6

WebServer server(80);

const char *AP_SSID = "ESP32-Honeypot";
const char *AP_PASS = "12345678";

struct HoneyLog {
  String ip;
  uint16_t port;
  String svc;
  String payload;
  unsigned long ms;
};

HoneyLog logs[MAX_LOGS];
int logCount = 0;
int logHead = 0;
uint32_t totalHits = 0;

struct HoneyDef {
  uint16_t port;
  const char *svc;
  const char *banner;
};

HoneyDef defs[NUM_HONEY] = {
  {21, "FTP", "220 (vsFTPd 3.0.5)\r\n"},
  {22, "SSH", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"},
  {23, "Telnet", "Ubuntu 22.04 LTS\r\nlogin: "},
  {445, "SMB", ""},
  {3389, "RDP", ""},
  {8080, "HTTP-alt", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n<html><body>It works!</body></html>"},
};

WiFiServer srvFtp(21);
WiFiServer srvSsh(22);
WiFiServer srvTel(23);
WiFiServer srvSmb(445);
WiFiServer srvRdp(3389);
WiFiServer srvHttpAlt(8080);

WiFiServer *srvs[NUM_HONEY] = {&srvFtp, &srvSsh, &srvTel, &srvSmb, &srvRdp, &srvHttpAlt};

String esc(String s) {
  s.replace("&", "&amp;");
  s.replace("<", "&lt;");
  s.replace(">", "&gt;");
  s.replace("\"", "&quot;");
  String out;
  out.reserve(s.length());
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c < 32 && c != '\n' && c != '\t') out += '.';
    else out += c;
  }
  return out;
}

String fmtTime(unsigned long ms) {
  unsigned long secs = ms / 1000;
  char b[16];
  snprintf(b, sizeof(b), "%02lu:%02lu:%02lu", secs / 3600, (secs / 60) % 60, secs % 60);
  return String(b);
}

void addLog(const String &ip, uint16_t port, const String &svc, const String &payload) {
  logs[logHead].ip = ip;
  logs[logHead].port = port;
  logs[logHead].svc = svc;
  logs[logHead].payload = payload;
  logs[logHead].ms = millis();
  logHead = (logHead + 1) % MAX_LOGS;
  if (logCount < MAX_LOGS) logCount++;
  totalHits++;
}

void checkHoney() {
  for (int i = 0; i < NUM_HONEY; i++) {
    WiFiClient c = srvs[i]->available();
    if (!c) continue;

    String ip = c.remoteIP().toString();
    String payload;
    unsigned long t0 = millis();
    while (c.connected() && millis() - t0 < 120 && payload.length() < 40) {
      if (c.available()) {
        payload += (char)c.read();
      } else {
        delay(1);
      }
    }
    addLog(ip, defs[i].port, defs[i].svc, payload);

    if (defs[i].banner[0] != 0) {
      c.print(defs[i].banner);
      delay(20);
    }
    c.stop();
  }
}

String escSafe(const String &s) {
  return esc(s);
}

const char *PAGE_HEAD =
  "<!DOCTYPE html><html lang='zh'><head><meta charset='utf-8'>"
  "<meta name='viewport' content='width=device-width,initial-scale=1'>"
  "<style>"
  "*{box-sizing:border-box;margin:0;padding:0}"
  "body{background:#0f172a;color:#e2e8f0;font-family:-apple-system,'Segoe UI',sans-serif;padding:16px;max-width:700px;margin:0 auto}"
  "h1{font-size:20px;margin-bottom:4px}"
  ".sub{color:#94a3b8;font-size:13px;margin-bottom:16px}"
  ".stat{display:flex;gap:10px;margin-bottom:14px}"
  ".stat div{flex:1;background:#1e293b;border-radius:10px;padding:10px;text-align:center}"
  ".stat b{display:block;font-size:20px;color:#38bdf8}"
  ".stat span{font-size:11px;color:#94a3b8}"
  ".net{background:#1e293b;border-radius:10px;padding:12px;margin-bottom:8px}"
  ".row{display:flex;align-items:center;gap:8px}"
  ".ip{flex:1;font-weight:600;font-size:14px;font-family:monospace;word-break:break-all}"
  ".tag{font-size:11px;padding:2px 7px;border-radius:6px;background:#334155;color:#cbd5e1;white-space:nowrap}"
  ".danger{background:#7f1d1d;color:#fca5a5}"
  ".mono{font-family:monospace;font-size:11px;color:#94a3b8;margin-top:6px;word-break:break-all}"
  ".pay{background:#0b1220;border-radius:6px;padding:6px;font-family:monospace;font-size:11px;color:#fbbf24;margin-top:6px;word-break:break-all;white-space:pre-wrap}"
  ".btn{display:inline-block;margin-top:14px;padding:11px 22px;background:#38bdf8;color:#0f172a;border-radius:10px;font-weight:600;text-decoration:none}"
  "</style></head><body>";

void handleRoot() {
  String html;
  html += F("<title>ESP32 蜜罐</title>");
  html += PAGE_HEAD;
  html += F("<h1>ESP32 网络蜜罐</h1>");
  html += "<div class='sub'>诱饵服务已开启：" + String(NUM_HONEY) + " 个端口，记录每一次探测</div>";

  html += F("<div class='stat'>");
  html += "<div><b>" + String((unsigned long)totalHits) + "</b><span>总探测次数</span></div>";
  html += "<div><b>" + String(logCount) + "</b><span>日志条数</span></div>";
  html += "<div><b>" + String(WiFi.softAPgetStationNum()) + "</b><span>当前连接设备</span></div>";
  html += "</div>";

  html += F("<div class='net'><div class='row' style='font-size:12px;color:#94a3b8'><span>蜜罐端口：");
  for (int i = 0; i < NUM_HONEY; i++) {
    html += "<span class='tag' style='margin-left:4px'>" + String(defs[i].port) + " " + String(defs[i].svc) + "</span>";
  }
  html += F("</span></div></div>");

  if (logCount == 0) {
    html += F("<div class='net'>还没有人探测。用手机/电脑连上热点后扫这些端口试试。</div>");
  }

  for (int k = 0; k < logCount; k++) {
    int idx = (logHead - 1 - k + 2 * MAX_LOGS) % MAX_LOGS;
    HoneyLog &l = logs[idx];
    html += "<div class='net'>";
    html += "<div class='row'><span class='ip'>" + esc(l.ip) + "</span>";
    html += "<span class='tag danger'>" + String(l.port) + " " + esc(l.svc) + "</span>";
    html += "<span class='tag'>" + fmtTime(l.ms) + "</span></div>";
    if (l.payload.length() > 0) {
      html += "<div class='pay'>" + esc(l.payload) + "</div>";
    } else {
      html += F("<div class='mono'>（连接后无数据，典型端口扫描特征）</div>");
    }
    html += "</div>";
  }

  html += F("<div style='text-align:center'><a class='btn' href='/'>刷新日志</a></div>");
  html += F("</body></html>");
  server.send(200, "text/html; charset=utf-8", html);
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID, AP_PASS);

  for (int i = 0; i < NUM_HONEY; i++) {
    srvs[i]->begin();
  }

  Serial.println("ESP32 蜜罐启动");
  Serial.print("热点：");
  Serial.println(AP_SSID);
  Serial.print("密码：");
  Serial.println(AP_PASS);
  Serial.print("管理页：http://");
  Serial.println(WiFi.softAPIP());
  Serial.print("蜜罐端口：");
  for (int i = 0; i < NUM_HONEY; i++) {
    Serial.print(defs[i].port);
    Serial.print(" ");
  }
  Serial.println();

  server.on("/", handleRoot);
  server.begin();
}

void loop() {
  checkHoney();
  server.handleClient();
}
