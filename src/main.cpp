#include <WiFi.h>
#include <map>
#include <vector>
#include <set>
#include <BluetoothSerial.h>
#include "mbedtls/sha256.h"
#include <algorithm>
#include <random>
#include <Preferences.h>
#include <lwip/err.h>
#include <lwip/ip4_addr.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/tcpip.h>
#include <netif/etharp.h>
#include <esp_random.h> // Add this include at the top of the file
BluetoothSerial SerialBT;

// --- Configuration ---
#define TRUE_PORTS_COUNT 4
#define FAKE_PORTS_COUNT 10 
#define MAX_CLIENTS 10
#define PORT_RANGE_START 2000
#define PORT_RANGE_END   3000

std::vector<int> truePorts;
std::vector<int> fakePorts;

// --- WiFi Settings ---
const char* ssid = "TP-Link_D06B";
const char* password = "123456789";

// Service names for nmap detection
const char* serviceNames[TRUE_PORTS_COUNT] = {
  "memory-ftp", 
  "protocol-ftp", 
  "encryption-ftp", 
  "network-ftp"
};

// Client management
struct ClientInfo {
  WiFiClient client;
  unsigned long lastActivity;
  bool isActive;
  int step; // To track conversation state
};

// Riddle stages
struct Stage {
  int port;
  String question;
  String answer;
  const char* serviceName;
};

std::vector<Stage> stages = {
  {0, "What's the maximum RAM addressable in a 32-bit system?", "4gb", "memory-ftp"},
  {0, "Which protocol operates at the Transport Layer of the OSI model and provides reliable communication?", "tcp", "protocol-ftp"},
  {0, "What encryption algorithm replaced DES as the Federal Information Processing Standard?", "aes", "encryption-ftp"},
  {0, "What technology allows multiple virtual networks to share the same physical infrastructure?", "vlan", "network-ftp"}
};

// Using unordered_map would be more efficient but it's not available in Arduino
std::map<String, std::set<int>> studentProgress;
std::map<int, WiFiServer*> servers;
std::map<int, ClientInfo*> clients; // Changed to pointer-based to save memory

// Timeout constants
const unsigned long CLIENT_TIMEOUT = 60000; // 60 seconds timeout

std::set<String> allowedMacs= {
  "C0:35:32:2E:D4:19" // реальний MAC
};
Preferences preferences;

// Function to save allowed MACs to flash
void saveAllowedMacs() {
  String macsStr = "";
  for(const auto& mac : allowedMacs) {
    macsStr += mac + ",";
  }
  preferences.begin("macfilter", false);
  preferences.putString("macs", macsStr);
  preferences.end();
}

// Function to load allowed MACs from flash
void loadAllowedMacs() {
  preferences.begin("macfilter", true);
  String macsStr = preferences.getString("macs", "");
  preferences.end();
  
  allowedMacs.clear();
  if(macsStr.length() > 0) {
    int start = 0;
    int end = macsStr.indexOf(',');
    while(end != -1) {
      allowedMacs.insert(macsStr.substring(start, end));
      start = end + 1;
      end = macsStr.indexOf(',', start);
    }
  }
}

// Function to add new allowed MAC
void addAllowedMac(String mac) {
  allowedMacs.insert(mac);
  saveAllowedMacs();
  Serial.println("Added MAC: " + mac);
}

// Function to remove MAC from allowed list
void removeAllowedMac(String mac) {
  allowedMacs.erase(mac);
  saveAllowedMacs();
  Serial.println("Removed MAC: " + mac);
}

// Function to handle MAC management commands
void handleSerialCommand() {
  if(Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    
    if(cmd.startsWith("ADD_MAC ")) {
      String mac = cmd.substring(8);
      addAllowedMac(mac);
    }
    else if(cmd.startsWith("REMOVE_MAC ")) {
      String mac = cmd.substring(11);
      removeAllowedMac(mac);
    }
    else if(cmd == "LIST_MACS") {
      Serial.println("Allowed MACs:");
      for(const auto& mac : allowedMacs) {
        Serial.println(mac);
      }
    }
  }
}

// Function to handle Bluetooth commands
void handleBluetoothCommand() {
  if (SerialBT.available()) {
    String cmd = SerialBT.readStringUntil('\n');
    cmd.trim();
    
    if (cmd.startsWith("ADD_MAC ")) {
      String mac = cmd.substring(8);
      addAllowedMac(mac);
      SerialBT.println("Added MAC: " + mac);
    }
    else if (cmd.startsWith("REMOVE_MAC ")) {
      String mac = cmd.substring(11);
      removeAllowedMac(mac);
      SerialBT.println("Removed MAC: " + mac);
    }
    else if (cmd == "LIST_MACS") {
      SerialBT.println("Allowed MACs:");
      for (const auto& mac : allowedMacs) {
        SerialBT.println(mac);
      }
    }
    else if (cmd == "SYNC_MACS") {
      // Send all MACs as one string
      String macsStr = "";
      for (const auto& mac : allowedMacs) {
        macsStr += mac + ",";
      }
      SerialBT.println("BEGIN_SYNC");
      SerialBT.println(macsStr);
      SerialBT.println("END_SYNC");
    }
    else if (cmd.startsWith("RECEIVE_MACS")) {
      String macsData = cmd.substring(12);
      int start = 0;
      int end = macsData.indexOf(',');
      while (end != -1) {
        String mac = macsData.substring(start, end);
        mac.trim();
        if (mac.length() > 0) {
          addAllowedMac(mac);
        }
        start = end + 1;
        end = macsData.indexOf(',', start);
      }
      SerialBT.println("MACs received and saved");
    }
  }
}

// Function to generate a unique flag based on MAC address
String generateFlag(String macAddress) {
    uint8_t hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    
    // Add "rabbit" modifier to the input string
    String modifiedInput = macAddress + "peacock";
    mbedtls_sha256_update(&ctx, (const unsigned char*)modifiedInput.c_str(), modifiedInput.length());
    mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    String flagResult = "FLAG{";
    for (int i = 0; i < 5; i++) {
        char hex[3];
        sprintf(hex, "%02x", hash[i]);
        flagResult += hex;
    }
    flagResult += "}";

    Serial.printf("[FLAG] Generated flag for MAC %s \n", macAddress.c_str());
    return flagResult;
}

const char* getServiceNameForPort(int port) {
  for (int i = 0; i < stages.size(); i++) {
    if (stages[i].port == port) {
      return stages[i].serviceName;
    }
  }
  return "unknown-service";
}

// Function to get MAC address from IP
String getMacFromIP(String ip) {
  ip4_addr_t addr;
  if (!ip4addr_aton(ip.c_str(), &addr)) {
      return "";
  }

  struct netif* netif = netif_default;
  if (!netif) {
      return "";
  }

  err_t result = etharp_request(netif, &addr);
  if (result != ERR_OK) {
      return "";
  }

  delay(100);

  struct eth_addr* eth_ret = NULL;
  ip4_addr_t* ip_ret = NULL;
  if (etharp_find_addr(netif, &addr, &eth_ret, (const ip4_addr_t**)&ip_ret) == -1 || eth_ret == NULL) {
      return "";
  }

  char macStr[18];
  sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X",
          eth_ret->addr[0], eth_ret->addr[1], eth_ret->addr[2],
          eth_ret->addr[3], eth_ret->addr[4], eth_ret->addr[5]);
  return String(macStr);
}

void processClientMessage(ClientInfo& clientInfo, int port) {
  WiFiClient& client = clientInfo.client;

  // Check if this is a real port
  auto it = std::find(truePorts.begin(), truePorts.end(), port);
  if (it == truePorts.end()) {
    delay(100);
    client.stop();
    clientInfo.isActive = false;
    return;
  }

  if (clientInfo.step == 0) {
    // Initial connection - send banner with service name for nmap detection
    const char* serviceName = getServiceNameForPort(port);
    client.println("220 ESP32 " + String(serviceName) + " Service Ready");
    client.println("Welcome to IT Challenge Service on port " + String(port));

    // Find the stage
    int stageIndex = -1;
    for (int i = 0; i < stages.size(); ++i) {
      if (stages[i].port == port) {
        stageIndex = i;
        break;
      }
    }

    if (stageIndex == -1) {
      client.println("No challenge here.");
      clientInfo.isActive = false;
      client.stop();
      return;
    }

    Stage& stage = stages[stageIndex];
    client.println("Question: " + stage.question);
    clientInfo.step = 1;
  } 
  else if (clientInfo.step == 1 && client.available()) {
    // Receive answer
    String input = client.readStringUntil('\n');
    input.trim();
    String mac = client.remoteIP().toString();

    // Find the current stage
    int stageIndex = -1;
    for (int i = 0; i < stages.size(); ++i) {
      if (stages[i].port == port) {
        stageIndex = i;
        break;
      }
    }

    if (stageIndex == -1) {
      client.println("Error: Stage not found.");
      clientInfo.isActive = false;
      client.stop();
      return;
    }

    Stage& stage = stages[stageIndex];

    if (input.equalsIgnoreCase(stage.answer)) {
      client.println("Correct!");
      studentProgress[mac].insert(port);
      if (studentProgress[mac].size() == TRUE_PORTS_COUNT) {
        String clientMac = getMacFromIP(mac);
        if(clientMac.length() > 0 && allowedMacs.find(clientMac) != allowedMacs.end()) {
          client.println("You solved all stages!");
          client.println("Here is your flag: " + generateFlag(clientMac));
        } else {
          client.println("You solved all stages!");
          client.println("But your device is not authorized to receive the flag.");
          client.println("MAC: " + (clientMac.length() > 0 ? clientMac : "Unable to get MAC"));
        }
      } else {
        client.println("Stage completed. Continue to the next port.");
      }
    } else {
      client.println("Wrong answer. Try again.");
      client.println("Question: " + stage.question);
      clientInfo.step = 1;  // Reset to same step to allow retry
    }

    // Reset after processing
    clientInfo.step = 0;
    clientInfo.isActive = false;
    delay(100);
    client.flush();
    client.stop();
  }
}

void setup() {
  Serial.begin(115200);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected");
  Serial.println(WiFi.localIP());

  // Initialize Bluetooth Serial
  if (!SerialBT.begin("ESP32_peacock")) {
    Serial.println("Bluetooth initialization failed!");
  } else {
    Serial.println("Bluetooth initialized. Device name: ESP32_peacock");
  }

  // Load allowed MACs from flash
  loadAllowedMacs();
  addAllowedMac("C0:35:32:2E:D4:19");
  

 
  //allowedMacs
  Serial.println("Allowed MACs loaded from flash: ");
  for (const auto& mac : allowedMacs) {
    Serial.println(mac);
  }

  // Initialize random number generator with a better seed
  randomSeed(esp_random()); // Use ESP32's hardware random number generator
  std::random_device rd;
  std::mt19937 gen(rd() + esp_random()); // Combine software and hardware randomness
  std::uniform_int_distribution<> portDist(PORT_RANGE_START, PORT_RANGE_END);

  // Clear previous ports
  truePorts.clear();
  fakePorts.clear();

  // Generate true ports
  std::set<int> usedPorts;
  while (truePorts.size() < TRUE_PORTS_COUNT) {
    int port = portDist(gen);
    if (usedPorts.find(port) == usedPorts.end()) {
      truePorts.push_back(port);
      usedPorts.insert(port);
      Serial.printf("Generated TRUE port: %d\n", port);
    }
  }

  // Generate fake ports
  while (fakePorts.size() < FAKE_PORTS_COUNT) {
    int port = portDist(gen);
    if (usedPorts.find(port) == usedPorts.end()) {
      fakePorts.push_back(port);
      usedPorts.insert(port);
      Serial.printf("Generated FAKE port: %d\n", port);
    }
  }

  // Assign ports to stages
  for (int i = 0; i < TRUE_PORTS_COUNT; ++i) {
    stages[i].port = truePorts[i];
  }

  // Initialize servers for true ports
  for (int port : truePorts) {
    WiFiServer* srv = new WiFiServer(port);
    srv->begin();
    servers[port] = srv;
    Serial.println("TRUE port: " + String(port) + " (" + String(getServiceNameForPort(port)) + ")");
  }

  // Initialize servers for fake ports - memory optimization
  for (int port : fakePorts) {
    WiFiServer* srv = new WiFiServer(port);
    srv->begin();
    servers[port] = srv;
    Serial.println("FAKE port: " + String(port));
  }
  
  // Initialize clients map only when needed, not all at once
}

void cleanupInactiveClients() {
  unsigned long currentTime = millis();

  // More efficient iteration over clients
  auto it = clients.begin();
  while (it != clients.end()) {
    ClientInfo* clientInfo = it->second;
    
    if (clientInfo && clientInfo->isActive) {
      // Check if client has timed out
      if (currentTime - clientInfo->lastActivity > CLIENT_TIMEOUT) {
        Serial.println("Client on port " + String(it->first) + " timed out. Closing connection.");
        clientInfo->client.stop();
        clientInfo->isActive = false;
        delete clientInfo;  // Free memory
        it = clients.erase(it);  // Remove from map and get next iterator
        continue;
      }
    } else if (clientInfo && !clientInfo->isActive) {
      // Clean up inactive clients
      delete clientInfo;  // Free memory
      it = clients.erase(it);  // Remove from map and get next iterator
      continue;
    }
    
    ++it;
  }
}

void loop() {
  // Add at the beginning of loop()
  handleSerialCommand();
  handleBluetoothCommand();

  // Handle new connections
  for (auto& [port, server] : servers) {
    WiFiClient newClient = server->available();

    if (newClient) {
      // Create client info only when needed
      ClientInfo* clientInfo = new ClientInfo();
      clientInfo->client = newClient;
      clientInfo->isActive = true;
      clientInfo->step = 0;
      clientInfo->lastActivity = millis();
      
      // Generate unique client ID based on port and connection timestamp
      long clientId = port * 10000 + (millis() % 10000);
      clients[clientId] = clientInfo;

      Serial.println("New client connected to port " + String(port) + ", assigned ID " + String(clientId));
      
      // Process the client immediately
      processClientMessage(*clientInfo, port);
    }
  }

  // Process existing clients
  for (auto& [clientId, clientInfo] : clients) {
    if (clientInfo && clientInfo->isActive) {
      WiFiClient& client = clientInfo->client;
      int port = clientId / 10000;  // Extract port from client ID

      if (client.connected()) {
        clientInfo->lastActivity = millis(); // Update activity time
        processClientMessage(*clientInfo, port);
      } else {
        // Client disconnected
        clientInfo->isActive = false;
      }
    }
  }

  // Cleanup inactive clients periodically
  cleanupInactiveClients();

  // Small delay to prevent CPU hogging
  delay(10);
}