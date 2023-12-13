/*  WiFi softAP Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"

#include "lwip/err.h"
#include "lwip/sys.h"

// SPIFFS-Related input
#include <stdio.h>
#include <sys/unistd.h>
#include <sys/stat.h>
#include "esp_err.h"
#include "esp_spiffs.h"

// MQTT dependencies
#include "lwip/sockets.h"
#include "lwip/dns.h"
#include "lwip/netdb.h"

#include "esp_log.h"
#include "mqtt_client.h"



#define IS_BROADCAST(addr) (addr[0] == 0xFF) && (addr[1] == 0xFF) && (addr[2] == 0xFF) && (addr[3] == 0xFF) && (addr[4] == 0xFF) && (addr[5] == 0xFF)

/* The examples use WiFi configuration that you can set via project configuration menu.

   If you'd rather not, just change the below entries to strings with
   the config you want - ie #define EXAMPLE_WIFI_SSID "mywifissid"
*/
#define EXAMPLE_ESP_WIFI_SSID      CONFIG_ESP_WIFI_SSID
#define EXAMPLE_ESP_WIFI_PASS      CONFIG_ESP_WIFI_PASSWORD
#define EXAMPLE_ESP_WIFI_CHANNEL   CONFIG_ESP_WIFI_CHANNEL
#define EXAMPLE_MAX_STA_CONN       CONFIG_ESP_MAX_STA_CONN

// Management frame header
struct mgmt_header_t {
    u_int16_t   fc;     /* 2 bytes */
    u_int16_t   duration;   /* 2 bytes */
    u_int8_t    da[6];      /* 6 bytes */
    u_int8_t    sa[6];      /* 6 bytes */
    u_int8_t    bssid[6];   /* 6 bytes */
    u_int16_t   seq_ctrl;   /* 2 bytes */
    u_int8_t    ssidId;     /* Beginning of information elements, always SSID */
    u_int8_t    ssidSize;
};

// Tags for logging
static const char *TAG = "wifi softAP";
static const char *SNIFFER = "Sniffer";
static const char *STORAGE = "Storage";
static const char *TRANS = "Transmission";

// Filter for probe requests
wifi_promiscuous_filter_t filtro;

// SPIFFS related 
static const char *filename = "/spiffs/sniffed_data.csv";
static _lock_t fileLock; // Lock for handling current file writting
portMUX_TYPE my_spinlock = portMUX_INITIALIZER_UNLOCKED;

// MQTT related  
static char mqttConnected = 0;
static esp_mqtt_client_handle_t client;


/*
 * Function declarations
 */
// Handler for Wi-Fi connection events 
static void wifi_event_handler(void *, esp_event_base_t, int32_t, void *);
// Function to initialize the wifi
void wifi_init_softap(void);
// Handler for received packets via promiscuous mode
static void packet_handler(void *, wifi_promiscuous_pkt_type_t);
// Task that sends file each minute to mqtt servevoid
void SendTask();
// Initialize spiffs partition
void SPIFFSInit();
// Initialize MQTT
void MQTTInit();


static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                                    int32_t event_id, void* event_data)
{
    if (event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t* event = (wifi_event_ap_staconnected_t*) event_data;
        ESP_LOGI(TAG, "station "MACSTR" join, AID=%d",
                 MAC2STR(event->mac), event->aid);
    } else if (event_id == IP_EVENT_STA_GOT_IP){
        ESP_LOGI(TAG,"Got IP");
        if(mqttConnected){        
            ESP_LOGI(TAG,"Initializing MQTT");
            MQTTInit();
        }
    }
    else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t* event = (wifi_event_ap_stadisconnected_t*) event_data;
        ESP_LOGI(TAG, "station "MACSTR" leave, AID=%d",
                 MAC2STR(event->mac), event->aid);
    }
}

static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data){
    ESP_LOGD(TAG, "Event dispatched from event loop base=%s, event_id=%" PRIi32 "", base, event_id);
    esp_mqtt_event_handle_t event = event_data;

    switch ((esp_mqtt_event_id_t)event_id) {
        case MQTT_EVENT_CONNECTED:
            ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
            mqttConnected = 1;
            break;
        case MQTT_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
            mqttConnected = 0;
            break;
        case MQTT_EVENT_PUBLISHED:
            ESP_LOGI(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
            break;
        case MQTT_EVENT_DATA:
            ESP_LOGI(TAG, "MQTT_EVENT_DATA");
            printf("TOPIC=%.*s\r\n", event->topic_len, event->topic);
            printf("DATA=%.*s\r\n", event->data_len, event->data);
            break;
        case MQTT_EVENT_ERROR:
            ESP_LOGI(TAG, "MQTT_EVENT_ERROR");
                ESP_LOGI(TAG, "Last errno string (%s)", strerror(event->error_handle->esp_transport_sock_errno));
            break;
        default:
            ESP_LOGI(TAG, "Other event id:%d", event->event_id);
            break;
    }
}

void MQTTInit(){
    esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = CONFIG_BROKER_URL,
    };
    
    client = esp_mqtt_client_init(&mqtt_cfg);
    /* The last argument may be used to pass data to the event handler, in this example mqtt_event_handler */
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    esp_mqtt_client_start(client);
}

static char line[150];
FILE *f;
int msg_id;
char *newLine;

void SendTask(){
        // Repeat indefinelty
        for (;;) { 
            vTaskDelay(60000/portTICK_PERIOD_MS); // Each minute
            ESP_LOGI(TRANS,"Beginning transmission");
        
            if (!mqttConnected){
                ESP_LOGI(TRANS,"Aborted. MQTT broker not connected!");
            }else {
                _lock_acquire(&fileLock);

                ESP_LOGI(TRANS,"Lock acquired.");
                
                f = fopen(filename,"r"); 
                if (f == NULL){
                    ESP_LOGE(TRANS,"ERROR opening file");
                }
                
                ESP_LOGI(TRANS,"Got file pointer");
                
                while(fgets(line,sizeof(line),f) != NULL){
                    // Don't send blanks
                    if (strlen(line) == 0){
                        break;
                    }
                    // Removes last line
                    newLine = strchr(line,'\n');
                    if(newLine == NULL){
                        break;
                    }
                    *newLine = '\0';
                    ESP_LOGI(TRANS,"Transmitting line \"%s\"",line);
                    msg_id = esp_mqtt_client_publish(client, "/sniffed/data", line, 0, 1, 0);
                    ESP_LOGI(TRANS,"TransmittedLine. Msgid=%d",msg_id);
                }
                
                ESP_LOGI(TRANS,"Ending transmission");
                
                fclose(f);
                unlink(filename);
                // Recreates file
                f = fopen(filename,"w");
                fclose(f);
                _lock_release(&fileLock);
        }
    }
}

/*
 * packet_handler()
 * Description: Handler for received packets.
 * Receives a packet and writes its contents into a file as a csv line.
 * Each column is described as follows:
 *      - (signed)      rssi: dBm
 *      - (unsigned)    sig_mode: 0 for non-HT(bg), 1 for HT(n), 2 for VTH(ac)
 *      - (unsinegd)    rate (for non-HT): Rate
 *      - (unsigned)    mcs (for HT): Modulation Coding Scheme
 *      - (unsigned)    cwb: Channel bandwith 0<-20MHz, 1<-40MHz
 *      - (signed)      noise_floor: Noise of wich packet was received  (dBm)
 *      - (unsigned)    sig_len: packet length plus FCS
 *      - (Array)       sender: Receiver address (in std MAC format)
 *      - (Array)       receiver: Receiver address (in std MAC format)
 *      - (Array)       SSID: SSID string (or hashed string)
 *
 */
void packet_handler(void *buffer, wifi_promiscuous_pkt_type_t packetType){
    
    wifi_promiscuous_pkt_t *packetInfo = buffer;
    struct mgmt_header_t *packet=(struct mgmt_header_t *) packetInfo->payload;
    FILE* file;
    
    char ssidString[33];
    char senderAddressString[20];
    char destinationAddressString[20];
    char bssidAddressString[20];
    int fc, len;

    fc = ntohs(packet->fc);

    if (packetType == WIFI_PKT_MGMT && (fc & 0xFF00) == 0x4000){
        ESP_LOGI(SNIFFER,"Packet received!");
        // Format addessses
        sprintf(senderAddressString,"%X:%X:%X:%X:%X:%X",
                packet->sa[0], packet->sa[1], packet->sa[2],
                packet->sa[3], packet->sa[4], packet->sa[5]
        );
        
        sprintf(destinationAddressString,"%X:%X:%X:%X:%X:%X",
                packet->da[0], packet->da[1], packet->da[2],
                packet->da[3], packet->da[4], packet->da[5]
        );
        
        sprintf(bssidAddressString,"%X:%X:%X:%X:%X:%X",
                packet->bssid[0], packet->bssid[1], packet->bssid[2],
                packet->bssid[3], packet->bssid[4], packet->bssid[5]
        );
        
        // gets ssid size
        len = (int) packet->ssidSize;
        if (len > 31){
            ESP_LOGD(SNIFFER,"SSID placement is misaligned. Value is greater than 32");
            len = 31; 
        }
        // Copies SSID value 
        strncpy(ssidString,(char*)packetInfo->payload+26,len);
        ssidString[len] = '\0';

        ESP_LOGD(SNIFFER,"ts,rssi,sig_mode,rate,mcs,cwb,noise_floor,sig_len,sender,receiver,bssid,ssid")
        ESP_LOGD(SNIFFER,"%d,%i,%d,%d,%d,%i,%d,%d,%s,%s,%s,\"%s\"",
                packetInfo->rx_ctrl.timestamp,
                packetInfo->rx_ctrl.rssi,
                packetInfo->rx_ctrl.sig_mode,
                packetInfo->rx_ctrl.mcs,
                packetInfo->rx_ctrl.cwb,
                packetInfo->rx_ctrl.noise_floor,
                packetInfo->rx_ctrl.sig_len,
                packet->seq_ctrl,
                senderAddressString,
                destinationAddressString,
                bssidAddressString,
                ssidString
                ); 
            
        _lock_acquire(&fileLock);
        file = fopen(filename,"a");
        fprintf(file,"%d,%i,%d,%d,%d,%i,%d,%d,%s,%s,%s,\"%s\"\n",
                packetInfo->rx_ctrl.timestamp,
                packetInfo->rx_ctrl.rssi,
                packetInfo->rx_ctrl.sig_mode,
                packetInfo->rx_ctrl.mcs,
                packetInfo->rx_ctrl.cwb,
                packetInfo->rx_ctrl.noise_floor,
                packetInfo->rx_ctrl.sig_len,
                packet->seq_ctrl,
                senderAddressString,
                destinationAddressString,
                bssidAddressString,
                ssidString
                );
        fclose(file);
        _lock_release(&fileLock);
    }
}

void wifi_init_softap(void)
{
    esp_err_t err;
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        NULL));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        NULL));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = EXAMPLE_ESP_WIFI_SSID,
            .password=CONFIG_ESP_WIFI_PASSWORD,
        },
    };
    if (strlen(EXAMPLE_ESP_WIFI_PASS) == 0) {
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    // Setting promiscuous mode for sniffing
    ESP_LOGI(TAG,"initializing promiscuous callback");
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&packet_handler));
    filtro.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filtro));
    ESP_LOGI(TAG,"initializing promiscuous mode");
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(1));
    // Starting WiFi
    ESP_LOGI(TAG,"WIFI start");
    while(true){
        err = esp_wifi_start();
        if (err == ESP_OK){
            ESP_LOGI(TAG,"WiFi Started");
            ESP_LOGI(TAG,"Attempting connection");
            err = esp_wifi_connect();
            if (err == ESP_OK){
                ESP_LOGI(TAG,"Sucess on connection");
                break;
            } else {
                ESP_LOGE(TAG,"Something failed from connection");
                esp_wifi_stop();
                vTaskDelay(100/portTICK_PERIOD_MS);
            }
        } else {
            ESP_LOGE(TAG,"WiFi not started, attempting again");
            esp_wifi_stop();
            vTaskDelay(100/portTICK_PERIOD_MS);
        }
    }

}

void SPIFFSInit(){

    ESP_LOGI(TAG, "Initializing SPIFFS");

    esp_vfs_spiffs_conf_t conf = {
      .base_path = "/spiffs",
      .partition_label = NULL,
      .max_files = 5,
      .format_if_mount_failed = true
    };

    // Use settings defined above to initialize and mount SPIFFS filesystem.
    // Note: esp_vfs_spiffs_register is an all-in-one convenience function.
    esp_err_t ret = esp_vfs_spiffs_register(&conf);

    if (ret != ESP_OK) {
        if (ret == ESP_FAIL) {
            ESP_LOGE(TAG, "Failed to mount or format filesystem");
        } else if (ret == ESP_ERR_NOT_FOUND) {
            ESP_LOGE(TAG, "Failed to find SPIFFS partition");
        } else {
            ESP_LOGE(TAG, "Failed to initialize SPIFFS (%s)", esp_err_to_name(ret));
        }
        return;
    }


    size_t total = 0, used = 0;
    ret = esp_spiffs_info(conf.partition_label, &total, &used);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get SPIFFS partition information (%s). Formatting...", esp_err_to_name(ret));
        esp_spiffs_format(conf.partition_label);
        return;
    } else {
        ESP_LOGI(TAG, "Partition size: total: %d, used: %d", total, used);
    }

    // Check consistency of reported partiton size info.
    if (used > total) {
        ESP_LOGW(TAG, "Number of used bytes cannot be larger than total. Performing SPIFFS_check().");
        ret = esp_spiffs_check(conf.partition_label);
        // Could be also used to mend broken files, to clean unreferenced pages, etc.
        // More info at https://github.com/pellepl/spiffs/wiki/FAQ#powerlosses-contd-when-should-i-run-spiffs_check
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "SPIFFS_check() failed (%s)", esp_err_to_name(ret));
            return;
        } else {
            ESP_LOGI(TAG, "SPIFFS_check() successful");
        }
    }
}

void app_main(void)
{ 
    //Initialize NVS
    ESP_LOGI(TAG,"App begin");
    ESP_LOGI(TAG,"NVS initialization");
    
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
      ESP_ERROR_CHECK(ret);
    }
    ESP_LOGI(TAG,"NVS inicialization successfull");

    ESP_LOGI(TAG,"SPIFFS initialization");
    SPIFFSInit();
    ESP_LOGI(TAG,"SPIFFS Successfull initialization");

    xTaskCreate(&SendTask, "SendTask", 600, NULL, 1, NULL);
    ESP_LOGI(TAG,"Registered task: MQTT offloading");
    ESP_LOGI(TAG, "Wi-Fi driver initialization");
    wifi_init_softap();
    ESP_LOGI(TAG,"Wi-Fi driver initialized");
}
