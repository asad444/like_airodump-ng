#include "main.h"

RH *r_hdr;
IH *i_hdr;
vector<BEACON> v;


void print_mac(uint8_t *mac_addr){
    for(int i=0;i<MAC_SIZE-1;i++){
        printf("%02X:", mac_addr[i]);
    }
    printf("%02X", mac_addr[MAC_SIZE-1]);
}

void print_state(void){
    printf("\033[H\033[J\n");
    puts(" BSSID            \tBeacons   \tESSID\n");
    
    for(auto tmp : v){
        printf(" ");
        print_mac(tmp.bss_id);
        printf("\t%03d\t\t", tmp.beacons);
        if(tmp.is_essid){
            printf("%s", tmp.ess_id);
        }
        printf("\n");
    }
}

void packet_parsing(const u_char* packet, int length){
    r_hdr = (RH*)packet;
    i_hdr = (IH*)(packet+r_hdr->it_len);
    uint8_t* lan_data = (uint8_t*)(packet+r_hdr->it_len+sizeof(IH)+12);

    if(i_hdr->subtype == 0x80){
        int is_new = 1;
        for(int i=0; i<v.size();i++){
            if(!memcmp(v[i].bss_id, i_hdr->bss_id, MAC_SIZE)){
                is_new = 0;
                v[i].beacons++;
                int idx = r_hdr->it_len+sizeof(IH)+12;
                while(idx < length){
                    uint8_t num = packet[idx++];
                    int len = packet[idx++];
                    if(idx + len >= length) break;
                    if(num == 0){
                        v[i].is_essid = true;
                        memcpy(v[i].ess_id, packet+idx, len);
                    }
                    idx += len;
                }
            }
        }
        if(is_new){
            BEACON new_v;
            memcpy(new_v.bss_id, i_hdr->bss_id, MAC_SIZE);
            new_v.beacons = 1;
            new_v.data = 0;
            int idx = r_hdr->it_len+sizeof(IH)+12;
            while(idx < length){
                uint8_t num = packet[idx++];
                int len = packet[idx++];
                if(idx + len >= length) break;
                if(num == 0){
                    new_v.is_essid = true;
                    memcpy(new_v.ess_id, packet+idx, len);
                }
                idx += len;
            }
            v.push_back(new_v);
        }
    }
    print_state();
}

int main(int argc, char* argv[]){
    if(argc != 2){
        puts("airodump <interface>");
        return 0;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr* header;
    const u_char* packet;

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL){
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return 0;
    }

    while(1){
        print_state();
        unsigned int error = pcap_next_ex(handle, &header, &packet);
        if(error == 0)
            continue;
        if(error == -1)
            printf("packet read error");
	if(error == -2)
	    printf("savefile? invalid!");

        int length = header->caplen;
        packet_parsing(packet, length);
    }
}
