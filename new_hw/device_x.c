/*
 * device_x.c — Terminal 4
 * Sends plain text as raw Ethernet frames with EtherType 0x9999.
 * Uses AF_PACKET raw socket on veth_x inside ns_devx.
 *
 * Build:  gcc device_x.c -o device_x
 * Run:    sudo ip netns exec ns_devx ./device_x
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#define IFACE        "veth_x"
#define MY_ETHERTYPE 0x9999
#define BUF          1500

int main(void) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket"); return 1; }

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, IFACE, IFNAMSIZ-1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) { perror("SIOCGIFINDEX"); return 1; }
    int ifindex = ifr.ifr_ifindex;

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) { perror("SIOCGIFHWADDR"); return 1; }
    uint8_t src_mac[6];
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);

    printf("=====================================\n");
    printf("  Device X — type a message\n");
    printf("  Interface : %s\n", IFACE);
    printf("  EtherType : 0x%04X (custom)\n", MY_ETHERTYPE);
    printf("=====================================\n\n");

    char    input[BUF];
    uint8_t frame[BUF + 14];

    for (;;) {
        printf("Device X > ");
        fflush(stdout);
        if (!fgets(input, sizeof(input), stdin)) break;

        int pay_len   = strlen(input);
        int frame_len = 14 + pay_len;

        /* Ethernet header */
        memset(frame,    0xff, 6);          /* DST: broadcast        */
        memcpy(frame+6,  src_mac, 6);       /* SRC: our MAC          */
        frame[12] = (MY_ETHERTYPE >> 8) & 0xFF;
        frame[13] =  MY_ETHERTYPE       & 0xFF;
        memcpy(frame+14, input, pay_len);   /* payload: plain text   */

        struct sockaddr_ll dest = {0};
        dest.sll_family  = AF_PACKET;
        dest.sll_ifindex = ifindex;
        dest.sll_halen   = 6;
        memset(dest.sll_addr, 0xff, 6);

        ssize_t sent = sendto(sock, frame, frame_len, 0,
                              (struct sockaddr*)&dest, sizeof(dest));
        if (sent < 0) { perror("sendto"); continue; }

        printf("[Device X] Sent plain text (%d bytes, unencrypted)\n\n", pay_len);
    }

    close(sock);
    return 0;
}