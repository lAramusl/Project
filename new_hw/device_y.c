/*
 * device_y.c — Terminal 3
 * Listens on veth_y for frames with EtherType 0x9999 (our custom type).
 * Prints only the text payload from those frames.
 *
 * Build:  gcc device_y.c -o device_y
 * Run:    sudo ip netns exec ns_devy ./device_y
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

#define IFACE        "veth_y"
#define MY_ETHERTYPE 0x9999   /* custom type — only our messages */
#define BUF          2048

int main(void) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket"); return 1; }

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, IFACE, IFNAMSIZ-1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) { perror("SIOCGIFINDEX"); return 1; }

    struct sockaddr_ll sa = {0};
    sa.sll_family   = AF_PACKET;
    sa.sll_ifindex  = ifr.ifr_ifindex;
    sa.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) { perror("bind"); return 1; }

    printf("=====================================\n");
    printf("  Device Y — waiting for messages\n");
    printf("  Interface : %s\n", IFACE);
    printf("  EtherType : 0x%04X (custom)\n", MY_ETHERTYPE);
    printf("=====================================\n\n");

    uint8_t frame[BUF];
    for (;;) {
        int len = recv(sock, frame, sizeof(frame), 0);
        if (len < 14) continue;

        /* read EtherType from bytes 12-13 */
        uint16_t et = (frame[12] << 8) | frame[13];

        /* ignore everything except our custom EtherType */
        if (et != MY_ETHERTYPE) continue;

        int pay_len = len - 14;
        if (pay_len <= 0) continue;

        /* null-terminate and print */
        char msg[BUF];
        int  copy = pay_len < BUF-1 ? pay_len : BUF-2;
        memcpy(msg, frame+14, copy);
        msg[copy] = '\0';

        printf("[Device Y] Received: %s", msg);
        fflush(stdout);
    }

    close(sock);
    return 0;
}