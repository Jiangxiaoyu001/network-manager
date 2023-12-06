/*********************************************************
*
* Description: 
*   A free tool for everyone
*   achieve ping feature by ICMP protocol
*
* Datetime: Tuesday November 18 2023
*
* Author: jiangxiaoyu
*
* Email: xinGuSoftWare@163.com
*
****************************************************************/
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <cerrno>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <netinet/if_ether.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <sys/time.h>

#define MAX_READ_LEN 1024

/* MAC header */
/* byte
|----- 6 -------|------ 6 ------|-- 2 --|

----------------|---------------|-------|
|des addr       | src addr      | type  |
|---------------|---------------|-------|
*/
struct {
    unsigned char DesMacAddr[6];  /* 6 byte desmac address */
    unsigned char SrcMacAddr[6];  /* 6 byte src mac address */
    unsigned short NetworkType;  /* 2 byte network type */
} mac_header, *pmac_header;

/* ip packet */
/*
---------------------------------------------32 bits--------------------------------------------|
|--------- 8 ------------|--------- 8 ----------|--------- 8 ----------|----------- 8 ----------|
|------------------------|----------------------|----------------------|------------------------|
| version   | header len |      server type     |               total len                       |
|-----------|------------|----------------------|-------------|---------------------------------|
|                  identifier                   |       flag  |         offest                  |
|-----------------------------------------------------------------------------------------------|
|      TTL |                    protocol        |               checksum|
|------------------------|----------------------|-----------------------------------------------|
|                                       source IP                                               |
|-----------------------------------------------------------------------------------------------|
|                                       destination IP                                          |
|-----------------------------------------------------------------------------------------------|
|                               optional                                |       fill            |
|-----------------------------------------------------------------------|-----------------------|
*/
#pragma pack(4)
typedef struct _ip_hdr{
#if defined (__BIG_ENDIAN_BITFIELD)
    unsigned short version : 4;     /* 0 - 3  */
    unsigned short header_len : 4;  /* 4 - 7  */
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    unsigned short header_len : 4;  /* 0 - 3 */
    unsigned short version : 4;     /* 4 - 7 */
#endif
    unsigned short server_type : 8; /* 8 - 15 */
    unsigned short total_len ;
    unsigned short identidier;
#if defined (__BIG_ENDIAN_BITFIELD)
    unsigned short flag : 4;        /* 0 - 3  */
    unsigned short offest : 12;     /* 4 - 15 */
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    unsigned short offest :4;
    unsigned short flag : 12;
#endif
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned int src_addr;
    unsigned int des_addr;
} IpHeader;
#pragma pack() /* cancel */

/* ICMP  
----------- 32 bits -------------
|-- 8 --|-- 8 --|----- 16 ------|
|-------|-----------------------|
| type  | code  | checksum      |
|-------------------------------|
|identifier     | serial number |
|---------------|---------------|
|        date                   |
|-------------------------------|
*/

#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0
#define IP_RECORD_ROUTE 0x7
#define ICMP_MIN  8 /* minmum 8-bytes icmp packet (header) */
#define MAX_IP_HEADER_SIZE 60 /* max ip header size */
#define MIN_IP_HEADER_SIZE 20 /* min ip header size */


struct {
    int seq_no;
    int recvBytes;
    int packetSize;
    bool recordRoute;
    bool icmpCount;
    char *destAddr;
} operation = {0, 0, 0, false, false, NULL};


#pragma pack(4)
typedef struct _icmp_hdr {
    unsigned char  type;
    unsigned char  code;
    unsigned short  checksum;
    unsigned short identifier;
    unsigned short seqNum;
    unsigned int   timestamp;
} IcmpHeader;
#pragma pack()

/* header len */
struct {
    unsigned short macHeader_len;
    unsigned short ipHeader_len;
    unsigned short ipSrcAdrLen;
    unsigned short ipDesAdrLen;
    unsigned short icmpHeaderLen;
} *p_headerLen, headerLen = {
    .macHeader_len = sizeof(mac_header),
    .ipHeader_len = sizeof(IpHeader),
    .ipSrcAdrLen = sizeof(unsigned int),
    .ipDesAdrLen = sizeof(unsigned int),
    .icmpHeaderLen = sizeof(IcmpHeader),
    };

/* IP-header optional */
#pragma pack(1)
typedef struct _ip_option {
    unsigned char code; /* option type */
    unsigned char len; /* length of options */
    unsigned char ptr; /* offset into options */
    unsigned int  addr[9]; /* list of IP address */
} IpOptHeader;
#pragma pack()


static void validate_args(int argc, char **argv);
static void ip_packet_parse(const char *msg, int bytes);

static void 
ip_options_parse(const char *msg);
static void 
icmp_request_packet(char * icmp_data, int data_size);
static unsigned short 
icmp_calc_checksum(unsigned short * icmp_packet, int size);



/**                                                                    
 * usage:
 * @progname: terminal parameter
 * @return: no value return
 * print usage information
 */ 
void usage(char *progname)
{
 printf("Usage: ping_c [options] <host>\n");
 printf("Options:\n");
 printf("<destination>  dns name or ip address\n");
 printf("-R             record route\n");
 printf("-s <size>      use <size> as number of data bytes to be sent\n");
}
 
/**        
 * icmp_header_parse:
 * @msg: ICMP packet
 * @bytes: The ICMP packet size decode from IP packet
 * 
 *  The response is an ICMP packet
 */ 
void icmp_header_parse(const char * msg, int bytes, struct in_addr from)
{
    /* obtian current timestamp(us)to calcultion 
    the time from ICMP echo replay */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    unsigned int milliseconds = tv.tv_sec * 1000 + tv.tv_usec / 1000; /* ms */
  

    IcmpHeader * Icmphdr = (IcmpHeader *)msg;
    if (Icmphdr->type != ICMP_ECHOREPLY) {
        printf("non echo replay, type:%d recvd", Icmphdr->type);
    }
    /* make sure this is an ICMP replay to somethinf we sent */
    if (Icmphdr->identifier != (unsigned short)getpid()) {
        printf("someone else's ICMP packet\n");
        return;
    }
    printf("%d bytes from %s:", bytes, inet_ntoa(from));
    printf(" icmp_seq=%d", Icmphdr->seqNum);
    printf(" time:%lld ms", milliseconds - (Icmphdr->timestamp  * 1000) );
    printf("\n");

    return;
}

/**        
 * icmp_request_packet:
 * @icmp_data: fill in various field for icmp request
 * @data_size: number of data bytes to be sent
 *
 * Helper function fill in various field for icmp request
 *
 * Return: On success return 0, on error reutrn -1
 */ 
void icmp_request_packet(char * icmp_packet, int size)
{

    IcmpHeader * Icmphdr = (IcmpHeader *)icmp_packet;
    //memset(p_icmpHeader, 0, p_headerLen->icmpHeaderLen);

    Icmphdr->type       = ICMP_ECHO;
    Icmphdr->code       = ICMP_ECHOREPLY;
    Icmphdr->identifier = getpid();
    Icmphdr->checksum   = 0;
    Icmphdr->seqNum     = operation.seq_no++;

    /* fill ICMP data part */
    if (size >= sizeof(IcmpHeader)) { 
        struct timeval tv;
        gettimeofday(&tv, NULL);
        unsigned int milliseconds = tv.tv_sec; /* ms */
        Icmphdr->timestamp = milliseconds ; //
        /* place some junk int the icmp data-part */
        memset(&icmp_packet[sizeof(IcmpHeader)], 'E', size - sizeof(IcmpHeader));
    }

    /* calc checksum */
    Icmphdr->checksum = icmp_calc_checksum((unsigned short *)Icmphdr, size);

    return;
}

/**                                                            
 * icmp_calc_checksum:
 * @size: the icmp data packet length
 * @icmp_packet: icmp protocol packet both header and data
 *
 * Calculates the 16-bit icmp's checksum
 * if we divide the ICMP data packet is 16 bit words and sum each of them up
 * then hihg 16bit add low 16bit to sum get a value, 
 * the value add low 16bit of value to sum
 * finally do a one's complementing 
 * then the value generated out of this operation would be the checksum.
 * 
 * Return: unsigned short checksum
 */
unsigned short icmp_calc_checksum(unsigned short * icmp_packet, int size)
{
 unsigned short * sum = (unsigned short *)icmp_packet;
 unsigned int checksum = 0;

 while (size > 1) {
  checksum += *sum++;
  size -= sizeof(unsigned short);
 }
 if (size) {
  checksum += (unsigned char)*sum;
 }

 checksum = (checksum >> 16) + (checksum & 0xffff);
 checksum += checksum >> 16;
 
 return (unsigned short)(~checksum);
}

/**        
 * ip_options_parse:
 * @msg: IPV4 protocol packet
 * 
 *  If the IP option header is present, find the ip 
 *  options within the IP header and print record route option values
 *
 */ 
void ip_options_parse(const char *msg)
{
    struct hostent *host = NULL;
    struct in_addr ipv4_addrs = {0};


    /* IP options setup address */
    IpOptHeader * p_ipOpt = (IpOptHeader *)(msg + 20);

    printf("RR: \n");

    /* IP address number of count
       IP address is a binary receive from network byte order
    */
    for (int i = 0; i < (p_ipOpt->ptr / 4) - 1; i++) {
        
        memcpy(&ipv4_addrs, &(p_ipOpt->addr[i]), sizeof(p_ipOpt->addr[i]));

        if ((host =  gethostbyaddr((char *)&ipv4_addrs.s_addr, 
                            sizeof(in_addr_t), AF_INET)))
            printf("(%-15s)%s\n", inet_ntoa(ipv4_addrs), host->h_name);
        else
            printf("(%-15s)\n", inet_ntoa(ipv4_addrs));
    }

    return;
}

/**        
 * ip_packet_parse:
 * @msg: IPV4 protocol packet
 * @bytes: The receive IPV4 packet size from network protocol
 * 
 * Already locate to IPV4 protocol packet from original network protocol packet
 * and decode IPV4 filed
 *
 */ 
void ip_packet_parse(const char *msg, int bytes)
{
    IpHeader * Iphdr = (IpHeader *)msg;

    /* obtian source IP addres */
    struct in_addr src_adr = {Iphdr->src_addr};

    /* (number of 32-bit) word * 4 = bytes */
    unsigned short iphdrlen = Iphdr->header_len * 4;
    /* if the ip options contain MAX IP address list (9) */
    if ((iphdrlen == MAX_IP_HEADER_SIZE) && (!operation.icmpCount)) {
        ip_options_parse(msg);
        operation.icmpCount = true;
    }
    if (bytes < iphdrlen + ICMP_MIN)
        printf("Too few bytes from %s\n", inet_ntoa(src_adr));
    
    icmp_header_parse(msg + iphdrlen, (bytes - iphdrlen), src_adr);
    
    return;
}


/**                                                                    
 * validate_args:
 * @argc: terminal paraments count
 * @argv: terminal parament content
 * 
 * Parse terminal parament
 */ 
void validate_args(int argc, char **argv)
{
    int i = 0;
    if (argc == 1) {
        usage(argv[0]);
        exit(-1);
    }
    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-' || argv[i][0] == '/') {
            if (argv[i][1] == 'R') {
                operation.recordRoute = 1;
            } else if (argv[i][1] == 's') {
                /* judge arg whether is packet size or not */
                if (isdigit(argv[++i][0]))
                    operation.packetSize = atoi(argv[i]);
            } else
                usage(argv[0]);
        } else if (argv[i] != NULL) /* obtain destination IP address */
            operation.destAddr = argv[i];
    }
}


/**
 * 
 *@Author: jiangxiaoyu
 *
 *@Email: xinGuSoftWare@163.com
 *
 *@Date: Tue Nov 26 2023 14：00
 */
 int main (int argc, char **argv)
 {
    validate_args(argc, argv);

    pmac_header = &mac_header;

    char recvBuff[1024] = {0};
    ssize_t recvByte = 0;
    struct sockaddr_in sockAdr;
    socklen_t len = sizeof(sockAdr);
    memset(&sockAdr, 0, sizeof(sockAdr));
    memset(&mac_header, 0, sizeof(mac_header));

 /* family:
  
  PF_PACKET : link layer
  AF_INET   : network layer /ipv4
  AF_INET6  : network layer /ipv6 
  ETH_P_ALL : All network protocol
 */  
 
    /* receive IP_ICMP packet from original network protocol */
    int sockrawfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockrawfd == -1) {
     fprintf(stderr, "sock raw create failed\n");
        return -1;
    } else
        printf("sock raw created succeed\n");

/*    
    struct ifreq ifstruct;
    struct sockaddr_in serverAdr;
    memset(&serverAdr, 0, sizeof(serverAdr));
    memset(&ifstruct, 0, sizeof(ifstruct));
    serverAdr.sin_family = AF_PACKET;
    serverAdr.sin_port = htons(ETH_P_ALL); 
    serverAdr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (setsockopt(sockrawfd, SOL_SOCKET, SO_BINDTODEVICE, &ifstruct, sizeof(ifstruct)) < 0)
    {
            cout << "socket setsockopt error" << endl;
            printf("bind interface fail, errno: %d \r\n", errno);
    close(sockrawfd);
    return -2;
    }
    addr_ll.sll_ifindex = ifstruct.ifr_ifindex;

*/
    /* record route:
        setup the IP option header to go out on every ICMP packet
     */
    struct hostent *hp = NULL;
    struct sockaddr_in dest_addr = {0}; 
    if (operation.recordRoute) {
        IpOptHeader IpOpthdr = {0};
        IpOpthdr.code = IP_RECORD_ROUTE;
        IpOpthdr.ptr  = 4; /* point to the first IP address offset */
        IpOpthdr.len  = 39; /* length of IP option header */

        if (setsockopt(sockrawfd, IPPROTO_IP, IP_OPTIONS,
                        (char *)&IpOpthdr, sizeof(IpOpthdr)) == -1) {
            fprintf(stderr, "setsockopt error: %s\n", strerror(errno));
            exit(-1);
        }

        /* set send/recv timeout value */
        struct timeval timeout;
        timeout.tv_sec = 1; /* timeout 1s */
        timeout.tv_usec = 0;
        if (setsockopt(sockrawfd, SOL_SOCKET, SO_RCVTIMEO,
                        (char *)&timeout, sizeof(timeout)) == -1) {
            fprintf(stderr, "setsockopt timeout error: %s\n", strerror(errno));
            exit(-1);
        }

        /* resolve the endpoint's name if necessary */
        dest_addr.sin_family = AF_INET;
        //dest_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        if ((dest_addr.sin_addr.s_addr = inet_addr(operation.destAddr)) == INADDR_NONE) {
            if ((hp = gethostbyname(operation.destAddr)) != NULL) {
                memcpy(&dest_addr.sin_addr, hp->h_addr, hp->h_length);
                dest_addr.sin_family = hp->h_addrtype;
                printf("dest.sin_addr = %s\n", inet_ntoa(dest_addr.sin_addr));
            } else {
                fprintf(stderr, "gethostbyname failed: %s\n", strerror(errno));
                exit(-1);
            }
        }
    }

    int dateSize = operation.packetSize + ICMP_MIN;
    char IcmpDate[dateSize] = {0};
    while (true) {
        usleep(500 * 1000); /* sleep 500ms */
        icmp_request_packet(IcmpDate, dateSize);
        int wrote = sendto(sockrawfd, IcmpDate, dateSize, 0, 
                            (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            fprintf(stderr, "send timeout: %s\n", strerror(errno));
        } else if (wrote == -1) {
            fprintf(stderr, "send to failed: %s\n", strerror(errno));
        }

        recvByte = recvfrom(sockrawfd, recvBuff, sizeof(recvBuff), 0, (struct sockaddr *)&sockAdr, &len);

        if (recvByte == -1) {
            fprintf(stderr, "send timeout: %s\n", strerror(errno));
        } else 
            ip_packet_parse(recvBuff, recvByte);
        
        //usleep(500 * 1000); /* sleep 500ms */
    }
    
    return 0;
}
