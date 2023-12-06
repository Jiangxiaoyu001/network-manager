/*********************************************************
*
* Description: 
*   A free test demo for everyone
*       as socket raw , recvive all packets data 
*       which through network card(MAC), 
*       parse protocol-packet such as tcp/ip udp and so on
*
* Datetime: Tuesday April 19 2022
*
* Author: jiangxiaoyu
*
* Email: xinGuSoftWare@163.com
*
****************************************************************/


#include <iostream>
#include <stdio.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netdb.h>
#include <thread>
#include <list>
#include <unistd.h>
#include <string.h>
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

using namespace std;

#define MAX_READ_LEN 1024


/* MAC header */

/* byte
|----- 6 -------|------ 6 ------|-- 2 --|

----------------|---------------|-------|
|des addr       | src addr      | type  |
|---------------|---------------|-------|

*/

struct{
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
struct{
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
} *p_ipheader, ip_header;
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

#pragma pack(4)
struct{
	unsigned char type;
	unsigned char code;
	unsigned char checksum;
	unsigned short identifier;
	unsigned short serNum;
} *p_icmpHeader, icmpHeader;
#pragma pack()

/* TCP 
|---------------------------- 32 bits --------------------------|
|------ 8 ------|----- 8 -------|----- 8 ------|------- 8 ------|

|---------------------------------------------------------------|
|       source port             |       destination port        |
|-------------------------------|-------------------------------|
|                       serial number                           |
|---------------------------------------------------------------|
|                       ack number                              |
|---------------------------------------------------------------|
| hd_len|  res  |       flag    |       windows size            |
|---------------------------------------------------------------|
|               checksum        |       urgent point            |
|---------------------------------------------------------------|
|       ... optional fill......                                 |
-----------------------------------------------------------------
*/


/* TCP struct */
#pragma pack(4)
struct {
	unsigned short srcPort;
	unsigned short desPort;
	unsigned int serialNum;
	unsigned int acknowledgeNum;
	#if defined (__BIG_ENDIAN_BITFIELD)
	unsigned short offest : 4;   /* 0 - 3 */
	unsigned short reserve : 4;     /* 4 - 7 */
	#elif defined(__LITTLE_ENDIAN_BITFIELD)
	unsigned short reserve : 4;     /* 0 - 3 */
	unsigned short offest : 4;   /* 4 - 7 */
	#endif
	unsigned short flag : 8;        /* 8 - 15 */
	unsigned short windowSize;
	unsigned short checkSum;
	unsigned short urgPoint;
} *p_tcpHeader, tcpHeader;
#pragma pack()


/* UDP */
#pragma pack(4)
struct {
	unsigned short srcPort;
	unsigned short desPort;
	unsigned short len;
	unsigned short checksum;
} *p_udpHeader, udpHeader;
#pragma pack()


/* header len */
struct{
	unsigned short macHeader_len;
	unsigned short ipHeader_len;
	unsigned short ipSrcAdrLen;
	unsigned short ipDesAdrLen;
	unsigned short icmpHeaderLen;
	unsigned short tcpHeaderLen;
	unsigned short udpHeaderLen;
} *p_headerLen, headerLen={
	.macHeader_len = sizeof(mac_header),
	.ipHeader_len = sizeof(ip_header),
	.ipSrcAdrLen = sizeof(ip_header.src_addr),
	.ipDesAdrLen = sizeof(ip_header.des_addr),
	.icmpHeaderLen = sizeof(icmpHeader),
	.tcpHeaderLen = sizeof(tcpHeader),
	.udpHeaderLen = sizeof(udpHeader)
	};

struct hostPriHandler{
	std::list<std::string> local_ipv4;
	std::list<std::string> local_ipv6;
} hostP = {
	.local_ipv4 = {""},
	.local_ipv6 = {""},
};  
struct hostPriHandler * hostPri = &hostP;


class sockManage{
public:
	explicit sockManage();
	~sockManage();
public:
	int recvByte;
	int sock_protocol_parse(const char *msg);
private:
	int macHeader();
	int ipHeader();

	/* sock packet parse*/
	int ip_packet_parse(const char * msg);
	int tcp_packet_parse(const char * msg);
	int udp_packet_parse(const char * msg);
	
	int get_local_ip();
};


sockManage::sockManage():recvByte(0)
{
	get_local_ip();
}


sockManage::~sockManage() {

}


int sockManage::get_local_ip()
{
        
	struct ifaddrs *ifa = nullptr;
	int family, s, n = 0;
	char host[NI_MAXHOST] = {0};
	
	if (getifaddrs(&ifa) == -1) {
		perror("getifaddrs");
		return -1;
	}
    /* Walk through linked list, maintaining head pointer so we
    can free list later */
    
	for (; ifa != NULL; ifa = ifa->ifa_next, n++) {
		if (ifa->ifa_addr == NULL)
			continue;
	
		family = ifa->ifa_addr->sa_family;
	
	 /* Display interface name and family (including symbolic
	             form of the latter for the common families) */
	      
	
		 printf("%-8s %s (%d)\n",
			 ifa->ifa_name,
			 (family == AF_PACKET) ? "AF_PACKET" :
			 (family == AF_INET) ? "AF_INET" :
			 (family == AF_INET6) ? "AF_INET6" : "???",
			 family);
	
	
	        
	    /* For an AF_INET* interface address, display the address */
	
		if (family == AF_INET || family == AF_INET6) {
			s = getnameinfo(ifa->ifa_addr,
		       			(family == AF_INET) ? sizeof(struct sockaddr_in) :
						sizeof(struct sockaddr_in6), 
		               	host, NI_MAXHOST,
						NULL, 0, NI_NUMERICHOST);
			if (s != 0) {
				printf("getnameinfo() failed: %s\n", gai_strerror(s));
				return -1;
			}
			if(atoi(host) != atoi("127.0.0.1")) {
				(family == AF_INET) ? hostPri->local_ipv4.push_back(host) : 
				(family == AF_INET6) ? hostPri->local_ipv6.push_back(host) :
				hostPri->local_ipv6.push_back("???");
			}
		           
			 printf("\t\taddress: <%s>\n", host);
		 } else if (family == AF_PACKET && ifa->ifa_data != nullptr) {
			 struct rtnl_link_stats *stats = reinterpret_cast<struct rtnl_link_stats *>(ifa->ifa_data);
			 printf("\t\ttx_packets = %10u; rx_packets = %10u\n"
			 "\t\ttx_bytes   = %10u; rx_bytes   = %10u\n",
			 stats->tx_packets, stats->rx_packets,
			 stats->tx_bytes, stats->rx_bytes);
		 }
    }

    freeifaddrs(ifa);
    return 0;
}



/*************************************************************
 *
 * @Description: network package parse
 *
 * @Author: jiangxiaoyu
 *
 * @Email: xinGuSoftWare@163.com
 *
 * @Date: Thu Aug 11 2022 18:30
 * ************************************************************/

int sockManage::ip_packet_parse(const char *msg)
{

	cout << "\t\tipHeader_len:" << dec << p_headerLen->ipHeader_len << endl;
	cout << "\t\tmacHeader_len:" << dec << p_headerLen->macHeader_len << endl;
	
	struct in_addr src_adr, des_adr = {0};
	p_headerLen = &headerLen;
	memset(p_ipheader, 0, sizeof(ip_header));
	
	memcpy(p_ipheader, &msg[p_headerLen->macHeader_len], p_headerLen->ipHeader_len);
	memcpy(&src_adr, &p_ipheader->src_addr, p_headerLen->ipSrcAdrLen);
	memcpy(&des_adr, &p_ipheader->des_addr, p_headerLen->ipDesAdrLen);
	
	printf("version:%d\n", p_ipheader->version);
	printf("header_len:%d\n", p_ipheader->header_len);
	printf("server_type:%d\n", p_ipheader->server_type);
	printf("total_len:%d\n", ntohs(p_ipheader->total_len));
	printf("flag:%d\n", p_ipheader->flag);
	printf("ttl:%d\n", p_ipheader->ttl);
	printf("dataLen:%d\n", ntohs(p_ipheader->total_len) - p_ipheader->header_len * 4);
	
	cout << "src_ip:" << inet_ntoa(src_adr) << endl;
	cout << "des_ip:" << inet_ntoa(des_adr) << endl;
	
	/* ip header len = headerLen * 4  max(headerLen):1111(b)/15(d) */
	unsigned short ipHeaderLen = p_ipheader->header_len * 4;
	if ( ipHeaderLen < 20 | ipHeaderLen > 60)
		printf("ip header(%d) less 20bytes , so fill %d bytes\n", 20 - p_ipheader->header_len);
	
	switch (static_cast<unsigned short>(p_ipheader->protocol)) {
	case IPPROTO_TCP:
		tcp_packet_parse(&msg[p_headerLen->macHeader_len + p_headerLen->ipHeader_len]);
		break;
	case IPPROTO_UDP:
		udp_packet_parse(&msg[p_headerLen->macHeader_len + p_headerLen->ipHeader_len]);
		break;
	default:
		printf("unknow protocol:0x%02x:\n", p_ipheader->protocol);
		break;
	}
	
	return 0;
}

int sockManage::tcp_packet_parse(const char *msg)
{
	p_tcpHeader = &tcpHeader;
	memset(p_tcpHeader, 0, p_headerLen->tcpHeaderLen);
	memcpy(p_tcpHeader, msg, p_headerLen->tcpHeaderLen);
	
	/* big endian to little endian
	unsigned short src_port, temp = 0;
	temp = (src_port | msg[0] &0x00FF) << 8;
	src_port = (temp & 0xFF00) | msg[1];
	*/
	
	unsigned int dataLen = this->recvByte - (p_headerLen->tcpHeaderLen +
	                        p_headerLen->macHeader_len + p_headerLen->ipHeader_len);
	
	char data[MAX_READ_LEN] = {0};
	
			/* cp tcp text-part message */
	memcpy(data, &msg[p_headerLen->tcpHeaderLen], dataLen);
	
	
	cout << "TCP portocol" << endl;
	cout << "\t\trecvByte:" << this->recvByte << endl;
	cout << "\t\theaderLen:" << p_tcpHeader->offest * 4 << endl;
	cout << "\t\ttcp text-part data size:" << dataLen << endl;
	cout << "\t\tsrc_port:" << ntohs(p_tcpHeader->srcPort) << endl;
	cout << "\t\tdes_port:" << ntohs(p_tcpHeader->desPort) << endl;
	cout << "\t\tacknowledge number:" << ntohs(p_tcpHeader->acknowledgeNum) << endl;
	cout << "\t\tflag:" << p_tcpHeader->flag << endl;
	
	/*
	for (int i = 0; i < dataLen - 1; i++)
	        printf("recvData[%d]:0x%x\n", i, (unsigned char)data[i]);
	cout << endl;
	*/
	return 0;
} 

int sockManage::udp_packet_parse(const char * msg)
{
	p_udpHeader = &udpHeader;
	memset(p_udpHeader, 0, p_headerLen->udpHeaderLen);
	memcpy(p_udpHeader, msg, p_headerLen->udpHeaderLen);
	    
	char data[MAX_READ_LEN] = {0};
	unsigned int dataLen = this->recvByte - (p_headerLen->udpHeaderLen +
	                        p_headerLen->macHeader_len + p_headerLen->ipHeader_len);
	
	/* cp udp text-part messages */
	memcpy(data, &msg[p_headerLen->udpHeaderLen], dataLen);
	
	cout << "UDP portocol" << endl;
	cout << "\t\trecvByte:" << this->recvByte << endl;
	cout << "\t\theader len:" << p_headerLen->udpHeaderLen << endl;
	cout << "\t\ttext-part data size:" << dataLen << endl;
	cout << "\t\ttotol_len:" << ntohs(p_udpHeader->len) << endl;
	cout << "\t\tsrc_port:" << ntohs(p_udpHeader->srcPort) << endl;
	cout << "\t\tdes_port:" << ntohs(p_udpHeader->desPort) << endl;
	cout << "\t\tcheck sum:" << ntohs(p_udpHeader->checksum) << endl;
}

int sockManage::sock_protocol_parse(const char *msg)
{
	 struct in_addr src_adr, des_adr;
	 p_headerLen = &headerLen;
	
	 memset(pmac_header, 0, sizeof(mac_header));
	
	 cout << "\nDES_MAC: ";
	 memcpy(pmac_header, msg, p_headerLen->macHeader_len);
	 for (int i = 0; i < 6; i++) {
	 	printf("%02x:", (unsigned char)pmac_header->DesMacAddr[i]);
	 }
	 cout << "\nSRC_MAC: ";
	 for (int i = 0; i < 6; i++) {
	 	printf("%02x:", (unsigned char)pmac_header->SrcMacAddr[i]);
	 }
	
	 cout << hex << "\nnet type:" << ntohs(pmac_header->NetworkType) << endl;
	 /*  byte order convert , network to host */
	 switch (ntohs(pmac_header->NetworkType)) {
	 case 0x0800:
     	ip_packet_parse(msg);
     	break;
	 /*
	 other protocol
	 */
	 default:
        cout << "\nunknow protocol packet:" << hex << ntohs(pmac_header->NetworkType) << endl;
        break;
	 }
	 return 0;
}

/************************************************************
 * @Description: network package response
 *
 * @Usage: network layer protocol package had been filled,
 * only need select feature function wihic message own want to send
 *
 *@Author: jiangxiaoyu
 *
 *@Email: xinGuSoftWare@163.com
 *
 *@Date: Wed Aug 10 2022 18：00
 *************************************************/


int main(int argc, char * argv[])
{
    sockManage sockmg;
    p_ipheader = &ip_header;
    pmac_header = &mac_header;

    char recvBuff[1024] = {0};
    ssize_t recvByte = 0;
    struct sockaddr_in sockAdr;
    socklen_t len = sizeof(sockAdr);
    memset(&sockAdr, 0, sizeof(sockAdr));
    memset(&mac_header, 0, sizeof(mac_header));
    memset(&ip_header, 0, sizeof(ip_header));

    /* int socket(int domain, int type, int protocol); */

    /* family:

       PF_PACKET : link layer
       AF_INET   : network layer /ipv4
       AF_INET   : network layer /ipv6 
    */

    int sockrawfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockrawfd == -1) {
		std::cout << "sock raw create failed" << endl;
   		return -1;
    } else
		std::cout << "sock raw created succeed" << endl;

	struct ifreq ifstruct;
	struct sockaddr_in serverAdr;
	
	memset(&serverAdr, 0, sizeof(serverAdr));
	memset(&ifstruct, 0, sizeof(ifstruct));
	serverAdr.sin_family = AF_PACKET;
	serverAdr.sin_port = htons(ETH_P_ALL); /* all port */
	serverAdr.sin_addr.s_addr = htonl(INADDR_ANY);

/*
    if (setsockopt(sockrawfd, SOL_SOCKET, SO_BINDTODEVICE, &ifstruct, sizeof(ifstruct)) < 0)
    {
            cout << "socket setsockopt error" << endl;
            printf("bind interface fail, errno: %d \r\n", errno);
    close(sockrawfd);
    return -2;
    }

    addr_ll.sll_ifindex = ifstruct.ifr_ifindex;

*/
	while (true) {

		recvByte = recvfrom(sockrawfd, recvBuff, sizeof(recvBuff), 0, (struct sockaddr *)&sockAdr, &len);
		
		 /*  */
		 switch (errno) {
		 case  ECONNREFUSED:
		     cout << "recv error: A remote host refused to allow the network connection \
		           (typically because it is not running the requested service)." << endl;
		 case ENOTCONN:
		     cout << "The socket is associated with a connection-oriented protocol and has not been connected" << endl;
		 case ENOTSOCK:
		     cout << "The file descriptor sockfd does not refer to a socket." << endl;
		 }
		 if (recvByte == -1) {}
		 else {
		     cout << "==========================================" << endl;
		     sockmg.recvByte = recvByte;
		     sockmg.sock_protocol_parse(recvBuff);
		     memset(recvBuff, 0, sizeof(recvBuff));
		 }
		 recvByte = -1;
		 std::this_thread::sleep_for(std::chrono::milliseconds(1*1000)); /* thread sleep 500ms */
	}
}
