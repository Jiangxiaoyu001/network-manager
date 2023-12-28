/*********************************************************
*
* Description: 
*   A free test demo for everyone
*   as socket raw , recvive all packets data 
*   which through network card(MAC), 
*  parse protocol-packet and Combined protoclo-packet
*	such as tcp/ip udp icmp arp and so on
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
#include <time.h>


using namespace std;

#define MAX_READ_LEN 1024



/* MAC header */

/* byte
|----- 6 -------|------ 6 ------|-- 2 --|

----------------|---------------|-------|
|des addr		| src addr		| type	|
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
| version   | header len | 	server type 		|		total len								|
|-----------|------------|----------------------|-------------|---------------------------------|
|		   identifier	   	 	|	flag  |    	offest	    		|
|-----------------------------------------------------------------------------------------------|
|      TTL |			protocol	|		checksum|
|------------------------|----------------------|-----------------------------------------------|
|					source IP						|
|-----------------------------------------------------------------------------------------------|
|					destination IP						|
|-----------------------------------------------------------------------------------------------|
|				optional				|	fill		|
|-----------------------------------------------------------------------|-----------------------|

*/

/*

- 1| - 2| --4| --6| --8| -9| -10| --12| ----16| ----20|
2 + 2 + 2 + 2 + 2  + 2 + 4 + 4 = 20(bytes)

*/

#pragma pack(4)
typedef struct _ip_hdr {
#if defined (__BIG_ENDIAN_BITFIELD)
	unsigned short version : 4;	/* 0 - 3  */ 
	unsigned short header_len : 4;	/* 4 - 7  */
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	unsigned short header_len : 4;	/* 0 - 3 */
	unsigned short version : 4;	/* 4 - 7 */
#endif
	unsigned short server_type : 8; /* 8 - 15 */
	unsigned short total_len ;
	unsigned short identidier;
#if defined (__BIG_ENDIAN_BITFIELD)
	unsigned short flag : 4;	/* 0 - 3  */
	unsigned short offest : 12;	/* 4 - 15 */
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

/* IP-header optional */
#pragma pack(1) /* cancel */
typedef struct _ip_option {
    unsigned char code; /* option type */
    unsigned char len; /* length of options */
    unsigned char ptr; /* offset into options */
    unsigned int  addr[9]; /* list of IP address */
} IpOptHeader;
#pragma pack() /* cancel */

/* ICMP  
----------- 32 bits -------------
|-- 8 --|-- 8 --|----- 16 ------|
|-------|-----------------------|
| type	| code	| checksum		|
|-------------------------------|
|identifier		| serial number	|
|---------------|---------------|
|	date						|
|-------------------------------|
*/

#pragma pack(4)
typedef struct _icmp_hdr {
    unsigned char  type;
    unsigned char  code;
    unsigned short checksum;
    unsigned short identifier;
    unsigned short seqNum;
//    unsigned long long   timestamp;
} IcmpHeader;
#pragma pack()


/* TCP 
|---------------------------- 32 bits --------------------------|
|------ 8 ------|----- 8 -------|----- 8 ------|-------	8 ------|

|---------------------------------------------------------------|
|	source port					|	destination port			|
|-------------------------------|-------------------------------|
|			serial number				|
|---------------------------------------------------------------|
|			ack number				|
|---------------------------------------------------------------|
| hd_len|  res	|	flag	|	windows size		|
|---------------------------------------------------------------|
|	  	checksum	|	urgent point		|
|---------------------------------------------------------------|
|	... optional fill......					|
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
	unsigned short offest : 4;	/* 0 - 3 */
	unsigned short reserve : 4;	/* 4 - 7 */
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	unsigned short reserve : 4;	/* 0 - 3 */
	unsigned short offest : 4;	/* 4 - 7 */
#endif
	unsigned short flag : 8;	/* 8 - 15 */
	unsigned short windowSize;
	unsigned short checksum;
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
struct {
	unsigned short macHeader_len;
	unsigned short ipHeader_len;
	unsigned short ipSrcAdrLen;
	unsigned short ipDesAdrLen;
	unsigned short icmpHeaderLen;
	unsigned short tcpHeaderLen;
	unsigned short udpHeaderLen;
} *p_headerLen, headerLen = {
	.macHeader_len = sizeof(mac_header),
	.ipHeader_len  = sizeof(IpHeader),
	.ipSrcAdrLen   = sizeof(unsigned int),
	.ipDesAdrLen   = sizeof(unsigned int),
	.icmpHeaderLen = sizeof(IcmpHeader),
	.tcpHeaderLen  = sizeof(tcpHeader),
	.udpHeaderLen  = sizeof(udpHeader)
	};

struct hostPriHandler{
	std::list<std::string> local_ipv4;
	std::list<std::string> local_ipv6;
} hostP = {
	.local_ipv4 = {""},
	.local_ipv6 = {""},
};  
struct hostPriHandler * hostPri = &hostP;


class sockManage {
public:
	explicit sockManage();
	~sockManage();
public:
	int recvByte;
	int sock_protocol_parse(const char *msg);
private:
	int macHeader();
	int ipHeader();
	
	/* sock packge  */
	int arp_package();
	int icmp_package();
	
	string icmp_timestamp_transition(unsigned int timestamp);
	
	unsigned short icmp_calc_checksum(char* icmp_packet, int size);

	/* sock packet parse*/
	int rarp_packet_parse(const char *msg);
	int icmp_packet_parse(const char *msg, int size);
	int arp_packet_parse(const char *msg);
	int ip_packet_parse(const char * msg);
	void ip_options_parse(const char *msg);
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
 * @Email: xinGuSoftware@163.com
 *
 * @Date: Thu Aug 11 2022 18:30
 * ************************************************************/

int sockManage::arp_packet_parse(const char *msg)
{
	cout << "\n arp packet" << endl;
	return 0;
	// struct in_addr src_adr, des_adr;
	// p_headerLen = &headerLen;

	// memset(pmac_header, 0, sizeof(*pmac_header));
	// memset(iphdr, 0, sizeof(*iphdr));

	// cout << "\nDES_MAC: ";
	// memcpy(pmac_header, msg, p_headerLen->macHeader_len);
	// for (int i = 0; i < 6; i++) {
	// 	printf("%02x:", (unsigned char)pmac_header->DesMacAddr[i]);
	// }
	// cout << "\nSRC_MAC: ";
	// for (int i = 0; i < 6; i++) {
    //     	printf("%02x:", (unsigned char)pmac_header->SrcMacAddr[i]);
	// }
	// memcpy(iphdr, &msg[p_headerLen->macHeader_len-1], p_headerLen->ipHeader_len);
}

/**        
 * ip_options_parse:
 * @msg: original network data packet
 * @bytes: the receive bytes from network
 * 
 *  If the IP option header is present, find the ip 
 *  options within the IP header and print record route option values
 *
 */ 
void sockManage::ip_options_parse(const char *msg)
{
	
	IpOptHeader * ipOpt = (IpOptHeader *)((char *)(msg) + 20);
	//printf("")
	printf("\nRR:\n");
	printf("options-code:%d\n", ipOpt->code);
	printf("options-len:%d\n",  ipOpt->len);
	printf("options-ptr:%d\n",  ipOpt->ptr);
	/* ip address number of count
		IP address is a binary receive from network byte order
	*/
	struct in_addr ipv4_addrs = {0};
	for (int i = 0; i < ( ipOpt->ptr / 4); i++) {
		ipv4_addrs.s_addr = ipOpt->addr[i];
		printf("(%-15s)\n", inet_ntoa(ipv4_addrs));
	}
}

/**        
 * ip_packet_parse:
 * @msg: IPV4 protocol packet
 * 
 * Already locate to IPV4 protocol packet from original network protocol packet
 * and decode IPV4 filed
 *
 */ 
int sockManage::ip_packet_parse(const char *msg)
{

	struct in_addr src_adr, des_adr = {0};
	p_headerLen = &headerLen;

	/* locate to IP header */
	IpHeader * iphdr = (IpHeader *)msg;

	/* calculation ip header size */
	unsigned int ipHeader_size = iphdr->header_len * 4;
	unsigned int ipDataSize = ntohs(iphdr->total_len) - iphdr->header_len * 4;

	//memcpy(iphdr, &msg[p_headerLen->macHeader_len], ipHeader_size);
	memcpy(&src_adr, &iphdr->src_addr, p_headerLen->ipSrcAdrLen);
	memcpy(&des_adr, &iphdr->des_addr, p_headerLen->ipSrcAdrLen);

	cout << "\t\tmacHeader_len:" << dec << p_headerLen->macHeader_len << endl;
	cout << "\t\tipHeader_len:"  << dec << (iphdr->header_len * 4) << endl;

	printf("IP PROTOCOL:( \n");
	printf("version:%d\n", iphdr->version);
	printf("header_len:%d\n", iphdr->header_len * 4);
	printf("server_type:%d\n", iphdr->server_type);
	printf("total_len:%d\n", ntohs(iphdr->total_len));
	printf("flag:%d\n", iphdr->flag);
	printf("ttl:%d\n", iphdr->ttl);

	cout << "src_ip:" << inet_ntoa(src_adr) << endl;
	cout << "des_ip:" << inet_ntoa(des_adr) << endl;
	
	printf("dataLen:%d )\n", ipDataSize);

	/* Ip options decode */
	if (iphdr->header_len > 5)
		ip_options_parse((char *)iphdr);
	
	/* ip header len = headerLen * 4  
		max(headerLen):1111(b)/15(d) 
		min(headerLen):0101(b)/5(d)
	*/
	p_headerLen->ipHeader_len = iphdr->header_len * 4;
	if ( p_headerLen->ipHeader_len < 20 | p_headerLen->ipHeader_len > 60)
		printf("ip header(%d) less 20bytes , so fill %d bytes\n", 20 - p_headerLen->ipHeader_len);

	switch (static_cast<unsigned short>(iphdr->protocol)) {
	case IPPROTO_ICMP:
       	printf("ICMP protocol\n");
		icmp_packet_parse(msg + p_headerLen->ipHeader_len, ipDataSize);
        break;
    case IPPROTO_IGMP:
        printf("IGMP protocol\n");
        break;
	case IPPROTO_IPIP:
        printf("IPIP protocol\n");
        break;
    case IPPROTO_TCP:
		tcp_packet_parse(msg + p_headerLen->ipHeader_len);
		break;
	case IPPROTO_UDP:
		udp_packet_parse(msg + p_headerLen->ipHeader_len);
		break;
	default:
		printf("unknow protocol:0x%02x:\n", iphdr->protocol);
		break;
	}

	return 0;
}

int sockManage::rarp_packet_parse(const char *msg)
{
	cout << "rarp packet" << endl;
	return 0;
	// struct in_addr src_adr, des_adr;
	// p_headerLen = &headerLen;

	// memset(pmac_header, 0, sizeof(*pmac_header));
	// memset(iphdr, 0, sizeof(*iphdr));

	// cout << "\nDES_MAC: ";
	// memcpy(pmac_header, msg, p_headerLen->macHeader_len);
	// for (int i = 0; i < 6; i++) {
	// 	printf("%02x:", (unsigned char)pmac_header->DesMacAddr[i]);
	// }
	// cout << "\nSRC_MAC: ";
	// for (int i = 0; i < 6; i++) {
    //     	printf("%02x:", (unsigned char)pmac_header->SrcMacAddr[i]);
	// }
	// memcpy(iphdr, &msg[p_headerLen->macHeader_len-1], p_headerLen->ipHeader_len);
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

	return 0;
}

/**
 * sock_protocol_parse:
 * @msg: Receive original network packet
 * @return: On success return 0, on error, return -1
 *
 * Receive All original network protocol packet, delive to 
 * feature to decode
 */
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
		ip_packet_parse(msg + p_headerLen->macHeader_len);
		break;
	case 0x0806:
		arp_packet_parse(msg);
		break;
	case 0x0835:
		rarp_packet_parse(msg);
		break;
	default:
		cout << "\nunknow protocol packet:" << hex << ntohs(pmac_header->NetworkType) << endl;
		break;
	}
	
	return 0;
}

/**
 * icmp_timestamp_transition:
 * @timestamp: current timestamp
 * @return: return readabled time format
 *
 */
string sockManage::icmp_timestamp_transition(unsigned int timestamp)
{

	time_t tm_t = timestamp;
	struct tm * time_info = ::localtime(&tm_t);
	
	char time_str[50] = {0};  
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", time_info);

	return string(time_str);
}

/**                                                            
 * icmp_calc_checksum:
 * @size: the icmp data packet length
 * @icmp_data: icmp protocol packet both header and data
 *
 * Calc icmp's checksum:
 * if we divide the ICMP data packet is 16 bit words and sum each of them up
 * then hihg 16bit add low 16bit to sum get a value,  
 * If the total length is odd, 
 * the last byte is padded with one octet of zeros for computing the checksum.
 * Then hihg 16bit add low 16bit to sum get a value,
 * finally do a one's complementing 
 * then the value generated out of this operation would be the checksum.
 * 
 * Return: unsigned short checksum
 */
unsigned short sockManage::icmp_calc_checksum(char * icmp_packet, int size)
{
	unsigned short * sum = (unsigned short *)icmp_packet;
	unsigned int checksum = 0;
	while (size > 1) {
		checksum += ntohs(*sum++);
		size -= sizeof(unsigned short);
	}
	if (size) {
		*sum = *((unsigned char*)sum);
		checksum += ((*sum << 8) & 0xFF00);
	}

	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += checksum >> 16;
	
	return (unsigned short)(~checksum);
}


/**        
 * icmp_packet_parse:
 * @msg: ICMP protocol packet
 * @size: ICMP packet size
 * 
 * Already locate to ICMP protocol packet from original network protocol packet
 * and decode ICMP header
 *
 */ 
int sockManage::icmp_packet_parse(const char *msg, int size)
{
	IcmpHeader * Icmphdr = (IcmpHeader *)msg;


	cout << "\t\tsize:" << size << endl;
	printf("\t\ttype:0x%02x\n", Icmphdr->type);
	printf("\t\tcode:0x%02x\n", Icmphdr->code);
	printf("\t\tchecksum:0x%02x\n", ntohs(Icmphdr->checksum));
	printf("\t\tidentifiler:0x%02x\n", ntohs(Icmphdr->identifier));
	printf("\t\tseqNum:0x%02x\n", ntohs(Icmphdr->seqNum));

	
	for (int i = 0; i < size; i++) {
		printf("0x%02x ", ((unsigned char*)Icmphdr)[i]);
	}
	printf("\n");

	Icmphdr->checksum = 0;
	printf("checksum:%02x\n", icmp_calc_checksum((char *)Icmphdr, size));

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
 *@Email: xinGuSoftware@163.com
 *
 *@Date: Wed Aug 10 2022 18：00
 *************************************************/

int sockManage::arp_package()
{
	return 0;
}

int main(int argc, char * argv[])
{
	sockManage sockmg;
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
	
    int sockrawfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	//int sockrawfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockrawfd == -1) {
		std::cout << "sock raw create failed" << endl;
		return -1;	
	} else
		std::cout << "sock raw created succeed" << endl;

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
