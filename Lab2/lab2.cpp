#include<WinSock2.h>
#include<iostream>
#include<pcap.h>
#include<stdio.h>
#include<time.h>
#include<string>
#include<iomanip>
#pragma comment(lib,"ws2_32.lib")//���ӵ�ʱ����ws2_32.lib
#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma warning(disable:4996)//ʹ�þɺ���
using namespace std;

//���屨�ĸ�ʽ
#pragma pack(1)//�����ֽڶ��뷽ʽ 
struct ethernet_header {//֡�ײ�
	uint8_t mac_dst[6];//Ŀ��MAC��ַ
	uint8_t mac_src[6];//ԴMAC��ַ
	uint16_t frame_type;//֡����
};

//ip��ַ��ʽ
typedef uint32_t in_addr_t;
struct ip_header {//ip�ײ�
	uint8_t ip_header_length : 4,//�ײ�����
		ip_version : 4;//�汾

	uint8_t ip_tos;//��������
	uint16_t total_len;//�ܳ���
	uint16_t ip_id;//��ʶ
	uint16_t ip_off;//Ƭƫ��
	uint8_t ip_ttl;//����ʱ��
	uint8_t ip_protocol;//Э������
	uint16_t ip_checksum;//�ײ������
	struct in_addr ip_source_address;//ԴIP��ַ
	struct in_addr ip_destination_address;//Ŀ��IP��ַ
};

//IP���ݰ���������
void ip_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content) {
	struct ip_header* ip_protocol;//IPЭ�����
	u_int header_length;//����
	u_int offset;//Ƭƫ��
	u_char tos;//��������
	uint16_t checksum;//�ײ������
	ip_protocol = (struct ip_header*)(packet_content + 14);//���IP���ݰ������� ȥ����̫ͷ//��Ϊǰ14�ֽ�ͨ������̫���ײ���������Ҫ������̫���ײ����֣��Ի�ȡ��IPv4�ײ���
	checksum = ntohs(ip_protocol->ip_checksum);//��ü����
	header_length = ip_protocol->ip_header_length * 4;//��ó���//IPv4�ײ�������32λ��Ϊ��λ��������Ҫ�������4�Ի�ȡʵ���ֽ�����
	tos = ip_protocol->ip_tos;//���tos��������
	offset = ntohs(ip_protocol->ip_off);//���ƫ����
	cout << "\n=============����㣨IPЭ�飩=============\n";
	printf("IP�汾��\t\tIPv%01X\n", ip_protocol->ip_version);//
	cout << "IPЭ���ײ�����\t" << header_length << endl;
	cout << "�ܳ���:\t\t" << ntohs(ip_protocol->total_len) << endl;//����ܳ���
	cout << "��ʶ:\t\t" << ntohs(ip_protocol->ip_id) << endl;//��ñ�ʶ
	cout << "Ƭƫ��:\t\t" << (offset & 0x1fff) * 8 << endl;
	printf("����ʱ��:\t%01X\n", ip_protocol->ip_ttl);//���ttl
	cout << "�ײ������:\t" << checksum << endl;
	cout << "ԴIP:\t" << inet_ntoa(ip_protocol->ip_source_address) << endl;//���Դip��ַ
	cout << "Ŀ��IP:\t" << inet_ntoa(ip_protocol->ip_destination_address) << endl;//���Ŀ��ip��ַ
	printf("Э���:\t%01X\n", ip_protocol->ip_protocol);//���Э������
	cout << "\n�����Э����:\t";
	switch (ip_protocol->ip_protocol) {
	case 1:
		cout << "ICMP" << endl;
		break;
	case 2:
		cout << "IGMP" << endl;
		break;
	case 3:
		cout << "GGP" << endl;
		break;
	case 6:
		cout << "TCP" << endl;
		break;
	case 8:
		cout << "EGP" << endl;
		break;
	case 17:
		cout << "UDP" << endl;
		break;
	case 89:
		cout << "OSPF" << endl;
		break;
	default:break;
	}
}

//����������·��
void ethernet_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content) {
	u_short ethernet_type;//��̫��Э������
	struct ethernet_header* ethernet_protocol;//��̫��Э�����
	uint8_t* mac_src;//MacԴ��ַ
	uint8_t* mac_dst;//MacĿ�ĵ�ַ
	static int packet_number = 1;//ץ������
	cout << endl;
	printf("�ڡ� %d ����IP���ݰ�������\n", packet_number);
	cout << "===========��·�㣨��̫��Э�飩===========" << endl;
	ethernet_protocol = (struct ethernet_header*)packet_content;//�����̫��Э����������//ָ��ָ�򲶻�����ݰ����ݵ���ʼλ�ã��Ա������̫���ײ�
	cout << "��̫�����ͣ�\t";
	ethernet_type = ntohs(ethernet_protocol->frame_type);//�����̫������//ntohs �����������ֽ���ת��Ϊ�����ֽ���
	cout << ethernet_type << endl;
	switch (ethernet_type) {//�ж���̫������
	case 0x0800:
		cout << "������ǣ�  IPv4Э��\n" << endl;
		break;
	case 0x0806:
		cout << "������ǣ�  ARPЭ��\n" << endl;
		break;
	case 0x0835:
		cout << "������ǣ�  RARPЭ��\n" << endl;
		break;
	default:break;
	}

	//MacԴ��ַ
	mac_src = ethernet_protocol->mac_src;
	printf("MacԴ��ַ:\t%02x:%02x:%02x:%02x:%02x:%02x:\n", *mac_src, *(mac_src + 1), *(mac_src + 2), *(mac_src + 3), *(mac_src + 4), *(mac_src + 5));//X ��ʾ��ʮ��������ʽ��� 02 ��ʾ������λ��ǰ�油0��� 
	//MacĿ�ĵ�ַ
	mac_dst = ethernet_protocol->mac_dst;
	printf("MacĿ�ĵ�ַ:\t%02x:%02x:%02x:%02x:%02x:%02x:\n", *mac_dst, *(mac_dst + 1), *(mac_dst + 2), *(mac_dst + 3), *(mac_dst + 4), *(mac_dst + 5));

	switch (ethernet_type) {
	case 0x0800://����ϲ���IPv4Э��,�͵��÷���ipЭ��ĺ�����IP���ݰ����н�һ���Ľ���
		ip_protocol_packet_callback(argument, packet_header, packet_content);
		break;
	default:break;
	}
	packet_number++;
}

int main() {
	cout << "=========== ����IP���ݰ���ʼ@_@ ===========\n";
	pcap_if_t* alldevs;//ָ�������б��ָ�룬���л���������ƺ�����
	pcap_if_t* d;//���ڱ��������б��ָ��
	int i = 0;//���ڱ�������
	int num = 0;//���ĸ����������룩
	pcap_t* adhandle;//����������������׽ʵ��,��pcap_open���صĶ���
	char errbuf[PCAP_ERRBUF_SIZE];//�洢������Ϣ���ַ�����

	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		cout << stderr << "��ȡ����ʧ��:%s\n" << errbuf;
		exit(1);
	}
	//��ӡ������Ϣ
	for (d = alldevs; d; d = d->next) {
		cout << ++i << d->name;
		if (d->description)
			cout << d->description;
		else
			cout << "No description available\n";
		cout << endl;
	}

	if (i == 0) {
		return -1;
	}
	//��ʱ��������Ϊi
	cout << "\n������Ҫ�򿪵������� (1-" << i << "):\t";
	cin >> num;

	if (num<1 || num>i) {
		cout << "Error!�����ų�����Χ��";
		pcap_freealldevs(alldevs);//�ͷ��豸�б�
		return -1;
	}

	/*�������� alldevs���ҵ��û�ָ�����������������num��Ӧ��������������Ϣ��
	ÿ�ε�����������ĵ�ǰ�ڵ�ָ�� d �ƶ�����һ���ڵ㣬������ i��ֱ�� i �ﵽ num - 1 ʱ��ѭ��ֹͣ��
	������d ��ָ�����û�ѡ���������������Ϣ*/
	for (d = alldevs, i = 0; i < num - 1; d = d->next, i++);

	/*ʹ�� pcap_open_live ������ѡ����������������
	����һ������ʵ�� adhandle�����ں��������ݰ��������*/
	if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL) {
		cout << stderr << "Error!";
		pcap_freealldevs(alldevs);
		return -1;
	}
	cout << "\n����" << d->description;
	pcap_freealldevs(alldevs);//�ͷ���ǰ����� alldevs �����ڴ�

	int cnt = 0;
	cout << "\n��Ҫ�������ݰ��ĸ�����\t\t";
	cin >> cnt;

	/*pcap_loop ��������ָ������cnt�����ݰ���
	ÿ�����ݰ����ᴫ�ݸ� ethernet_protocol_packet_callback �������н�������ʾ��*/
	pcap_loop(adhandle, cnt, ethernet_protocol_packet_callback, NULL);
	cout << "\n\t����IP���ݰ�������\n";
	return 0;
}