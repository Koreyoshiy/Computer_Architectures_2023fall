#ifndef USER_DEFINED_DATA_H
#define USER_DEFINED_DATA_H
#define WIN32
#define WPCAP
#define HAVE_REMOTE
#include "pcap.h"
#include<WinSock2.h>
#include <process.h>
#include <stdio.h>
#include <bitset>
#include <time.h>
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define BYTE unsigned char
#define MAX_SIZE 2048
#define MAX_BUFFER 50

#pragma pack(1)		//�����ֽڶ��뷽ʽ

//֡�ײ�
typedef struct FrameHeader_t {
	BYTE DesMAC[6];//Ŀ�ĵ�ַ
	BYTE SrcMAC[6];//Դ��ַ
	WORD FrameType;//֡����
}FrameHeader_t;

//ARP����֡
typedef struct ARPFrame_t {
	FrameHeader_t FrameHeader;//֡�ײ�
	WORD HardwareType;//Ӳ������
	WORD ProtocolType;//Э�鳤��
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	DWORD SendIP;
	BYTE RecvHa[6];
	DWORD RecvIP;
}ARPFrame_t;

//IP�ײ�
typedef struct IPHeader_t {
	BYTE Ver_HLen;
	BYTE TOS;
	WORD TotalLen;
	WORD ID;
	WORD Flag_Segment;
	BYTE TTL;//��������
	BYTE Protocol;
	WORD Checksum;//У���
	ULONG SrcIP;//ԴIP
	ULONG DstIP;//Ŀ��IP
}IPHeader_t;

//IP���ݱ�������֡�ײ���IP�ײ������ݰ�
typedef struct IPFrame_t {//����֡�ײ���IP�ײ������ݰ�
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
}IPFrame_t;

// ICMP�ײ�
typedef struct ICMPHeader_t {
	BYTE    Type;
	BYTE    Code;
	WORD    Checksum;
	WORD    Id;
	WORD    Sequence;
}ICMPHeader_t;

#pragma pack()	//�ָ�ȱʡ���뷽ʽ

/*·����������ݽṹ*/

//·�ɱ���
class RoutingEntry
{
public:
	RoutingEntry* next;
	int index;//����
	DWORD mask;//����
	DWORD dst_net;//Ŀ������
	DWORD next_hop;//��һ����IP��ַ
	BYTE nextMAC[6];//��һ����MAC��ַ
	int flag;//0Ϊֱ�����ӣ�����ɾ������1Ϊ�û����
	RoutingEntry() {
		next = NULL;
		index = 0;
		mask = 0;
		dst_net = 0;
		next_hop = 0;
		flag = 0;
	}
	RoutingEntry(int index, DWORD dstNetwork, DWORD mask, DWORD nextHop, int access)
	{
		this->index = index;
		this->dst_net = dstNetwork;
		this->mask = mask;
		this->next_hop = nextHop;
		this->flag = access;
	}
	void print();
};

//·�ɱ�
//����������ʽ��֯�������ƥ��ԭ������Խ��Խ��ǰ������ԽС
class RoutingTable {
public:
	RoutingEntry* head, * last;//ͷ�ڵ�
	int num;//����
	RoutingTable();//��ʼ�������ֱ������������
	void add(RoutingEntry* entry);//���·�ɱ��ֱ������������ǰ�棬����İ����ƥ��ԭ��
	void remove(int number);//ɾ����i��·�ɱ��ֱ�������Ĳ���ɾ��
	void print();
	DWORD search(DWORD dstip);//�����ƥ��ԭ�������һ����ip��ַ

};

/*ARP��ַӳ���*/
class ArpTable {
public:
	DWORD IP;
	BYTE MAC[6];
	static int num;
	static void add(DWORD IP, BYTE MAC[6]);
	static int search(DWORD IP, BYTE MAC[6]);
};

/*ת�������ݱ��ṹ*/
class Datagram
{
public:
	BYTE			Data[MAX_SIZE];// ���ݻ���
	int				Len;// ���ݰ��ܳ���
	ULONG			dst_IP;//Ŀ��IP��ַ
	bool			isValid = 1; //��Чλ������Ѿ���ת�����߳�ʱ������0
	clock_t			time;// ��ʱ�ж�
	Datagram() {};
	Datagram(const Datagram& x)//���ƹ��캯��--->��飡����
	{
		memcpy(this->Data, x.Data, x.Len);
		this->Len = x.Len;
		this->dst_IP = x.dst_IP;
		this->isValid = x.isValid;
		this->time = x.time;
	}
};


/*��־����*/
//д�����־����������ARP���ݱ�������ARP���ݱ�������IP���ݱ���ת��IP���ݱ�������ICMP���ݱ�

class Log
{
public:
	Log();//���ļ�����д��
	~Log();//�ر��ļ���
	static FILE* logFile;
	//д����־
	static void addInfo(const char* info/*��־��Ϣ��ʶ*/);
	static void addInfohop(const char* info/*��־��Ϣ��ʶ*/, DWORD hop);//������������Ϣ
	static void ARPInfo(const char* info/*��־��Ϣ��ʶ*/, ARPFrame_t* p);//arp����
	static void IPInfo(const char* info, IPFrame_t* p);//ip����
	static void ICMPInfo(const char* info);//icmp����
};

//////////

void printMac(BYTE MAC[]);
unsigned short calCheckSum1(IPHeader_t* temp);
//����У���
unsigned short calCheckSum2(unsigned short* pBuffer, int nSize);

bool check_checksum(IPFrame_t* temp);

pcap_t* open(char* name);

extern char netIP[10][20];//�򿪵�������Ӧ��ip��ַ
extern char netMask[10][20];//�򿪵�������Ӧ������
extern BYTE myMAC[6];//����MAC��ַ
extern Datagram sendbuffer[MAX_BUFFER];//�������ݱ���������
extern Log mylog;//��־
extern ArpTable arpMappingTable[50];//ARPӳ���
extern int packetcount;
extern char errorbuf[PCAP_ERRBUF_SIZE];
extern RoutingTable routingtable;


#endif 


