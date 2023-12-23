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

#pragma pack(1)		//进入字节对齐方式

//帧首部
typedef struct FrameHeader_t {
	BYTE DesMAC[6];//目的地址
	BYTE SrcMAC[6];//源地址
	WORD FrameType;//帧类型
}FrameHeader_t;

//ARP数据帧
typedef struct ARPFrame_t {
	FrameHeader_t FrameHeader;//帧首部
	WORD HardwareType;//硬件类型
	WORD ProtocolType;//协议长度
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	DWORD SendIP;
	BYTE RecvHa[6];
	DWORD RecvIP;
}ARPFrame_t;

//IP首部
typedef struct IPHeader_t {
	BYTE Ver_HLen;
	BYTE TOS;
	WORD TotalLen;
	WORD ID;
	WORD Flag_Segment;
	BYTE TTL;//生命周期
	BYTE Protocol;
	WORD Checksum;//校验和
	ULONG SrcIP;//源IP
	ULONG DstIP;//目的IP
}IPHeader_t;

//IP数据报：包含帧首部和IP首部的数据包
typedef struct IPFrame_t {//包含帧首部和IP首部的数据包
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
}IPFrame_t;

// ICMP首部
typedef struct ICMPHeader_t {
	BYTE    Type;
	BYTE    Code;
	WORD    Checksum;
	WORD    Id;
	WORD    Sequence;
}ICMPHeader_t;

#pragma pack()	//恢复缺省对齐方式

/*路由器相关数据结构*/

//路由表项
class RoutingEntry
{
public:
	RoutingEntry* next;
	int index;//索引
	DWORD mask;//掩码
	DWORD dst_net;//目的网络
	DWORD next_hop;//下一跳的IP地址
	BYTE nextMAC[6];//下一跳的MAC地址
	int flag;//0为直接连接（不可删除），1为用户添加
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

//路由表
//按照链表形式组织，按照最长匹配原则，掩码越长越靠前，索引越小
class RoutingTable {
public:
	RoutingEntry* head, * last;//头节点
	int num;//条数
	RoutingTable();//初始化，添加直接相连的网络
	void add(RoutingEntry* entry);//添加路由表项，直接相连的在最前面，其余的按照最长匹配原则
	void remove(int number);//删除第i条路由表项，直接相连的不能删除
	void print();
	DWORD search(DWORD dstip);//根据最长匹配原则查找下一跳的ip地址

};

/*ARP地址映射表*/
class ArpTable {
public:
	DWORD IP;
	BYTE MAC[6];
	static int num;
	static void add(DWORD IP, BYTE MAC[6]);
	static int search(DWORD IP, BYTE MAC[6]);
};

/*转发的数据报结构*/
class Datagram
{
public:
	BYTE			Data[MAX_SIZE];// 数据缓存
	int				Len;// 数据包总长度
	ULONG			dst_IP;//目的IP地址
	bool			isValid = 1; //有效位：如果已经被转发或者超时，则置0
	clock_t			time;// 超时判断
	Datagram() {};
	Datagram(const Datagram& x)//复制构造函数--->检查！！！
	{
		memcpy(this->Data, x.Data, x.Len);
		this->Len = x.Len;
		this->dst_IP = x.dst_IP;
		this->isValid = x.isValid;
		this->time = x.time;
	}
};


/*日志操作*/
//写相关日志，包括接收ARP数据报，发送ARP数据报，接收IP数据报，转发IP数据报，发送ICMP数据报

class Log
{
public:
	Log();//打开文件进行写入
	~Log();//关闭文件！
	static FILE* logFile;
	//写入日志
	static void addInfo(const char* info/*日志信息标识*/);
	static void addInfohop(const char* info/*日志信息标识*/, DWORD hop);//包含跳数的信息
	static void ARPInfo(const char* info/*日志信息标识*/, ARPFrame_t* p);//arp类型
	static void IPInfo(const char* info, IPFrame_t* p);//ip类型
	static void ICMPInfo(const char* info);//icmp类型
};

//////////

void printMac(BYTE MAC[]);
unsigned short calCheckSum1(IPHeader_t* temp);
//检验校验和
unsigned short calCheckSum2(unsigned short* pBuffer, int nSize);

bool check_checksum(IPFrame_t* temp);

pcap_t* open(char* name);

extern char netIP[10][20];//打开的网卡对应的ip地址
extern char netMask[10][20];//打开的网卡对应的掩码
extern BYTE myMAC[6];//本机MAC地址
extern Datagram sendbuffer[MAX_BUFFER];//发送数据报缓存数组
extern Log mylog;//日志
extern ArpTable arpMappingTable[50];//ARP映射表
extern int packetcount;
extern char errorbuf[PCAP_ERRBUF_SIZE];
extern RoutingTable routingtable;


#endif 


