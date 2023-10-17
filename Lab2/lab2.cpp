#include<WinSock2.h>
#include<iostream>
#include<pcap.h>
#include<stdio.h>
#include<time.h>
#include<string>
#include<iomanip>
#pragma comment(lib,"ws2_32.lib")//链接的时候找ws2_32.lib
#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma warning(disable:4996)//使用旧函数
using namespace std;

//定义报文格式
#pragma pack(1)//进入字节对齐方式 
struct ethernet_header {//帧首部
	uint8_t mac_dst[6];//目的MAC地址
	uint8_t mac_src[6];//源MAC地址
	uint16_t frame_type;//帧类型
};

//ip地址格式
typedef uint32_t in_addr_t;
struct ip_header {//ip首部
	uint8_t ip_header_length : 4,//首部长度
		ip_version : 4;//版本

	uint8_t ip_tos;//服务类型
	uint16_t total_len;//总长度
	uint16_t ip_id;//标识
	uint16_t ip_off;//片偏移
	uint8_t ip_ttl;//生存时间
	uint8_t ip_protocol;//协议类型
	uint16_t ip_checksum;//首部检验和
	struct in_addr ip_source_address;//源IP地址
	struct in_addr ip_destination_address;//目的IP地址
};

//IP数据包分析函数
void ip_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content) {
	struct ip_header* ip_protocol;//IP协议变量
	u_int header_length;//长度
	u_int offset;//片偏移
	u_char tos;//服务类型
	uint16_t checksum;//首部检验和
	ip_protocol = (struct ip_header*)(packet_content + 14);//获得IP数据包的内容 去掉以太头//因为前14字节通常是以太网首部，所以需要跳过以太网首部部分，以获取到IPv4首部。
	checksum = ntohs(ip_protocol->ip_checksum);//获得检验和
	header_length = ip_protocol->ip_header_length * 4;//获得长度//IPv4首部长度以32位字为单位，所以需要将其乘以4以获取实际字节数。
	tos = ip_protocol->ip_tos;//获得tos服务类型
	offset = ntohs(ip_protocol->ip_off);//获得偏移量
	cout << "\n=============网络层（IP协议）=============\n";
	printf("IP版本：\t\tIPv%01X\n", ip_protocol->ip_version);//
	cout << "IP协议首部长度\t" << header_length << endl;
	cout << "总长度:\t\t" << ntohs(ip_protocol->total_len) << endl;//获得总长度
	cout << "标识:\t\t" << ntohs(ip_protocol->ip_id) << endl;//获得标识
	cout << "片偏移:\t\t" << (offset & 0x1fff) * 8 << endl;
	printf("生存时间:\t%01X\n", ip_protocol->ip_ttl);//获得ttl
	cout << "首部检验和:\t" << checksum << endl;
	cout << "源IP:\t" << inet_ntoa(ip_protocol->ip_source_address) << endl;//获得源ip地址
	cout << "目的IP:\t" << inet_ntoa(ip_protocol->ip_destination_address) << endl;//获得目的ip地址
	printf("协议号:\t%01X\n", ip_protocol->ip_protocol);//获得协议类型
	cout << "\n传输层协议是:\t";
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

//解析数据链路层
void ethernet_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content) {
	u_short ethernet_type;//以太网协议类型
	struct ethernet_header* ethernet_protocol;//以太网协议变量
	uint8_t* mac_src;//Mac源地址
	uint8_t* mac_dst;//Mac目的地址
	static int packet_number = 1;//抓包数量
	cout << endl;
	printf("第【 %d 】个IP数据包被捕获\n", packet_number);
	cout << "===========链路层（以太网协议）===========" << endl;
	ethernet_protocol = (struct ethernet_header*)packet_content;//获得以太网协议数据内容//指针指向捕获的数据包内容的起始位置，以便访问以太网首部
	cout << "以太网类型：\t";
	ethernet_type = ntohs(ethernet_protocol->frame_type);//获得以太网类型//ntohs 函数将网络字节序转换为主机字节序。
	cout << ethernet_type << endl;
	switch (ethernet_type) {//判断以太网类型
	case 0x0800:
		cout << "网络层是：  IPv4协议\n" << endl;
		break;
	case 0x0806:
		cout << "网络层是：  ARP协议\n" << endl;
		break;
	case 0x0835:
		cout << "网络层是：  RARP协议\n" << endl;
		break;
	default:break;
	}

	//Mac源地址
	mac_src = ethernet_protocol->mac_src;
	printf("Mac源地址:\t%02x:%02x:%02x:%02x:%02x:%02x:\n", *mac_src, *(mac_src + 1), *(mac_src + 2), *(mac_src + 3), *(mac_src + 4), *(mac_src + 5));//X 表示以十六进制形式输出 02 表示不足两位，前面补0输出 
	//Mac目的地址
	mac_dst = ethernet_protocol->mac_dst;
	printf("Mac目的地址:\t%02x:%02x:%02x:%02x:%02x:%02x:\n", *mac_dst, *(mac_dst + 1), *(mac_dst + 2), *(mac_dst + 3), *(mac_dst + 4), *(mac_dst + 5));

	switch (ethernet_type) {
	case 0x0800://如果上层是IPv4协议,就调用分析ip协议的函数对IP数据包进行进一步的解析
		ip_protocol_packet_callback(argument, packet_header, packet_content);
		break;
	default:break;
	}
	packet_number++;
}

int main() {
	cout << "=========== 解析IP数据包开始@_@ ===========\n";
	pcap_if_t* alldevs;//指向网卡列表的指针，从中获得网卡名称和描述
	pcap_if_t* d;//用于遍历网卡列表的指针
	int i = 0;//用于遍历链表
	int num = 0;//打开哪个网卡（输入）
	pcap_t* adhandle;//打开网络适配器，捕捉实例,是pcap_open返回的对象
	char errbuf[PCAP_ERRBUF_SIZE];//存储错误消息的字符数组

	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		cout << stderr << "获取网卡失败:%s\n" << errbuf;
		exit(1);
	}
	//打印网卡信息
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
	//此时网卡总数为i
	cout << "\n请输入要打开的网卡号 (1-" << i << "):\t";
	cin >> num;

	if (num<1 || num>i) {
		cout << "Error!网卡号超出范围！";
		pcap_freealldevs(alldevs);//释放设备列表
		return -1;
	}

	/*遍历链表 alldevs，找到用户指定的网络适配器编号num对应的网络适配器信息。
	每次迭代都将链表的当前节点指针 d 移动到下一个节点，并递增 i，直到 i 达到 num - 1 时，循环停止。
	这样，d 就指向了用户选择的网络适配器信息*/
	for (d = alldevs, i = 0; i < num - 1; d = d->next, i++);

	/*使用 pcap_open_live 函数打开选定的网络适配器，
	创建一个捕获实例 adhandle，用于后续的数据包捕获操作*/
	if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL) {
		cout << stderr << "Error!";
		pcap_freealldevs(alldevs);
		return -1;
	}
	cout << "\n监听" << d->description;
	pcap_freealldevs(alldevs);//释放先前分配的 alldevs 链表内存

	int cnt = 0;
	cout << "\n将要捕获数据包的个数：\t\t";
	cin >> cnt;

	/*pcap_loop 函数捕获指定数量cnt的数据包，
	每个数据包都会传递给 ethernet_protocol_packet_callback 函数进行解析和显示。*/
	pcap_loop(adhandle, cnt, ethernet_protocol_packet_callback, NULL);
	cout << "\n\t解析IP数据包结束！\n";
	return 0;
}