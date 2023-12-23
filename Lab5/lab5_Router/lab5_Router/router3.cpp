#include "router3.h"
#define MAX_IP_NUM 6//设定一块网卡上最多绑定的IP地址数
char errorbuf[PCAP_ERRBUF_SIZE];

//全局变量
pcap_if_t* alldevs;//所有网卡
pcap_t* open_dev;//open的网卡
pcap_addr* address;//网卡对应的地址
char netIP[10][20];//打开的网卡对应的ip地址
char netMask[10][20];//打开的网卡对应的掩码
BYTE myMAC[6];//本机MAC地址
Datagram sendbuffer[MAX_BUFFER];//发送数据报缓存数组
Log mylog;//日志
ArpTable arpMappingTable[50];//ARP映射表
int packetcount = 0; //数据报缓存个数

//多线程
HANDLE hThread;
DWORD dwThreadId;


//比较两个MAC地址是否相同
bool Compare(BYTE a[6], BYTE b[6])
{
	for (int i = 0; i < 6; i++)
	{
		if (a[i] != b[i])
			return false;
	}
	return true;
}

//展示ARP数据帧
void showARP(ARPFrame_t* p) {
	in_addr addr1;
	addr1.s_addr = p->SendIP;
	char* str1 = inet_ntoa(addr1);
	printf("源IP地址：%s\n", str1);

	printf("源MAC地址：");
	for (int i = 0; i < 5; i++)
		printf("%02X-", p->SendHa[i]);
	printf("%02X\n", p->SendHa[5]);

	in_addr addr2;
	addr2.s_addr = p->RecvIP;
	char* str2 = inet_ntoa(addr2);
	printf("目的IP地址：%s\n", str2);

	printf("目的MAC地址：");
	for (int i = 0; i < 5; i++)
		printf("%02X-", p->RecvHa[i]);
	printf("%02X\n", p->RecvHa[5]);

}

//获取指向IP地址的指针
void* get_in_addr(struct sockaddr* sa)
{
	if (sa->sa_family == AF_INET) {
		// 如果地址族是 IPv4
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}
	else {
		// 如果地址族是 IPv6
		return &(((struct sockaddr_in6*)sa)->sin6_addr);
	}
}

//缓冲区删除函数
void deleteBuffer(Datagram buf[50], int target) {
	int j = 0;
	for (int i = 0; i < packetcount; i++) {
		if (i != target) {
			buf[j] = buf[i];
			j++;
		}
	}
}

//打开网卡获取双IP
void  findtheTWO() {

	pcap_if_t* dev;//用于遍历网卡信息链表
	pcap_addr_t* add;//用于遍历IP地址信息链表：一个网卡可能有多个IP地址
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 	//获取本机的接口设备
		NULL,			       //无需认证
		&alldevs, 		       //指向设备列表首部
		errorbuf
	) == -1)//返回-1表示出错
	{
		printf("There's Error in pcap_findalldevs_ex! Program exit.\n");
		exit(1);
	}
	//显示设备列表信息
	int index = 0;
	for (dev = alldevs; dev; dev = dev->next) {
		printf("%d. %s", ++index, dev->name);
		if (dev->description)
			printf("( %s )\n", dev->description);
		else
			printf("(No description )\n");

		//获取该网络接口设备绑定的的IP地址信息
		for (add = dev->addresses; add != NULL; add = add->next) {
			if (add->addr->sa_family == AF_INET) { //判断该地址是否IP地址
				//输出相关的信息
				char str[INET_ADDRSTRLEN];
				//通过 inet_ntoa将一个网络字节序的IP地址转化为点分十进制的IP地址（字符串）
				strcpy(str, inet_ntoa(((struct sockaddr_in*)add->addr)->sin_addr));
				printf("IP地址：%s\n", str);
				strcpy(str, inet_ntoa(((struct sockaddr_in*)add->netmask)->sin_addr));
				printf("子网掩码：%s\n", str);

			}
		}
	}
	if (index == 0)
	{
		printf("\nNo interfaces found!\n");
	}
	printf("====================================================================\n\n");
	dev = alldevs;
	int num;
	printf("选择您要打开的网卡：");
	scanf("%d", &num);

	//遍历寻找要打开的网络
	for (int i = 0; i < num - 1; i++) {
		dev = dev->next;
	}
	//把对应的ip和掩码存上
	int t = 0;
	for (add = dev->addresses; add != NULL && t < 10; add = add->next) {
		if (add->addr->sa_family == AF_INET) {//是IP类型的
			strcpy(netIP[t], inet_ntoa(((struct sockaddr_in*)add->addr)->sin_addr));
			strcpy(netMask[t], inet_ntoa(((struct sockaddr_in*)add->netmask)->sin_addr));
			t++;
		}
	}
	open_dev = open(dev->name);//pcap_open
	if (open_dev == NULL) {
		pcap_freealldevs(alldevs);

	}

	pcap_freealldevs(alldevs);

}


//获取本机MAC地址
void SET_ARP_Frame_HOST(ARPFrame_t& ARPFrame1, DWORD ip) {
	for (int i = 0; i < 6; i++) {
		ARPFrame1.FrameHeader.DesMAC[i] = 0xff;//广播地址
		ARPFrame1.FrameHeader.SrcMAC[i] = 0x0f;//随意
		ARPFrame1.SendHa[i] = 0x0f;//随意
		ARPFrame1.RecvHa[i] = 0x00;//全0代表未知
	}

	ARPFrame1.FrameHeader.FrameType = htons(0x0806);//帧类型为ARP
	ARPFrame1.HardwareType = htons(0x0001);//硬件类型为以太网
	ARPFrame1.ProtocolType = htons(0x0800);//协议类型为IP
	ARPFrame1.HLen = 6;
	ARPFrame1.PLen = 4;
	ARPFrame1.Operation = htons(0x0001);//操作类型为ARP请求
	ARPFrame1.SendIP = inet_addr("10.10.10.10");
	ARPFrame1.RecvIP = ip;//本机ip地址
}

void getselfmac(DWORD ip) {
	memset(myMAC, 0, sizeof(myMAC));
	ARPFrame_t ARPF_Send;
	SET_ARP_Frame_HOST(ARPF_Send, ip);
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	struct pcap_pkthdr* header = new pcap_pkthdr;
	int k;
	mylog.addInfo("【获取本机MAC地址】\n");
	mylog.ARPInfo("发送ARP请求包……", &ARPF_Send);
	//发送构造好的数据包
	//用pcap_next_ex()捕获数据包，pkt_data指向捕获到的网络数据包

	while ((k = pcap_next_ex(open_dev, &pkt_header, &pkt_data)) >= 0) {
		//发送数据包

		pcap_sendpacket(open_dev, (u_char*)&ARPF_Send, sizeof(ARPFrame_t));
		struct ARPFrame_t* arp_message;
		arp_message = (struct ARPFrame_t*)(pkt_data);
		if (k == 0)continue;
		else
		{   //帧类型为ARP，且操作类型为ARP响应

			if (arp_message->FrameHeader.FrameType == htons(0x0806) && arp_message->Operation == htons(0x0002)) {


				//展示一下包的内容
				mylog.ARPInfo("收到ARP应答包……", arp_message);
				showARP(arp_message);
				//用my_mac记录本机的MAC地址，
				for (int i = 0; i < 6; i++) {
					myMAC[i] = *(unsigned char*)(pkt_data + 22 + i);
				}
				printf("【成功获取本机MAC地址】\n");
				break;
			}
		}
	}
	mylog.addInfo("【成功获取本机MAC地址】\n");
}


//获取其他机器的MAC地址
void SET_ARP_Frame_DEST(ARPFrame_t& ARPFrame, char ip[20], unsigned char* mac) {
	for (int i = 0; i < 6; i++) {
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;//将APRFrame.FrameHeader.DesMAC设置为广播地址
		ARPFrame.RecvHa[i] = 0x00;
		ARPFrame.FrameHeader.SrcMAC[i] = mac[i];//设置为本机网卡的MAC地址
		ARPFrame.SendHa[i] = mac[i];//设置为本机网卡的MAC地址
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);//帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
	ARPFrame.HLen = 6;//硬件地址长度为6
	ARPFrame.PLen = 4;//协议地址长为4
	ARPFrame.Operation = htons(0x0001);//操作为ARP请求
	ARPFrame.SendIP = inet_addr(ip);//将ARPFrame->SendIP设置为本机网卡上绑定的IP地址

}

//获取ip对应的mac
void Get_Other_Mac(DWORD ip_) {
	/*这里只发送ARP请求！！！*/

	ARPFrame_t ARPFrame;
	SET_ARP_Frame_DEST(ARPFrame, netIP[0], myMAC);
	ARPFrame.RecvIP = ip_;

	mylog.addInfo("【获取远程主机MAC地址】\n");
	pcap_sendpacket(open_dev, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
	mylog.ARPInfo("发送ARP请求包……", &ARPFrame);

}


//发送ICMP数据报
void Send_ICMP_Pac(BYTE type, BYTE code, const u_char* pkt_data) {
	u_char* Buffer = new u_char[70];

	// 填充以太网帧首部
	memcpy(((FrameHeader_t*)Buffer)->DesMAC, ((FrameHeader_t*)pkt_data)->SrcMAC, 6);
	memcpy(((FrameHeader_t*)Buffer)->SrcMAC, ((FrameHeader_t*)pkt_data)->DesMAC, 6);
	((FrameHeader_t*)Buffer)->FrameType = htons(0x0800);

	// 填充IP首部
	((IPHeader_t*)(Buffer + 14))->Ver_HLen = ((IPHeader_t*)(pkt_data + 14))->Ver_HLen;
	((IPHeader_t*)(Buffer + 14))->TOS = ((IPHeader_t*)(pkt_data + 14))->TOS;
	((IPHeader_t*)(Buffer + 14))->TotalLen = htons(56);
	((IPHeader_t*)(Buffer + 14))->ID = ((IPHeader_t*)(pkt_data + 14))->ID;
	((IPHeader_t*)(Buffer + 14))->Flag_Segment = ((IPHeader_t*)(pkt_data + 14))->Flag_Segment;
	((IPHeader_t*)(Buffer + 14))->TTL = 64;
	((IPHeader_t*)(Buffer + 14))->Protocol = 1;
	((IPHeader_t*)(Buffer + 14))->SrcIP = ((IPHeader_t*)(pkt_data + 14))->DstIP;
	((IPHeader_t*)(Buffer + 14))->DstIP = ((IPHeader_t*)(pkt_data + 14))->SrcIP;
	((IPHeader_t*)(Buffer + 14))->Checksum = htons(calCheckSum1((IPHeader_t*)(Buffer + 14)));
	// calCheckSum1((IPHeader_t*)(Buffer + 14));
	// 填充ICMP首部:前8字节
	((ICMPHeader_t*)(Buffer + 34))->Type = type;
	((ICMPHeader_t*)(Buffer + 34))->Code = code;
	((ICMPHeader_t*)(Buffer + 34))->Id = 0;
	((ICMPHeader_t*)(Buffer + 34))->Sequence = 0;
	((ICMPHeader_t*)(Buffer + 34))->Checksum = htons(calCheckSum2((unsigned short*)(Buffer + 34), 36));
	// ((IPHeader_t*)(Buffer + 34))->Checksum = 0;

	// 将原本计算完校验和的数据包首部填充进去
	memcpy((u_char*)(Buffer + 42), (IPHeader_t*)(pkt_data + 14), 20);
	//取出ICMP首部的前8个字节，到此一共是70
	memcpy((u_char*)(Buffer + 62), (u_char*)(pkt_data + 34), 8);
	//发送报文
	pcap_sendpacket(open_dev, (u_char*)Buffer, 70);

	if (type == 11)
	{
		mylog.ICMPInfo("发送ICMP超时数据包……\n");
	}
	if (type == 3)
	{
		mylog.ICMPInfo("发送ICMP目的不可达数据包……\n");
	}

	delete[] Buffer;
}

//线程函数

//处理接收到的数据报
DWORD WINAPI Recv_Handle(LPVOID lparam) {

	RoutingTable router_table = *(RoutingTable*)(LPVOID)lparam;//从参数中获取路由表
	//过滤码
	struct bpf_program fcode;
	//编辑过滤字符串
	//pcap_compile()用来把用户输入的过滤字符串编译进过滤信息
	if (pcap_compile(open_dev, &fcode, "ip or arp", 1, bpf_u_int32(netMask[0])) < 0)
	{
		fprintf(stderr, "\nError  filter\n");
		system("pause");
		return -1;
	}

	//根据编译好的过滤码设置过滤条件
	if (pcap_setfilter(open_dev, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter\n");
		system("pause");
		return -1;
	}

	//捕获数据包并转发
	while (1)
	{
		pcap_pkthdr* pkt_header = NULL;
		const u_char* pkt_data = NULL;
		while (1)
		{
			int ret = pcap_next_ex(open_dev, &pkt_header, &pkt_data);//抓包
			if (ret)break;//接收到消息
		}
		//格式化收到的包为帧首部，以获取目的MAC地址和帧类型
		FrameHeader_t* recv_header = (FrameHeader_t*)pkt_data;
		//只处理目的目的mac是自己的包
		if (Compare(recv_header->DesMAC, myMAC))
		{
			//收到IP数据报
			if (ntohs(recv_header->FrameType) == 0x800)
			{
				//格式化收到的包为帧首部+IP首部类型
				IPFrame_t* data = (IPFrame_t*)pkt_data;

				mylog.IPInfo("接收IP数据报……\n", data);
				//获取目的IP地址并在路由表中查找，并获取下一跳ip地址



				// ICMP超时
				if (data->IPHeader.TTL <= 0)
				{
					//发送超时报文
					Send_ICMP_Pac(11, 0, pkt_data);
					mylog.addInfo("发送ICMP超时数据包……");
					continue;
				}

				IPHeader_t* IpHeader = &(data->IPHeader);
				// 检验校验和，数据报损坏或是出错
				if (check_checksum(data) == 0)
				{
					mylog.IPInfo("校验和错误，丢弃", data);
					continue;
				}
				DWORD dstip = data->IPHeader.DstIP;

				DWORD nexthop = router_table.search(dstip);

				mylog.addInfohop("接收到的IP数据报目的IP地址为：", dstip);
				mylog.addInfohop("接收到的IP数据报下一跳为：", nexthop);
				//无匹配项
				//目的不可达
				if (nexthop == -1)
				{
					Send_ICMP_Pac(3, 0, pkt_data);// ICMP目的不可达
					mylog.addInfo("发送ICMP目的不可达数据报!");
					continue;
				}
				else
				{

					Datagram packet;
					packet.dst_IP = nexthop;

					//重新封装MAC地址(源MAC地址变为my_mac)
					for (int t = 0; t < 6; t++)
					{
						data->FrameHeader.SrcMAC[t] = myMAC[t];
					}

					data->IPHeader.TTL -= 1;// TTL减1
					// 设IP头中的校验和为0
					data->IPHeader.Checksum = 0;
					unsigned short buff[sizeof(IPHeader_t)];

					memset(buff, 0, sizeof(IPHeader_t));
					IPHeader_t* header = &(data->IPHeader);
					memcpy(buff, header, sizeof(IPHeader_t));

					// 计算IP头部校验和
					// data->IPHeader.Checksum = cal_checksum(check_buff, sizeof(IPHeader_t));
					data->IPHeader.Checksum = calCheckSum1(header);

					// IP-MAC地址映射表中存在该映射关系
					//根据nexthop取ARP映射表中查看是否存在映射

					if (arpMappingTable->search(nexthop, data->FrameHeader.DesMAC))
					{
						//查找到了数据报可以直接转发
						memcpy(packet.Data, pkt_data, pkt_header->len);
						packet.Len = pkt_header->len;
						if (pcap_sendpacket(open_dev, (u_char*)packet.Data, packet.Len) != 0)
						{
							// 错误处理
							continue;
						}
						mylog.addInfo("【转发数据包】");
						mylog.IPInfo("转发", data);
					}


					// IP-MAC地址映射表中不存在该映射关系,获取
					//先缓存IP数据报
					//设置缓冲区my_buffer
					else
					{
						//最多存50条
						if (packetcount < MAX_BUFFER)		// 存入缓存队列
						{
							packet.Len = pkt_header->len;
							// 将需要转发的数据报存入缓冲区
							memcpy(packet.Data, pkt_data, pkt_header->len);

							sendbuffer[packetcount++] = packet;

							packet.time = clock();

							mylog.IPInfo("缓存IP数据报……\n", data);
							// 发送ARP请求
							Get_Other_Mac(packet.dst_IP);
						}
						else
						{
							mylog.addInfo("缓冲区已满，丢弃该IP数据包！");
							mylog.IPInfo("缓冲区溢出，丢弃！", data);
						}
					}
				}
			}
			//收到ARP数据报
			else if (ntohs(recv_header->FrameType) == 0x806)
			{
				ARPFrame_t* data = (ARPFrame_t*)pkt_data;//格式化收到的包为帧首部+ARP首部类型
				mylog.ARPInfo("接收ARP响应包……", data);
				//收到ARP响应包
				//处理响应报文
				if (data->Operation == ntohs(0x0002)) {
					BYTE tmp_mac[6] = { 1 };

					if (arpMappingTable->search(data->SendIP, tmp_mac)) {//该映射关系已经存到路由表中，不做处理
					}
					else {

						DWORD tmp_ip = data->SendIP;
						for (int i = 0; i < 6; i++) {
							tmp_mac[i] = data->SendHa[i];
						}

						//IP-MAC对应关系存表
						arpMappingTable->add(data->SendIP, data->SendHa);

						//遍历缓冲区，看是否有可以转发的包
						for (int i = 0; i < packetcount; i++)
						{
							Datagram packet = sendbuffer[i];
							if (packet.isValid == 0)continue;
							if (clock() - packet.time >= 6000) {//超时
								// packet.valid = 0;
								// my_buffer[i].valid = 0;
								deleteBuffer(sendbuffer, i);
								packetcount -= 1;
								continue;
							}
							////往此IP地址转发
							if (packet.dst_IP == data->SendIP)
							{
								IPFrame_t* ipframe = (IPFrame_t*)packet.Data;
								//重新封装IP包
								for (int i = 0; i < 6; i++) {
									ipframe->FrameHeader.SrcMAC[i] = myMAC[i];
									ipframe->FrameHeader.DesMAC[i] = data->SendHa[i];
								}
								// 发送IP数据包
								pcap_sendpacket(open_dev, (u_char*)packet.Data, packet.Len);

								sendbuffer[i].isValid = 0;
								mylog.addInfo("【转发数据包】");
								mylog.IPInfo("转发", ipframe);
								mylog.addInfo("该数据包转发成功！");
							}
						}

					}
				}
				else if (data->Operation == ntohs(0x0002)) {}//请求报文什么也不做

			}

		}


	}

}

pcap_t* open(char* deviceName) {

	pcap_t* deviceHandle = pcap_open(deviceName, 65536 /* 最大值 */, PCAP_OPENFLAG_PROMISCUOUS, 1000, nullptr, errorbuf);

	if (deviceHandle == nullptr) {
		printf("无法打开设备: %s\n", errorbuf); // 输出错误信息
	}
	return deviceHandle;
}

void RoutingEntry::print() {
	// 打印序号
	printf("%d   ", index);

	in_addr maskAddr;
	in_addr dstNetAddr;
	in_addr nextHopAddr;

	// 打印掩码
	maskAddr.s_addr = mask;
	printf("%s\t", inet_ntoa(maskAddr));

	// 打印目的主机
	dstNetAddr.s_addr = dst_net;
	printf("%s\t", inet_ntoa(dstNetAddr));

	// 打印下一跳IP地址
	nextHopAddr.s_addr = next_hop;
	printf("%s\t", inet_ntoa(nextHopAddr));

	// 用户是否可操作
	if (flag == 0)
		printf("0\n");
	else
		printf("1\n");
	printf("\n");
}

/*路由表*/

//初始化，添加直接连接的网络
RoutingTable::RoutingTable()
{
	head = new RoutingEntry;
	head->next = NULL;
	num = 0;
	//通过得到的双IP的掩码，在路由表中添加直接相连的网络，将类型设置为0，即不可删除项
	for (int i = 0; i < 2; i++)
	{
		RoutingEntry* entry = new RoutingEntry;
		//添加直接相连的网络
		entry->dst_net = (inet_addr(netIP[i])) & (inet_addr(netMask[i]));
		entry->mask = inet_addr(netMask[i]);
		entry->flag = 0;
		this->add(entry);
	}

}

void RoutingTable::add(RoutingEntry* newRouteEntry) {
	// 如果路由表为空，直接将新的路由表项添加到头节点后面
	RoutingEntry* currentEntry;
	if (num == 0) {
		head->next = newRouteEntry;
		newRouteEntry->next = NULL;
	}
	else {
		currentEntry = head->next;
		while (currentEntry != NULL)
		{
			if (currentEntry->next == NULL || (newRouteEntry->mask < currentEntry->mask && newRouteEntry->mask >= currentEntry->next->mask))
			{
				break;
			}
			currentEntry = currentEntry->next;
		}
		if (currentEntry->next == NULL)
		{
			newRouteEntry->next = NULL;
			currentEntry->next = newRouteEntry;
		}
		else
		{
			newRouteEntry->next = currentEntry->next;
			currentEntry->next = newRouteEntry;
		}
	}
	// 重新编号
	RoutingEntry* p = head->next;
	for (int i = 0; p != nullptr; i++) {
		p->index = i;
		p = p->next;
	}

	num++;
	mylog.addInfo("已成功添加该路由表项！");
	return;
}

void RoutingTable::remove(int number) {
	RoutingEntry* temp = new RoutingEntry;
	bool found = false;
	for (RoutingEntry* t = head; t->next != NULL; t = t->next)
	{
		if (t->next->index == number)
			found = true;
	}
	if (!found) {
		printf("查无此项，请重新输入！\n");
		return;
	}

	if (number == 0)//删除第一项
	{
		temp = head->next;
		//默认路由表项不能删
		if (temp->flag == 0)
		{
			printf("没有权限删除该项！\n");
			return;
		}
		else
		{
			if (num == 1)
			{
				head->next = NULL;
			}
			else
			{
				temp = head->next;
				head->next = temp->next;
				printf("已成功删除该路由表项！\n");

			}

		}
	}
	else
	{
		temp = head->next;
		for (int i = 0; i < number - 1; i++)//遍历到index处,寻找删除结点的前驱结点
		{
			temp = temp->next;
		}
		RoutingEntry* rem = new RoutingEntry;
		rem = temp->next;//要删除的结点x

		if (rem->flag == 0)
		{
			printf("没有权限删除该项！\n");
			return;
		}
		if (rem->next == NULL)//尾删
		{
			temp->next = NULL;

			//	printf("已成功删除指定项！\n");

		}
		//中间删
		temp->next = rem->next;
		printf("已成功删除该路由表项！\n");

	}


	// 重新编号
	RoutingEntry* p = head->next;
	for (int i = 0; p != nullptr; i++) {
		p->index = i;
		p = p->next;
	}

	num--;
	mylog.addInfo("路由表删除成功!");
	return;
}

// 打印路由表
void RoutingTable::print() {
	RoutingEntry* temp = head->next;
	printf("【路由表】\n");
	int t = 0;
	while (temp != NULL) {
		temp->print();
		temp = temp->next;
		t++;
	}
}

// 查找下一跳的IP地址（参数为目标IP地址）
DWORD RoutingTable::search(DWORD dst_ip) {
	DWORD next_hop = -1;

	RoutingEntry* t = head->next;
	for (; t != NULL; t = t->next) {
		if ((t->mask & dst_ip) == t->dst_net) {
			if (t->flag == 0)  // 直接相连的网络
			{
				next_hop = dst_ip;
			}
			else {
				next_hop = t->next_hop;
			}
		}
	}

	return next_hop;
}

/*日志打印函数*/
FILE* Log::logFile = nullptr;

Log::Log() {
	logFile = fopen("logfile.txt", "a+");  // 以附加的方式打开文件
	if (!logFile) {
		// 处理文件打开失败的情况，可以输出错误信息到标准错误流（stderr）
		fprintf(stderr, "Error opening log file!\n");
	}
}

Log::~Log() {
	if (logFile) {
		fclose(logFile);
	}
}

// 日志信息标识
void Log::addInfo(const char* str) {
	fprintf(logFile, "%s\n", str);
}
// 日志信息标识和下一跳信息
void Log::addInfohop(const char* str, DWORD hop) {
	fprintf(logFile, "%s", str);

	if (hop == -1)
		fprintf(logFile, "%s\n", "-1");
	else {
		fprintf(logFile, "\n");

		in_addr addr;
		addr.s_addr = hop;
		char* str1 = inet_ntoa(addr);
		fprintf(logFile, "%s\n", str1);
	}
}

// ARP数据包信息
void Log::ARPInfo(const char* str, ARPFrame_t* p) {
	fprintf(logFile, "%s【ARP 数据包】\n", str);

	// 源IP地址
	in_addr addr;
	addr.s_addr = p->SendIP;
	fprintf(logFile, "源IP： %s\n", inet_ntoa(addr));

	// 源MAC地址
	fprintf(logFile, "源MAC： %02X-%02X-%02X-%02X-%02X-%02X\n",
		p->SendHa[0], p->SendHa[1], p->SendHa[2], p->SendHa[3], p->SendHa[4], p->SendHa[5]);

	// 目的IP地址
	in_addr addr2;
	addr2.s_addr = p->RecvIP;
	fprintf(logFile, "目的IP： %s\n", inet_ntoa(addr2));

	// 目的MAC地址
	fprintf(logFile, "目的MAC： %02X-%02X-%02X-%02X-%02X-%02X\n",
		p->RecvHa[0], p->RecvHa[1], p->RecvHa[2], p->RecvHa[3], p->RecvHa[4], p->RecvHa[5]);

	fprintf(logFile, "\n");
}

// IP数据包信息
void Log::IPInfo(const char* str, IPFrame_t* p) {
	fprintf(logFile, "%s【IP 数据包】\n", str);

	// 源IP地址
	fprintf(logFile, "源IP： %s\n", inet_ntoa(*(in_addr*)&(p->IPHeader.SrcIP)));

	// 源MAC地址
	fprintf(logFile, "源MAC： %02X-%02X-%02X-%02X-%02X-%02X\n",
		p->FrameHeader.SrcMAC[0], p->FrameHeader.SrcMAC[1], p->FrameHeader.SrcMAC[2],
		p->FrameHeader.SrcMAC[3], p->FrameHeader.SrcMAC[4], p->FrameHeader.SrcMAC[5]);

	// 目的IP地址
	fprintf(logFile, "目的IP： %s\n", inet_ntoa(*(in_addr*)&(p->IPHeader.DstIP)));



	// 目的MAC地址
	fprintf(logFile, "目的MAC： %02X-%02X-%02X-%02X-%02X-%02X\n",
		p->FrameHeader.DesMAC[0], p->FrameHeader.DesMAC[1], p->FrameHeader.DesMAC[2],
		p->FrameHeader.DesMAC[3], p->FrameHeader.DesMAC[4], p->FrameHeader.DesMAC[5]);

	fprintf(logFile, "\n");
}

// ICMP信息
void Log::ICMPInfo(const char* str) {
	fprintf(logFile, "%s\n", str);
}

// 打印MAC地址
void printMac(BYTE MAC[]) {
	printf("MAC地址为： ");
	for (int i = 0; i < 5; i++)
		printf("%02X-", MAC[i]);
	printf("%02X\n", MAC[5]);
}

// ARP表
int ArpTable::num = 0;
// 添加ARP表项的实现
void ArpTable::add(DWORD ip, BYTE mac[6])
{
	arpMappingTable[num].IP = ip;
	memcpy(arpMappingTable[num].MAC, mac, 6);
	num++;
}

int ArpTable::search(DWORD ip, BYTE mac[6])
{
	memset(mac, 0, 6);
	for (int i = 0; i < num; i++)
	{
		if (ip == arpMappingTable[i].IP)
		{
			memcpy(mac, arpMappingTable[i].MAC, 6);
			return 1;
		}
	}
	return 0;
}

//参数是IP数据包头
unsigned short calCheckSum1(IPHeader_t* temp)
{
	unsigned int sum = 0;
	WORD* t = (WORD*)temp;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++) {
		sum += t[i];
		while (sum >= 0x10000) {
			//如果溢出，则进行回卷
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	return (unsigned short)~sum;
}

unsigned short calCheckSum2(unsigned short* pBuffer, int nSize) {

	//计算方法：将校验和字段设置为0（传进来的是已经为0的）
	//按顺序对每16位（1个字=2字节）进行加法运算；
	//如果溢出就将进位加到最低位
	//对累加的结果取反——就是头部校验和值
	
	unsigned long ulCheckSum = 0;
	while (nSize > 1)
	{
		ulCheckSum += *pBuffer++;
		nSize -= sizeof(unsigned short);//每16位一组
	}
	if (nSize)
	{
		ulCheckSum += *(unsigned short*)pBuffer;
	}

	ulCheckSum = (ulCheckSum >> 16) + (ulCheckSum & 0xffff);
	ulCheckSum += (ulCheckSum >> 16);
	return (unsigned short)(~ulCheckSum);
}

bool check_checksum(IPFrame_t* temp) {
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;//每16位为一组
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++) {
		sum += t[i];
		while (sum >= 0x10000) {
			//包含原校验和一起进行相加
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}

	if (sum == 65535)return 1;//全1，校验和正确
	return 0;
}


int main() {
	//打开网卡获取双IP
	findtheTWO();
	printf("本机的双IP地址及子网掩码为：\n");
	//输出此时存储的IP地址与子网掩码
	for (int i = 0; i < 2; i++) {
		printf("%s\t", netIP[i]);
		printf("%s\n", netMask[i]);
	}
	//获取本机MAC地址
	getselfmac(inet_addr(netIP[0]));
	printMac(myMAC);
	//路由表
	RoutingTable my_route;
	//建立转发线程
	hThread = CreateThread(NULL, NULL, Recv_Handle, LPVOID(&my_route), 0, &dwThreadId);

	//对路由表的相关操作
	int choice;
	while (1)
	{
		printf("==================== 1. 打印路由表 ====================\n");
		printf("==================== 2. 添加路由表项 ====================\n");
		printf("==================== 3. 删除路由表项 ====================\n");
		printf("\n");
		printf("|| 请输入操作序号 ：");
		scanf("%d", &choice);
		RoutingEntry* entry = new RoutingEntry;

		switch (choice) {
		case 1:
			my_route.print();
			break;
		case 2:
			char t[30];
			printf("Destination Network：");
			scanf("%s", &t);
			entry->dst_net = inet_addr(t);
			printf("MASK：");
			scanf("%s", &t);
			entry->mask = inet_addr(t);
			printf("Next Hop：");
			scanf("%s", &t);
			entry->next_hop = inet_addr(t);
			entry->flag = 1;
			entry->print();
			my_route.add(entry);
			break;
		case 3:
			my_route.print();
			printf("请输入要删除的表项：");
			int i;
			scanf("%d", &i);
			my_route.remove(i);
			break;
		default:
			printf("操作无效，请重新输入\n");
			break;
		}
	}
	return 0;

}