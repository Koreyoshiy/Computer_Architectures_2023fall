#include "router3.h"
#define MAX_IP_NUM 6//�趨һ�����������󶨵�IP��ַ��
char errorbuf[PCAP_ERRBUF_SIZE];

//ȫ�ֱ���
pcap_if_t* alldevs;//��������
pcap_t* open_dev;//open������
pcap_addr* address;//������Ӧ�ĵ�ַ
char netIP[10][20];//�򿪵�������Ӧ��ip��ַ
char netMask[10][20];//�򿪵�������Ӧ������
BYTE myMAC[6];//����MAC��ַ
Datagram sendbuffer[MAX_BUFFER];//�������ݱ���������
Log mylog;//��־
ArpTable arpMappingTable[50];//ARPӳ���
int packetcount = 0; //���ݱ��������

//���߳�
HANDLE hThread;
DWORD dwThreadId;


//�Ƚ�����MAC��ַ�Ƿ���ͬ
bool Compare(BYTE a[6], BYTE b[6])
{
	for (int i = 0; i < 6; i++)
	{
		if (a[i] != b[i])
			return false;
	}
	return true;
}

//չʾARP����֡
void showARP(ARPFrame_t* p) {
	in_addr addr1;
	addr1.s_addr = p->SendIP;
	char* str1 = inet_ntoa(addr1);
	printf("ԴIP��ַ��%s\n", str1);

	printf("ԴMAC��ַ��");
	for (int i = 0; i < 5; i++)
		printf("%02X-", p->SendHa[i]);
	printf("%02X\n", p->SendHa[5]);

	in_addr addr2;
	addr2.s_addr = p->RecvIP;
	char* str2 = inet_ntoa(addr2);
	printf("Ŀ��IP��ַ��%s\n", str2);

	printf("Ŀ��MAC��ַ��");
	for (int i = 0; i < 5; i++)
		printf("%02X-", p->RecvHa[i]);
	printf("%02X\n", p->RecvHa[5]);

}

//��ȡָ��IP��ַ��ָ��
void* get_in_addr(struct sockaddr* sa)
{
	if (sa->sa_family == AF_INET) {
		// �����ַ���� IPv4
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}
	else {
		// �����ַ���� IPv6
		return &(((struct sockaddr_in6*)sa)->sin6_addr);
	}
}

//������ɾ������
void deleteBuffer(Datagram buf[50], int target) {
	int j = 0;
	for (int i = 0; i < packetcount; i++) {
		if (i != target) {
			buf[j] = buf[i];
			j++;
		}
	}
}

//��������ȡ˫IP
void  findtheTWO() {

	pcap_if_t* dev;//���ڱ���������Ϣ����
	pcap_addr_t* add;//���ڱ���IP��ַ��Ϣ����һ�����������ж��IP��ַ
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 	//��ȡ�����Ľӿ��豸
		NULL,			       //������֤
		&alldevs, 		       //ָ���豸�б��ײ�
		errorbuf
	) == -1)//����-1��ʾ����
	{
		printf("There's Error in pcap_findalldevs_ex! Program exit.\n");
		exit(1);
	}
	//��ʾ�豸�б���Ϣ
	int index = 0;
	for (dev = alldevs; dev; dev = dev->next) {
		printf("%d. %s", ++index, dev->name);
		if (dev->description)
			printf("( %s )\n", dev->description);
		else
			printf("(No description )\n");

		//��ȡ������ӿ��豸�󶨵ĵ�IP��ַ��Ϣ
		for (add = dev->addresses; add != NULL; add = add->next) {
			if (add->addr->sa_family == AF_INET) { //�жϸõ�ַ�Ƿ�IP��ַ
				//�����ص���Ϣ
				char str[INET_ADDRSTRLEN];
				//ͨ�� inet_ntoa��һ�������ֽ����IP��ַת��Ϊ���ʮ���Ƶ�IP��ַ���ַ�����
				strcpy(str, inet_ntoa(((struct sockaddr_in*)add->addr)->sin_addr));
				printf("IP��ַ��%s\n", str);
				strcpy(str, inet_ntoa(((struct sockaddr_in*)add->netmask)->sin_addr));
				printf("�������룺%s\n", str);

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
	printf("ѡ����Ҫ�򿪵�������");
	scanf("%d", &num);

	//����Ѱ��Ҫ�򿪵�����
	for (int i = 0; i < num - 1; i++) {
		dev = dev->next;
	}
	//�Ѷ�Ӧ��ip���������
	int t = 0;
	for (add = dev->addresses; add != NULL && t < 10; add = add->next) {
		if (add->addr->sa_family == AF_INET) {//��IP���͵�
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


//��ȡ����MAC��ַ
void SET_ARP_Frame_HOST(ARPFrame_t& ARPFrame1, DWORD ip) {
	for (int i = 0; i < 6; i++) {
		ARPFrame1.FrameHeader.DesMAC[i] = 0xff;//�㲥��ַ
		ARPFrame1.FrameHeader.SrcMAC[i] = 0x0f;//����
		ARPFrame1.SendHa[i] = 0x0f;//����
		ARPFrame1.RecvHa[i] = 0x00;//ȫ0����δ֪
	}

	ARPFrame1.FrameHeader.FrameType = htons(0x0806);//֡����ΪARP
	ARPFrame1.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
	ARPFrame1.ProtocolType = htons(0x0800);//Э������ΪIP
	ARPFrame1.HLen = 6;
	ARPFrame1.PLen = 4;
	ARPFrame1.Operation = htons(0x0001);//��������ΪARP����
	ARPFrame1.SendIP = inet_addr("10.10.10.10");
	ARPFrame1.RecvIP = ip;//����ip��ַ
}

void getselfmac(DWORD ip) {
	memset(myMAC, 0, sizeof(myMAC));
	ARPFrame_t ARPF_Send;
	SET_ARP_Frame_HOST(ARPF_Send, ip);
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	struct pcap_pkthdr* header = new pcap_pkthdr;
	int k;
	mylog.addInfo("����ȡ����MAC��ַ��\n");
	mylog.ARPInfo("����ARP���������", &ARPF_Send);
	//���͹���õ����ݰ�
	//��pcap_next_ex()�������ݰ���pkt_dataָ�򲶻񵽵��������ݰ�

	while ((k = pcap_next_ex(open_dev, &pkt_header, &pkt_data)) >= 0) {
		//�������ݰ�

		pcap_sendpacket(open_dev, (u_char*)&ARPF_Send, sizeof(ARPFrame_t));
		struct ARPFrame_t* arp_message;
		arp_message = (struct ARPFrame_t*)(pkt_data);
		if (k == 0)continue;
		else
		{   //֡����ΪARP���Ҳ�������ΪARP��Ӧ

			if (arp_message->FrameHeader.FrameType == htons(0x0806) && arp_message->Operation == htons(0x0002)) {


				//չʾһ�°�������
				mylog.ARPInfo("�յ�ARPӦ�������", arp_message);
				showARP(arp_message);
				//��my_mac��¼������MAC��ַ��
				for (int i = 0; i < 6; i++) {
					myMAC[i] = *(unsigned char*)(pkt_data + 22 + i);
				}
				printf("���ɹ���ȡ����MAC��ַ��\n");
				break;
			}
		}
	}
	mylog.addInfo("���ɹ���ȡ����MAC��ַ��\n");
}


//��ȡ����������MAC��ַ
void SET_ARP_Frame_DEST(ARPFrame_t& ARPFrame, char ip[20], unsigned char* mac) {
	for (int i = 0; i < 6; i++) {
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;//��APRFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ
		ARPFrame.RecvHa[i] = 0x00;
		ARPFrame.FrameHeader.SrcMAC[i] = mac[i];//����Ϊ����������MAC��ַ
		ARPFrame.SendHa[i] = mac[i];//����Ϊ����������MAC��ַ
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);//֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);//Э������ΪIP
	ARPFrame.HLen = 6;//Ӳ����ַ����Ϊ6
	ARPFrame.PLen = 4;//Э���ַ��Ϊ4
	ARPFrame.Operation = htons(0x0001);//����ΪARP����
	ARPFrame.SendIP = inet_addr(ip);//��ARPFrame->SendIP����Ϊ���������ϰ󶨵�IP��ַ

}

//��ȡip��Ӧ��mac
void Get_Other_Mac(DWORD ip_) {
	/*����ֻ����ARP���󣡣���*/

	ARPFrame_t ARPFrame;
	SET_ARP_Frame_DEST(ARPFrame, netIP[0], myMAC);
	ARPFrame.RecvIP = ip_;

	mylog.addInfo("����ȡԶ������MAC��ַ��\n");
	pcap_sendpacket(open_dev, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
	mylog.ARPInfo("����ARP���������", &ARPFrame);

}


//����ICMP���ݱ�
void Send_ICMP_Pac(BYTE type, BYTE code, const u_char* pkt_data) {
	u_char* Buffer = new u_char[70];

	// �����̫��֡�ײ�
	memcpy(((FrameHeader_t*)Buffer)->DesMAC, ((FrameHeader_t*)pkt_data)->SrcMAC, 6);
	memcpy(((FrameHeader_t*)Buffer)->SrcMAC, ((FrameHeader_t*)pkt_data)->DesMAC, 6);
	((FrameHeader_t*)Buffer)->FrameType = htons(0x0800);

	// ���IP�ײ�
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
	// ���ICMP�ײ�:ǰ8�ֽ�
	((ICMPHeader_t*)(Buffer + 34))->Type = type;
	((ICMPHeader_t*)(Buffer + 34))->Code = code;
	((ICMPHeader_t*)(Buffer + 34))->Id = 0;
	((ICMPHeader_t*)(Buffer + 34))->Sequence = 0;
	((ICMPHeader_t*)(Buffer + 34))->Checksum = htons(calCheckSum2((unsigned short*)(Buffer + 34), 36));
	// ((IPHeader_t*)(Buffer + 34))->Checksum = 0;

	// ��ԭ��������У��͵����ݰ��ײ�����ȥ
	memcpy((u_char*)(Buffer + 42), (IPHeader_t*)(pkt_data + 14), 20);
	//ȡ��ICMP�ײ���ǰ8���ֽڣ�����һ����70
	memcpy((u_char*)(Buffer + 62), (u_char*)(pkt_data + 34), 8);
	//���ͱ���
	pcap_sendpacket(open_dev, (u_char*)Buffer, 70);

	if (type == 11)
	{
		mylog.ICMPInfo("����ICMP��ʱ���ݰ�����\n");
	}
	if (type == 3)
	{
		mylog.ICMPInfo("����ICMPĿ�Ĳ��ɴ����ݰ�����\n");
	}

	delete[] Buffer;
}

//�̺߳���

//������յ������ݱ�
DWORD WINAPI Recv_Handle(LPVOID lparam) {

	RoutingTable router_table = *(RoutingTable*)(LPVOID)lparam;//�Ӳ����л�ȡ·�ɱ�
	//������
	struct bpf_program fcode;
	//�༭�����ַ���
	//pcap_compile()�������û�����Ĺ����ַ��������������Ϣ
	if (pcap_compile(open_dev, &fcode, "ip or arp", 1, bpf_u_int32(netMask[0])) < 0)
	{
		fprintf(stderr, "\nError  filter\n");
		system("pause");
		return -1;
	}

	//���ݱ���õĹ��������ù�������
	if (pcap_setfilter(open_dev, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter\n");
		system("pause");
		return -1;
	}

	//�������ݰ���ת��
	while (1)
	{
		pcap_pkthdr* pkt_header = NULL;
		const u_char* pkt_data = NULL;
		while (1)
		{
			int ret = pcap_next_ex(open_dev, &pkt_header, &pkt_data);//ץ��
			if (ret)break;//���յ���Ϣ
		}
		//��ʽ���յ��İ�Ϊ֡�ײ����Ի�ȡĿ��MAC��ַ��֡����
		FrameHeader_t* recv_header = (FrameHeader_t*)pkt_data;
		//ֻ����Ŀ��Ŀ��mac���Լ��İ�
		if (Compare(recv_header->DesMAC, myMAC))
		{
			//�յ�IP���ݱ�
			if (ntohs(recv_header->FrameType) == 0x800)
			{
				//��ʽ���յ��İ�Ϊ֡�ײ�+IP�ײ�����
				IPFrame_t* data = (IPFrame_t*)pkt_data;

				mylog.IPInfo("����IP���ݱ�����\n", data);
				//��ȡĿ��IP��ַ����·�ɱ��в��ң�����ȡ��һ��ip��ַ



				// ICMP��ʱ
				if (data->IPHeader.TTL <= 0)
				{
					//���ͳ�ʱ����
					Send_ICMP_Pac(11, 0, pkt_data);
					mylog.addInfo("����ICMP��ʱ���ݰ�����");
					continue;
				}

				IPHeader_t* IpHeader = &(data->IPHeader);
				// ����У��ͣ����ݱ��𻵻��ǳ���
				if (check_checksum(data) == 0)
				{
					mylog.IPInfo("У��ʹ��󣬶���", data);
					continue;
				}
				DWORD dstip = data->IPHeader.DstIP;

				DWORD nexthop = router_table.search(dstip);

				mylog.addInfohop("���յ���IP���ݱ�Ŀ��IP��ַΪ��", dstip);
				mylog.addInfohop("���յ���IP���ݱ���һ��Ϊ��", nexthop);
				//��ƥ����
				//Ŀ�Ĳ��ɴ�
				if (nexthop == -1)
				{
					Send_ICMP_Pac(3, 0, pkt_data);// ICMPĿ�Ĳ��ɴ�
					mylog.addInfo("����ICMPĿ�Ĳ��ɴ����ݱ�!");
					continue;
				}
				else
				{

					Datagram packet;
					packet.dst_IP = nexthop;

					//���·�װMAC��ַ(ԴMAC��ַ��Ϊmy_mac)
					for (int t = 0; t < 6; t++)
					{
						data->FrameHeader.SrcMAC[t] = myMAC[t];
					}

					data->IPHeader.TTL -= 1;// TTL��1
					// ��IPͷ�е�У���Ϊ0
					data->IPHeader.Checksum = 0;
					unsigned short buff[sizeof(IPHeader_t)];

					memset(buff, 0, sizeof(IPHeader_t));
					IPHeader_t* header = &(data->IPHeader);
					memcpy(buff, header, sizeof(IPHeader_t));

					// ����IPͷ��У���
					// data->IPHeader.Checksum = cal_checksum(check_buff, sizeof(IPHeader_t));
					data->IPHeader.Checksum = calCheckSum1(header);

					// IP-MAC��ַӳ����д��ڸ�ӳ���ϵ
					//����nexthopȡARPӳ����в鿴�Ƿ����ӳ��

					if (arpMappingTable->search(nexthop, data->FrameHeader.DesMAC))
					{
						//���ҵ������ݱ�����ֱ��ת��
						memcpy(packet.Data, pkt_data, pkt_header->len);
						packet.Len = pkt_header->len;
						if (pcap_sendpacket(open_dev, (u_char*)packet.Data, packet.Len) != 0)
						{
							// ������
							continue;
						}
						mylog.addInfo("��ת�����ݰ���");
						mylog.IPInfo("ת��", data);
					}


					// IP-MAC��ַӳ����в����ڸ�ӳ���ϵ,��ȡ
					//�Ȼ���IP���ݱ�
					//���û�����my_buffer
					else
					{
						//����50��
						if (packetcount < MAX_BUFFER)		// ���뻺�����
						{
							packet.Len = pkt_header->len;
							// ����Ҫת�������ݱ����뻺����
							memcpy(packet.Data, pkt_data, pkt_header->len);

							sendbuffer[packetcount++] = packet;

							packet.time = clock();

							mylog.IPInfo("����IP���ݱ�����\n", data);
							// ����ARP����
							Get_Other_Mac(packet.dst_IP);
						}
						else
						{
							mylog.addInfo("������������������IP���ݰ���");
							mylog.IPInfo("�����������������", data);
						}
					}
				}
			}
			//�յ�ARP���ݱ�
			else if (ntohs(recv_header->FrameType) == 0x806)
			{
				ARPFrame_t* data = (ARPFrame_t*)pkt_data;//��ʽ���յ��İ�Ϊ֡�ײ�+ARP�ײ�����
				mylog.ARPInfo("����ARP��Ӧ������", data);
				//�յ�ARP��Ӧ��
				//������Ӧ����
				if (data->Operation == ntohs(0x0002)) {
					BYTE tmp_mac[6] = { 1 };

					if (arpMappingTable->search(data->SendIP, tmp_mac)) {//��ӳ���ϵ�Ѿ��浽·�ɱ��У���������
					}
					else {

						DWORD tmp_ip = data->SendIP;
						for (int i = 0; i < 6; i++) {
							tmp_mac[i] = data->SendHa[i];
						}

						//IP-MAC��Ӧ��ϵ���
						arpMappingTable->add(data->SendIP, data->SendHa);

						//���������������Ƿ��п���ת���İ�
						for (int i = 0; i < packetcount; i++)
						{
							Datagram packet = sendbuffer[i];
							if (packet.isValid == 0)continue;
							if (clock() - packet.time >= 6000) {//��ʱ
								// packet.valid = 0;
								// my_buffer[i].valid = 0;
								deleteBuffer(sendbuffer, i);
								packetcount -= 1;
								continue;
							}
							////����IP��ַת��
							if (packet.dst_IP == data->SendIP)
							{
								IPFrame_t* ipframe = (IPFrame_t*)packet.Data;
								//���·�װIP��
								for (int i = 0; i < 6; i++) {
									ipframe->FrameHeader.SrcMAC[i] = myMAC[i];
									ipframe->FrameHeader.DesMAC[i] = data->SendHa[i];
								}
								// ����IP���ݰ�
								pcap_sendpacket(open_dev, (u_char*)packet.Data, packet.Len);

								sendbuffer[i].isValid = 0;
								mylog.addInfo("��ת�����ݰ���");
								mylog.IPInfo("ת��", ipframe);
								mylog.addInfo("�����ݰ�ת���ɹ���");
							}
						}

					}
				}
				else if (data->Operation == ntohs(0x0002)) {}//������ʲôҲ����

			}

		}


	}

}

pcap_t* open(char* deviceName) {

	pcap_t* deviceHandle = pcap_open(deviceName, 65536 /* ���ֵ */, PCAP_OPENFLAG_PROMISCUOUS, 1000, nullptr, errorbuf);

	if (deviceHandle == nullptr) {
		printf("�޷����豸: %s\n", errorbuf); // ���������Ϣ
	}
	return deviceHandle;
}

void RoutingEntry::print() {
	// ��ӡ���
	printf("%d   ", index);

	in_addr maskAddr;
	in_addr dstNetAddr;
	in_addr nextHopAddr;

	// ��ӡ����
	maskAddr.s_addr = mask;
	printf("%s\t", inet_ntoa(maskAddr));

	// ��ӡĿ������
	dstNetAddr.s_addr = dst_net;
	printf("%s\t", inet_ntoa(dstNetAddr));

	// ��ӡ��һ��IP��ַ
	nextHopAddr.s_addr = next_hop;
	printf("%s\t", inet_ntoa(nextHopAddr));

	// �û��Ƿ�ɲ���
	if (flag == 0)
		printf("0\n");
	else
		printf("1\n");
	printf("\n");
}

/*·�ɱ�*/

//��ʼ�������ֱ�����ӵ�����
RoutingTable::RoutingTable()
{
	head = new RoutingEntry;
	head->next = NULL;
	num = 0;
	//ͨ���õ���˫IP�����룬��·�ɱ������ֱ�����������磬����������Ϊ0��������ɾ����
	for (int i = 0; i < 2; i++)
	{
		RoutingEntry* entry = new RoutingEntry;
		//���ֱ������������
		entry->dst_net = (inet_addr(netIP[i])) & (inet_addr(netMask[i]));
		entry->mask = inet_addr(netMask[i]);
		entry->flag = 0;
		this->add(entry);
	}

}

void RoutingTable::add(RoutingEntry* newRouteEntry) {
	// ���·�ɱ�Ϊ�գ�ֱ�ӽ��µ�·�ɱ�����ӵ�ͷ�ڵ����
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
	// ���±��
	RoutingEntry* p = head->next;
	for (int i = 0; p != nullptr; i++) {
		p->index = i;
		p = p->next;
	}

	num++;
	mylog.addInfo("�ѳɹ���Ӹ�·�ɱ��");
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
		printf("���޴�����������룡\n");
		return;
	}

	if (number == 0)//ɾ����һ��
	{
		temp = head->next;
		//Ĭ��·�ɱ����ɾ
		if (temp->flag == 0)
		{
			printf("û��Ȩ��ɾ�����\n");
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
				printf("�ѳɹ�ɾ����·�ɱ��\n");

			}

		}
	}
	else
	{
		temp = head->next;
		for (int i = 0; i < number - 1; i++)//������index��,Ѱ��ɾ������ǰ�����
		{
			temp = temp->next;
		}
		RoutingEntry* rem = new RoutingEntry;
		rem = temp->next;//Ҫɾ���Ľ��x

		if (rem->flag == 0)
		{
			printf("û��Ȩ��ɾ�����\n");
			return;
		}
		if (rem->next == NULL)//βɾ
		{
			temp->next = NULL;

			//	printf("�ѳɹ�ɾ��ָ���\n");

		}
		//�м�ɾ
		temp->next = rem->next;
		printf("�ѳɹ�ɾ����·�ɱ��\n");

	}


	// ���±��
	RoutingEntry* p = head->next;
	for (int i = 0; p != nullptr; i++) {
		p->index = i;
		p = p->next;
	}

	num--;
	mylog.addInfo("·�ɱ�ɾ���ɹ�!");
	return;
}

// ��ӡ·�ɱ�
void RoutingTable::print() {
	RoutingEntry* temp = head->next;
	printf("��·�ɱ�\n");
	int t = 0;
	while (temp != NULL) {
		temp->print();
		temp = temp->next;
		t++;
	}
}

// ������һ����IP��ַ������ΪĿ��IP��ַ��
DWORD RoutingTable::search(DWORD dst_ip) {
	DWORD next_hop = -1;

	RoutingEntry* t = head->next;
	for (; t != NULL; t = t->next) {
		if ((t->mask & dst_ip) == t->dst_net) {
			if (t->flag == 0)  // ֱ������������
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

/*��־��ӡ����*/
FILE* Log::logFile = nullptr;

Log::Log() {
	logFile = fopen("logfile.txt", "a+");  // �Ը��ӵķ�ʽ���ļ�
	if (!logFile) {
		// �����ļ���ʧ�ܵ�������������������Ϣ����׼��������stderr��
		fprintf(stderr, "Error opening log file!\n");
	}
}

Log::~Log() {
	if (logFile) {
		fclose(logFile);
	}
}

// ��־��Ϣ��ʶ
void Log::addInfo(const char* str) {
	fprintf(logFile, "%s\n", str);
}
// ��־��Ϣ��ʶ����һ����Ϣ
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

// ARP���ݰ���Ϣ
void Log::ARPInfo(const char* str, ARPFrame_t* p) {
	fprintf(logFile, "%s��ARP ���ݰ���\n", str);

	// ԴIP��ַ
	in_addr addr;
	addr.s_addr = p->SendIP;
	fprintf(logFile, "ԴIP�� %s\n", inet_ntoa(addr));

	// ԴMAC��ַ
	fprintf(logFile, "ԴMAC�� %02X-%02X-%02X-%02X-%02X-%02X\n",
		p->SendHa[0], p->SendHa[1], p->SendHa[2], p->SendHa[3], p->SendHa[4], p->SendHa[5]);

	// Ŀ��IP��ַ
	in_addr addr2;
	addr2.s_addr = p->RecvIP;
	fprintf(logFile, "Ŀ��IP�� %s\n", inet_ntoa(addr2));

	// Ŀ��MAC��ַ
	fprintf(logFile, "Ŀ��MAC�� %02X-%02X-%02X-%02X-%02X-%02X\n",
		p->RecvHa[0], p->RecvHa[1], p->RecvHa[2], p->RecvHa[3], p->RecvHa[4], p->RecvHa[5]);

	fprintf(logFile, "\n");
}

// IP���ݰ���Ϣ
void Log::IPInfo(const char* str, IPFrame_t* p) {
	fprintf(logFile, "%s��IP ���ݰ���\n", str);

	// ԴIP��ַ
	fprintf(logFile, "ԴIP�� %s\n", inet_ntoa(*(in_addr*)&(p->IPHeader.SrcIP)));

	// ԴMAC��ַ
	fprintf(logFile, "ԴMAC�� %02X-%02X-%02X-%02X-%02X-%02X\n",
		p->FrameHeader.SrcMAC[0], p->FrameHeader.SrcMAC[1], p->FrameHeader.SrcMAC[2],
		p->FrameHeader.SrcMAC[3], p->FrameHeader.SrcMAC[4], p->FrameHeader.SrcMAC[5]);

	// Ŀ��IP��ַ
	fprintf(logFile, "Ŀ��IP�� %s\n", inet_ntoa(*(in_addr*)&(p->IPHeader.DstIP)));



	// Ŀ��MAC��ַ
	fprintf(logFile, "Ŀ��MAC�� %02X-%02X-%02X-%02X-%02X-%02X\n",
		p->FrameHeader.DesMAC[0], p->FrameHeader.DesMAC[1], p->FrameHeader.DesMAC[2],
		p->FrameHeader.DesMAC[3], p->FrameHeader.DesMAC[4], p->FrameHeader.DesMAC[5]);

	fprintf(logFile, "\n");
}

// ICMP��Ϣ
void Log::ICMPInfo(const char* str) {
	fprintf(logFile, "%s\n", str);
}

// ��ӡMAC��ַ
void printMac(BYTE MAC[]) {
	printf("MAC��ַΪ�� ");
	for (int i = 0; i < 5; i++)
		printf("%02X-", MAC[i]);
	printf("%02X\n", MAC[5]);
}

// ARP��
int ArpTable::num = 0;
// ���ARP�����ʵ��
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

//������IP���ݰ�ͷ
unsigned short calCheckSum1(IPHeader_t* temp)
{
	unsigned int sum = 0;
	WORD* t = (WORD*)temp;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++) {
		sum += t[i];
		while (sum >= 0x10000) {
			//������������лؾ�
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	return (unsigned short)~sum;
}

unsigned short calCheckSum2(unsigned short* pBuffer, int nSize) {

	//���㷽������У����ֶ�����Ϊ0�������������Ѿ�Ϊ0�ģ�
	//��˳���ÿ16λ��1����=2�ֽڣ����мӷ����㣻
	//�������ͽ���λ�ӵ����λ
	//���ۼӵĽ��ȡ����������ͷ��У���ֵ
	
	unsigned long ulCheckSum = 0;
	while (nSize > 1)
	{
		ulCheckSum += *pBuffer++;
		nSize -= sizeof(unsigned short);//ÿ16λһ��
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
	WORD* t = (WORD*)&temp->IPHeader;//ÿ16λΪһ��
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++) {
		sum += t[i];
		while (sum >= 0x10000) {
			//����ԭУ���һ��������
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}

	if (sum == 65535)return 1;//ȫ1��У�����ȷ
	return 0;
}


int main() {
	//��������ȡ˫IP
	findtheTWO();
	printf("������˫IP��ַ����������Ϊ��\n");
	//�����ʱ�洢��IP��ַ����������
	for (int i = 0; i < 2; i++) {
		printf("%s\t", netIP[i]);
		printf("%s\n", netMask[i]);
	}
	//��ȡ����MAC��ַ
	getselfmac(inet_addr(netIP[0]));
	printMac(myMAC);
	//·�ɱ�
	RoutingTable my_route;
	//����ת���߳�
	hThread = CreateThread(NULL, NULL, Recv_Handle, LPVOID(&my_route), 0, &dwThreadId);

	//��·�ɱ����ز���
	int choice;
	while (1)
	{
		printf("==================== 1. ��ӡ·�ɱ� ====================\n");
		printf("==================== 2. ���·�ɱ��� ====================\n");
		printf("==================== 3. ɾ��·�ɱ��� ====================\n");
		printf("\n");
		printf("|| ������������ ��");
		scanf("%d", &choice);
		RoutingEntry* entry = new RoutingEntry;

		switch (choice) {
		case 1:
			my_route.print();
			break;
		case 2:
			char t[30];
			printf("Destination Network��");
			scanf("%s", &t);
			entry->dst_net = inet_addr(t);
			printf("MASK��");
			scanf("%s", &t);
			entry->mask = inet_addr(t);
			printf("Next Hop��");
			scanf("%s", &t);
			entry->next_hop = inet_addr(t);
			entry->flag = 1;
			entry->print();
			my_route.add(entry);
			break;
		case 3:
			my_route.print();
			printf("������Ҫɾ���ı��");
			int i;
			scanf("%d", &i);
			my_route.remove(i);
			break;
		default:
			printf("������Ч������������\n");
			break;
		}
	}
	return 0;

}