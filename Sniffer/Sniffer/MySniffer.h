#pragma once

#pragma warning(disable:4996) // ���� �� ������� �����, �� ��������� ������
#include <winsock2.h>
#include <string>

class MySniffer
{
public:

#pragma pack(push,1)
	struct IPHeader_t
	{
		unsigned char  ver_len;			// ������ � ����� ���������
		unsigned char  tos;				// ��� ������� 
		unsigned short length;			// ����� ����� ������ 
		unsigned short id;				// id 
		unsigned short flgs_offset;		// ����� � ��������
		unsigned char  ttl;				// ����� ����� 
		unsigned char  protocol;		// �������� 
		unsigned short checksum;		// ����������� ����� 
		unsigned long  src;				// IP-����� ����������� 
		unsigned long  dest;			// IP-����� ���������� 
		unsigned char  data[];			// ������ 
	};

	struct UDPHeader_t
	{
		unsigned short src_port;		// ���� ���������
		unsigned short dst_port;		// ���� ����������
		unsigned short length;			// ����� UDP
		unsigned short checksum;		// ����������� ����� 
		unsigned char  data[];			// ������ 
	};

	struct TCPHeader_t {
		unsigned short src_port;		// ���� ���������
		unsigned short dst_port;		// ���� ����������
		unsigned long  seq_num;			// ���������� �����
		unsigned long  ack_num;			// ����� �������������
		unsigned short length		:4;	// ����� ��������� 
		unsigned short flags_reserv	:12;// ������ � �����
		unsigned short window_size;		// ������ ����
		unsigned short checksum;		// ����������� �����
		unsigned short urp;				// ��������� ��������
		unsigned char  data[];			// ������ 
	};
#pragma pack(pop)

private:
	SOCKET m_socket;
public:
	MySniffer()
		:m_socket(0)
	{};
	~MySniffer(){};

	void listenEthernet(std::string ip, std::string fileName);

private:
	std::string getStrFromIPhdr(IPHeader_t* hdr);
	std::string getStrFromTCPhdr(TCPHeader_t* hdr);
	std::string getStrFromUDPhdr(UDPHeader_t* hdr);
	std::string shortToStrHex(unsigned short n);
	std::string charToStrHex(unsigned char n);
	std::string writeSpaces(int count);
};

