#pragma once

#pragma warning(disable:4996) // пока не понимаю зачем, но исправлет ошибку
#include <winsock2.h>
#include <string>

class MySniffer
{
public:

#pragma pack(push,1)
	struct IPHeader_t
	{
		unsigned char  ver_len;			// версия и длина заголовка
		unsigned char  tos;				// тип сервиса 
		unsigned short length;			// длина всего пакета 
		unsigned short id;				// id 
		unsigned short flgs_offset;		// флаги и смещение
		unsigned char  ttl;				// время жизни 
		unsigned char  protocol;		// протокол 
		unsigned short checksum;		// контрольная сумма 
		unsigned long  src;				// IP-адрес отправителя 
		unsigned long  dest;			// IP-адрес назначения 
		unsigned char  data[];			// данные 
	};

	struct UDPHeader_t
	{
		unsigned short src_port;		// порт источника
		unsigned short dst_port;		// порт получателя
		unsigned short length;			// длина UDP
		unsigned short checksum;		// контрольная сумма 
		unsigned char  data[];			// данные 
	};

	struct TCPHeader_t {
		unsigned short src_port;		// порт источника
		unsigned short dst_port;		// порт получателя
		unsigned long  seq_num;			// порядковый номер
		unsigned long  ack_num;			// номер подтверждения
		unsigned short length		:4;	// длина заголовка 
		unsigned short flags_reserv	:12;// резерв и флаги
		unsigned short window_size;		// размер Окна
		unsigned short checksum;		// контрольная сумма
		unsigned short urp;				// указатель важности
		unsigned char  data[];			// данные 
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

