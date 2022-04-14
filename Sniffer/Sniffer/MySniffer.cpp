#include "MySniffer.h"
#include "Timer.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <conio.h>
#include <iomanip>

#define SIO_RCVALL          0x98000001
#define MAX_PACKET_SIZE     0x10000
#define SIZE_NAME           100

#define BYTE_L(u)           (u & 0xF)
#define BYTE_H(u)           (u >> 4)

#define IP_FLAGS(u)         (u >> 13)
#define IP_OFFSET(u)        (u & 0x1FFF)

#define IP_PROTO_UDP        17
#define IP_PROTO_TCP        6

void MySniffer::listenEthernet(std::string ip, std::string fileName)
{
    // Инициализация
    WSAData wsadata;
    if (WSAStartup(MAKEWORD(2, 2), &wsadata) == 0)
    {
        std::cout << "WSA Startup succes" << std::endl;
    }
    else
    {
        std::cout << "WSA Startup unsucces" << std::endl;
        WSACleanup();
        return;
    }

    // Создание сокета
    m_socket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);

    if (m_socket != INVALID_SOCKET)
    {
        std::cout << "Socket RAW created " << std::endl;
    }
    else
    {
        std::cout << "Socket RAW not created, try to run under administrator " << WSAGetLastError() << std::endl;
        WSACleanup();
        return;
    }

    // Привязка сокета
    sockaddr_in sockAddr;
    ZeroMemory(&sockAddr, sizeof(sockAddr));
    sockAddr.sin_family = AF_INET;
    sockAddr.sin_addr.s_addr = inet_addr(ip.c_str());

    if (bind(m_socket, (sockaddr*)&sockAddr, sizeof(sockAddr)) != SOCKET_ERROR)
    {
        std::cout << "Socket RAW succed binded" << std::endl;
    }
    else
    {
        std::cout << "Socket RAW not binded, check ip " << WSAGetLastError() << std::endl;
        closesocket(m_socket);
        WSACleanup();
        return;
    }

    // Включение promiscuous mode (Прием всех ip заголовков)
    bool receiveAll = true;
    if (ioctlsocket(m_socket, SIO_RCVALL, (unsigned long*)&receiveAll) != SOCKET_ERROR)
    {
        std::cout << "Socket RAW set promiscuous mode" << std::endl;
    }
    else
    {
        std::cout << "Socket RAW not set promiscuous mode " << WSAGetLastError() << std::endl;
        return;
    }

    uint8_t *buf = new uint8_t[MAX_PACKET_SIZE];
    ZeroMemory(buf, MAX_PACKET_SIZE);
    std::ofstream file(fileName);
    
    if (file.is_open()) 
    {
        std::cout << "File " << fileName << " ready to writing " << std::endl;
    }
    else 
    {
        std::cout << "File " << fileName<< "  not ready to writing"  << std::endl;
    }

    Timer t;

    while (!_kbhit())
    {
        int count = recv(m_socket, (char*)buf, MAX_PACKET_SIZE, 0);

        if (count != SOCKET_ERROR)
        {
            IPHeader_t* ipHdr = (IPHeader_t*)buf;

            // обработка IP-пакета
            if (count >= sizeof(IPHeader_t))
            {
                std::string str = getStrFromIPhdr(ipHdr);

                if (ipHdr->protocol == IP_PROTO_TCP)
                {
                    TCPHeader_t* tcpHdr = (TCPHeader_t*)ipHdr->data;
                    str += "\n" + writeSpaces(15);
                    str += getStrFromTCPhdr(tcpHdr);
                }
                else if(ipHdr->protocol == IP_PROTO_UDP)
                {
                    UDPHeader_t* udpHdr = (UDPHeader_t*)ipHdr->data;
                    str += "\n" + writeSpaces(15);
                    str += getStrFromUDPhdr(udpHdr);
                }
                std::cout <<"time=" << t.elapsed() << " " << str << std::endl;

                file << "time=" << t.elapsed() << " " ;
                file.write(str.c_str(), str.length());
                file << "\n";
            }
        }
        else 
        {
            std::cout << WSAGetLastError() << std::endl;
        }
    }

    file.close();
    delete[] buf;
    closesocket(m_socket);
    WSACleanup();
}

std::string MySniffer::getStrFromIPhdr(IPHeader_t* hdr)
{
    std::string str = "";
    in_addr src, dest;

    str += "IP:";
    str += "ver=";
    str += std::to_string( BYTE_H(hdr->ver_len) );
    str += " len=";
    str += std::to_string( BYTE_L(hdr->ver_len) * 4 );
    str += " tos=";
    str += charToStrHex(hdr->tos);
    str += " totLen=";
    str += std::to_string( ntohs(hdr->length) );
    str += " id=";
    str += std::to_string( ntohs(hdr->id) );
    str += " flags,offset=";
    str += shortToStrHex( (ntohs(hdr->flgs_offset)) );
    str += " ttl=";
    str += std::to_string(hdr->ttl);
    str += " proto=";
    str += std::to_string(hdr->protocol);
    str += " checksum=";
    str += shortToStrHex( ntohs(hdr->checksum) );
    src.s_addr = hdr->src;
    str += " src=";
    str += inet_ntoa(src);
    dest.s_addr = hdr->dest;
    str += " dest=";
    str += inet_ntoa(dest);

    return str;
}

std::string MySniffer::getStrFromTCPhdr(TCPHeader_t* hdr)
{
    std::string str = "";

    str += "TCP:";
    str += " src_port=";
    str += std::to_string(ntohs(hdr->src_port));
    str += " dst_port=";
    str += std::to_string(ntohs(hdr->dst_port));
    str += " seq_num=";
    str += std::to_string(ntohl(hdr->seq_num));
    str += " ack_num=";
    str += std::to_string(ntohl(hdr->ack_num));
    str += " len=";
    str += std::to_string(BYTE_L(hdr->length) * 4);
    str += " flags=";
    str += shortToStrHex((ntohs(hdr->flags_reserv)));
    str += " window=";
    str += std::to_string((ntohs(hdr->window_size)));
    str += " checksum=";
    str += shortToStrHex((ntohs(hdr->checksum)));
    str += " urdPtr=";
    str += std::to_string((ntohs(hdr->urp)));

    return str;
}

std::string MySniffer::getStrFromUDPhdr(UDPHeader_t* hdr)
{
    std::string str = "";

    str += "UDP:";
    str += " src_port=";
    str += std::to_string(ntohs(hdr->src_port));
    str += " dst_port=";
    str += std::to_string(ntohs(hdr->dst_port));
    str += " len=";
    str += std::to_string(ntohs(hdr->length) * 4);
    str += " checksum=";
    str += shortToStrHex((ntohs(hdr->checksum)));

    return str;
}

std::string MySniffer::shortToStrHex(unsigned short n)
{
    std::stringstream ss;
    ss << "0x" << std::hex << n;
    return ss.str();
}


std::string MySniffer::charToStrHex(unsigned char n)
{
    std::stringstream ss;
    ss << "0x" << std::hex << (short)n;
    return ss.str();
}

std::string MySniffer::writeSpaces(int count)
{
    std::string str;

    for (int i = 0; i < count; i++)
    {
        str += " ";
    }

    return str;
}