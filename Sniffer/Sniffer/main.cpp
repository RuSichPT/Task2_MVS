#include <iostream>
#include "MySniffer.h"

int main(int argc, char* argv[])
{
    // Перебираем каждый аргумент и выводим его порядковый номер и значение
    for (int count = 0; count < argc; ++count)
        std::cout << count << " " << argv[count] << '\n';

    std::string ip = argv[1];
    std::string fileName = argv[2];

    MySniffer sniffer;

    sniffer.listenEthernet(ip, fileName);

    return 0;
}

