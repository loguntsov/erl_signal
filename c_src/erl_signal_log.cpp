#include <iostream>
#include <sstream>
// #include <cstring>

#include "erl_signal_log.h"

void es_log(const char * message) {
/*
    if (message != NULL) {
        std::cout << message << "\n" << std::flush ;
    }
*/
}

void es_log_hex(const char *message, const char *data, int len) {
/*
    if (message != NULL) {
        std::cout << message << len << "=";
    }
    char const hex_chars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

    if (data != NULL) {
        for(int i=0; i<len; i++) {
            char const byte = ((char *) data)[i];
            std::cout << hex_chars[ ( byte & 0xF0 ) >> 4 ];
            std::cout << hex_chars[ ( byte & 0x0F ) >> 0 ];
            std::cout << "|";            
        }     
        std::cout << "\n";
    }
    std::cout << std::flush;
*/
}
    
