#ifndef TSHARK_DATATYPE_H
#define TSHARK_DATATYPE_H

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
//网卡信息1. \Device\NPF_{A0621D3E-EA7A-4415-8753-313805AD0861} (本地连接* 12)
struct AdapterInfo {
	int id;//前面的编号
	std::string name; //中间的名称
    std::string remark;//括号里的名称
};  
struct Packet {
    int frame_number;
    std::string time;
    std::string src_mac;
    std::string dst_mac;
    uint32_t cap_len;
    uint32_t len;
    std::string src_ip;
    std::string src_location;
    uint16_t src_port;
    std::string dst_ip;
    std::string dst_location;
    uint16_t dst_port;
    std::string protocol;
    std::string info;
    uint32_t file_offset;
};


// PCAP全局文件头
struct PcapHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

// 每一个数据报文前面的头
struct PacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t caplen;
    uint32_t len;
};


#endif // TSHARK_DATATYPE_H
