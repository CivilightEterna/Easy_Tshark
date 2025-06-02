#ifndef TSHARKMANAGER_H
#define TSHARKMANAGER_H
#include "tshark_datatype.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "ip2region_util.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <sstream>
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <thread>
#include "process_util.hpp"
class TsharkManager {

public:
    TsharkManager(std::string workDir);
    ~TsharkManager();
    //枚举网卡
    std::vector<AdapterInfo>getNetworkAdapters();

    // 分析数据包文件
    bool analysisFile(std::string filePath);

    // 打印所有数据包的信息
    void printAllPackets();

    // 获取指定编号数据包的十六进制数据
    bool getPacketHexData(uint32_t frameNumber, std::vector<unsigned char>& data);
public:
    //开始抓包
    bool startCapture(std::string adapterName);
    // 停止抓包
    bool stopCapture();

private:
    // 解析每一行
    bool parseLine(std::string line, std::shared_ptr<Packet> packet);

private:

    std::string tsharkPath;
    IP2RegionUtil ip2RegionUtil;

    // 当前分析的文件路径
    std::string currentFilePath;

    // 分析得到的所有数据包信息，key是数据包ID，value是数据包信息指针，方便根据编号获取指定数据包信息
    std::unordered_map<uint32_t, std::shared_ptr<Packet>> allPackets;
private:
    //在线采集数据包的工作进程
    void captureWorkerThreadEntry(std::string adapterName);
    //在线分析线程captureWorkThread 是用来保存和管理抓包线程的成员变量，保证抓包任务可以在后台独立运行，并且可以被安全地控制和释放
    std::shared_ptr<std::thread>captureWorkThread;
    //是否停止抓包的标记
    bool stopFlag;
    // 在线抓包的tshark进程PID
    PID_T captureTsharkPid;
};


#endif //TSHARKMANAGER_H