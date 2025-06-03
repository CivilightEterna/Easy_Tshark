
#include "tshark_manager.h"
#include "third_library/loguru/loguru.hpp"
#include <set>
#ifdef _WIN32
#define popen _popen
#define pclose _pclose
#endif // _WIN32

TsharkManager::TsharkManager(std::string workDir) {
    this->tsharkPath = "D:/wireshark/tshark";
    std::string xdbPath = workDir + "/third_library/ip2region/ip2region.xdb";
    ip2RegionUtil.init(xdbPath);
}

TsharkManager::~TsharkManager() {
    ip2RegionUtil.uninit();
}

std::vector<AdapterInfo>TsharkManager::getNetworkAdapters() {
//过滤掉虚拟网卡
    std::set<std::string>specialInterfaces = { "sshdump","ciscodump","udpdump","randpkt"  };
    //枚举到的网卡列表
    std::vector<AdapterInfo> interfaces;
	//准备一个buffer缓冲区，来读取tshark -D每一行的内容
    char buffer[256] = { 0 };
    std::string result;
	//启动tshark命令
	std::string cmd = tsharkPath + " -D";
	FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) {
		throw std::runtime_error("Failed to run tshark command !");
    }
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
	}
	//解析tshark的输出结果,输出结果的格式是：1.\Devices\NPF_{xxxx}(网卡描述)
	std::istringstream stream(result);
    std::string line;
	int index = 1;
    while (std::getline(stream, line)) {
        //通过空格拆分字符
		size_t startPos = line.find(' ');
        if (startPos != std::string::npos) {
            size_t endPos = line.find(' ', startPos + 1);
            std::string interfaceName;
            if (endPos != std::string::npos) {
				interfaceName = line.substr(startPos + 1, endPos - startPos - 1);
            }
            else {
				interfaceName = line.substr(startPos + 1);
            }
            //过滤掉特殊的网卡
            if (specialInterfaces.find(interfaceName) != specialInterfaces.end()) {
                continue;
            }
            AdapterInfo adapterInfo;
			adapterInfo.name = interfaceName;
			adapterInfo.id = index++;
            //定位到括号，把括号里面的备注内容提取出来
            if(line.find("(") !=std::string::npos && line.find(")") != std::string::npos){
                adapterInfo.remark = line.substr(line.find("(") + 1, line.find(")") - line.find("(") - 1);//就是从左括号后面第一个字符开始，截取到右括号前的所有字符。
            }
			interfaces.push_back(adapterInfo);

        }
    }
	_pclose(pipe);
	return interfaces;
}
bool TsharkManager::analysisFile(std::string filePath) {

    std::vector<std::string> tsharkArgs = {
            tsharkPath,
            "-r", filePath,
            "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "frame.len",
            "-e", "frame.cap_len",
            "-e", "eth.src",
            "-e", "eth.dst",
            "-e", "ip.src",
            "-e", "ipv6.src",
            "-e", "ip.dst",
            "-e", "ipv6.dst",
            "-e", "tcp.srcport",
            "-e", "udp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.dstport",
            "-e", "_ws.col.Protocol",
            "-e", "_ws.col.Info",
    };

    std::string command;
    for (auto arg : tsharkArgs) {
        command += arg;
        command += " ";
    }

    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        //std::cerr << "Failed to run tshark command!" << std::endl;
		LOG_F(ERROR, "无法运行 tshark 命令: %s", command.c_str());    
        return false;
    }

    char buffer[1024];

    // 当前处理的报文在文件中的偏移，第一个报文的偏移就是全局文件头24(也就是sizeof(PcapHeader))字节
    uint32_t file_offset = sizeof(PcapHeader);
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::shared_ptr<Packet> packet = std::make_shared<Packet>();
        parseLine(buffer, packet);

        // 计算当前报文的偏移，然后记录在Packet对象中
        packet->file_offset = file_offset + sizeof(PacketHeader);

        // 更新偏移游标
        file_offset = file_offset + sizeof(PacketHeader) + packet->cap_len;

        // 获取IP地理位置
        packet->src_location = ip2RegionUtil.getIpLocation(packet->src_ip);
        packet->dst_location = ip2RegionUtil.getIpLocation(packet->dst_ip);

        // 将分析的数据包插入保存起来
        allPackets.insert(std::make_pair<>(packet->frame_number, packet));
    }

    _pclose(pipe);

    // 记录当前分析的文件路径
    currentFilePath = filePath;

    LOG_F(INFO, "分析完成，数据包总数：%d", allPackets.size());

    return true;
}

void TsharkManager::printAllPackets() {

    for (auto pair : allPackets) {

        std::shared_ptr<Packet> packet = pair.second;

        // 构建JSON对象
        rapidjson::Document pktObj;
        rapidjson::Document::AllocatorType& allocator = pktObj.GetAllocator();
        pktObj.SetObject();

        pktObj.AddMember("frame_number", packet->frame_number, allocator);
        pktObj.AddMember("timestamp", rapidjson::Value(packet->time.c_str(), allocator), allocator);
        pktObj.AddMember("src_mac", rapidjson::Value(packet->src_mac.c_str(), allocator), allocator);
        pktObj.AddMember("dst_mac", rapidjson::Value(packet->dst_mac.c_str(), allocator), allocator);
        pktObj.AddMember("src_ip", rapidjson::Value(packet->src_ip.c_str(), allocator), allocator);
        pktObj.AddMember("src_location", rapidjson::Value(packet->src_location.c_str(), allocator), allocator);
        pktObj.AddMember("src_port", packet->src_port, allocator);
        pktObj.AddMember("dst_ip", rapidjson::Value(packet->dst_ip.c_str(), allocator), allocator);
        pktObj.AddMember("dst_location", rapidjson::Value(packet->dst_location.c_str(), allocator), allocator);
        pktObj.AddMember("dst_port", packet->dst_port, allocator);
        pktObj.AddMember("protocol", rapidjson::Value(packet->protocol.c_str(), allocator), allocator);
        pktObj.AddMember("info", rapidjson::Value(packet->info.c_str(), allocator), allocator);
        pktObj.AddMember("file_offset", packet->file_offset, allocator);
        pktObj.AddMember("cap_len", packet->cap_len, allocator);
        pktObj.AddMember("len", packet->len, allocator);

        // 序列化为 JSON 字符串
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        pktObj.Accept(writer);

        // 打印JSON输出
        std::cout << buffer.GetString() << std::endl;
    }

}

bool TsharkManager::parseLine(std::string line, std::shared_ptr<Packet> packet) {
    if (line.back() == '\n') {
        line.pop_back();
    }
    std::stringstream ss(line);
    std::string field;
    std::vector<std::string> fields;

    size_t start = 0, end;
    while ((end = line.find('\t', start)) != std::string::npos) {
        fields.push_back(line.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(line.substr(start)); // 添加最后一个子串
    // 字段顺序：
    // 0: frame.number
    // 1: frame.time_epoch
    // 2: frame.len
    // 3: frame.cap_len
    // 4: eth.src
    // 5: eth.dst
    // 6: ip.src
    // 7: ipv6.src
    // 8: ip.dst
    // 9: ipv6.dst
    // 10: tcp.srcport
    // 11: udp.srcport
    // 12: tcp.dstport
    // 13: udp.dstport
    // 14: _ws.col.Protocol
    // 15: _ws.col.Info

    if (fields.size() >= 16) {
        packet->frame_number = std::stoi(fields[0]);
        packet->time = fields[1];
        packet->len = std::stoi(fields[2]);
        packet->cap_len = std::stoi(fields[3]);
        packet->src_mac = fields[4];
        packet->dst_mac = fields[5];
        packet->src_ip = fields[6].empty() ? fields[7] : fields[6];
        packet->dst_ip = fields[8].empty() ? fields[9] : fields[8];
        if (!fields[10].empty() || !fields[11].empty()) {
            packet->src_port = std::stoi(fields[10].empty() ? fields[11] : fields[10]);
        }

        if (!fields[12].empty() || !fields[13].empty()) {
            packet->dst_port = std::stoi(fields[12].empty() ? fields[13] : fields[12]);
        }
        packet->protocol = fields[14];
        packet->info = fields[15];

        return true;
    }
    else {
        return false;
    }
}

bool TsharkManager::getPacketHexData(uint32_t frameNumber, std::vector<unsigned char>& data) {

    // 获取指定编号数据包的信息
    if (allPackets.find(frameNumber) == allPackets.end()) {
        //std::cerr << "找不到编号为 " << frameNumber << " 的数据包" << std::endl;
		LOG_F(ERROR, "找不到编号为 %d 的数据包", frameNumber);
        return false;
    }
    std::shared_ptr<Packet> packet = allPackets[frameNumber];


    // 打开文件（以二进制模式）
    std::ifstream file(currentFilePath, std::ios::binary);
    if (!file) {
        //std::cerr << "无法打开文件: " << currentFilePath << std::endl;
		LOG_F(ERROR, "无法打开文件: %s", currentFilePath.c_str());    
        return false;
    }

    // 移动到指定偏移位置
    file.seekg(packet->file_offset, std::ios::beg);
    if (!file) {
        //std::cerr << "seekg 失败，偏移可能超出文件大小" << std::endl;
		LOG_F(ERROR, "seekg 失败，偏移可能超出文件大小");
        return false;
    }

    // 读取数据
    data.resize(packet->cap_len);
    file.read(reinterpret_cast<char*>(data.data()), packet->cap_len);

    return true;
}
//开始抓包
bool TsharkManager::startCapture(std::string adapterName) {
	LOG_F(INFO, "即将开始抓包，网卡: %s", adapterName.c_str());
	//跨平台的线程安全问题，使用std::shared_ptr来管理线程对象  
	captureWorkThread = std::make_shared<std::thread>(&TsharkManager::captureWorkerThreadEntry, this, "\"" +adapterName +"\"");
    //初始化停止标志
    stopFlag = false;
	return true;
}
void TsharkManager::captureWorkerThreadEntry(std::string adapterName) {
    std::string captureFile = "captrue.pcap";
    std::vector<std::string>tsharkArgs = {
        tsharkPath,
        "-i", adapterName.c_str(),
        "-w", captureFile,
        "-F","pcap",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "frame.cap_len",
        "-e", "eth.src",
        "-e", "eth.dst",
        "-e", "ip.src",
        "-e", "ipv6.src",
        "-e", "ip.dst",
        "-e", "ipv6.dst",
        "-e", "tcp.srcport",
        "-e", "udp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",

    };
	std::string command;
    for (auto arg : tsharkArgs) {
        command += arg;
		command += " ";
    }
	//使用ProcessUtil::PopenEx来执行tshark命令，并捕获tshark的PID，防止无流量时tshark进程一直存在
	FILE* pipe = ProcessUtil::PopenEx(command.c_str(), &captureTsharkPid);
    if (!pipe) {
        LOG_F(ERROR, "无法运行 tshark 命令: %s", command.c_str());    
		return;
    }
	char buffer[4096];
	//当前处理的报文在文件中的偏移，第一个报文的偏移就是全局文件头24(也就是sizeof(PcapHeader))字节
    uint32_t file_offset = sizeof(PcapHeader);
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr && !stopFlag) {
        //在线采集的时候过滤额外的信息
		std::string line(buffer);
        if(line.find("Capturing on") != std::string::npos) {
            continue; // 跳过捕获信息
		}
		std::shared_ptr<Packet>packet = std::make_shared<Packet>();
        if (!parseLine(buffer, packet)) {
            LOG_F(ERROR, buffer);
			assert(false);
        }
    //计算当前报文的偏移，然后记录在Packet对象中
        packet->file_offset = file_offset + sizeof(PacketHeader);
        //更新偏移游标
        file_offset = file_offset + sizeof(PacketHeader) + packet->cap_len;
        //获取IP地理位置
		packet->src_location = IP2RegionUtil::getIpLocation(packet->src_ip);
        packet->dst_location = IP2RegionUtil::getIpLocation(packet->dst_ip);
        //将分析的数据包插入保存起来
		allPackets.insert(std::make_pair<>(packet->frame_number, packet));
    }
	pclose(pipe);
	// 记录当前分析的文件路径
    currentFilePath = captureFile;
	/*LOG_F(INFO, "抓包完成，数据包总数：%d", allPackets.size());*/

}
//停止抓包
bool TsharkManager::stopCapture() {
    LOG_F(INFO, "即将停止抓包");
	stopFlag = true;
	ProcessUtil::Kill(captureTsharkPid); // 停止 tshark 进程
	captureWorkThread->join(); // 等待抓包线程结束
	return true;
}
//获取指定网卡的流量统计数据
void TsharkManager::adapterFlowTrendMonitorThreadEntry(std::string adapterName) {
    adapterFlowTrendMapLock.lock();
    if (adapterFlowTrendMonitorMap.find(adapterName) == adapterFlowTrendMonitorMap.end()) {
        adapterFlowTrendMapLock.unlock();
        return;
    }
    adapterFlowTrendMapLock.unlock();
    char buffer[256] = { 0 };
    std::map<long, long>& trafficPerSencond = adapterFlowTrendMonitorMap[adapterName].flowTrendDtata;
    //Tshark命令, -i 选项指定网卡，-T fields -e表示输出指定的字段
    std::string tsharkCmd = tsharkPath + " -i \"" + adapterName + "\" -T fields -e frame.time_epoch -e frame.len";
    LOG_F(INFO, "启动网卡流量监视:%s", tsharkCmd.c_str());
    PID_T tsharkPid = 0;
    FILE* pipe = ProcessUtil::PopenEx(tsharkCmd.c_str(), &tsharkPid);
    if (!pipe) {
        throw std::runtime_error("无法运行 tshark 命令: " + tsharkCmd);
    }
    //将管道保存起来
    adapterFlowTrendMapLock.lock();
    adapterFlowTrendMonitorMap[adapterName].monitorTsharkPipe = pipe;
	adapterFlowTrendMonitorMap[adapterName].tsharkPid = tsharkPid;
	adapterFlowTrendMapLock.unlock();
	//逐行读取tshark的输出
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::string line(buffer);
        std::istringstream iss(line);
        std::string timestampStr, lengthStr;
        if (line.find("Capturing on") != std::string::npos) {
            continue; // 跳过捕获信息
        }
		//解析每行时间戳和长度
        if (!(iss >> timestampStr >> lengthStr)) {
			continue; // 如果解析失败，跳过这一行
        }
        try {
			//转换时间戳为long类型，秒数部分
            long timestamp = static_cast<long>(std::stod(timestampStr));
			//转换数据包长度为long类型
			long packetLength = std::stol(lengthStr);
            //每秒的字节数累加
			trafficPerSencond[timestamp] += packetLength;
			//如果trafficPerSencond的大小超过300秒，则删除最早的数据,始终只储存最近300秒的数据
            while (trafficPerSencond.size() > 300) {
				//访问并删除最早的时间戳数据
                auto it = trafficPerSencond.begin();
				LOG_F(INFO, "删除最早的流量数据,时间戳:%ld,字节数:%ld", it->first, it->second);
				trafficPerSencond.erase(it);
            }
        }
        catch (const std::exception&e) {
			//处理转换错误
            LOG_F(ERROR, "Error parsing tshark output:%s", line.c_str());
        }
    }
	LOG_F(INFO, "adapterFlowTrendMonitorTreadEntry 已结束");
}
//开始监视所有网卡流量统计数据
void TsharkManager::startMonitorAdaptersFlowTrend() {
    std::unique_lock < std::recursive_mutex >lock(adapterFlowTrendMapLock);
    adapterFlowTrendMonitorStartTime = time(nullptr);
    //第一步：获取网卡列表
    std::vector<AdapterInfo> adapterList = getNetworkAdapters();
    //第二步：每个网卡启动一个线程，统计对应网卡的数据
    for (auto adapter : adapterList) {
        adapterFlowTrendMonitorMap.insert(std::make_pair<>(adapter.name, AdapterMonitorInfo()));
        AdapterMonitorInfo& monitorInfo = adapterFlowTrendMonitorMap.at(adapter.name);
        monitorInfo.monitorThread = std::make_shared<std::thread>(&TsharkManager::adapterFlowTrendMonitorThreadEntry, this, adapter.name);
        if (monitorInfo.monitorThread == nullptr) {
            LOG_F(ERROR, "监视进程创建失败,网卡名:%s", adapter.name.c_str());
        }
        else {
            LOG_F(INFO, "监视进程创建成功,网卡名:%s", adapter.name.c_str());
        }
    }
}
//停止监视所有网卡流量统计数据
void TsharkManager::stopMonitorAdaptersFlowTrend() {
    std::unique_lock<std::recursive_mutex>lock(adapterFlowTrendMapLock);
	//先杀死对应的tshark进程
    for (auto adapterPipePair : adapterFlowTrendMonitorMap) {
        ProcessUtil::Kill(adapterPipePair.second.tsharkPid);
    }
    //然后关闭管道
    for(auto adapterPipePair : adapterFlowTrendMonitorMap) {
		//关闭管道
        pclose(adapterPipePair.second.monitorTsharkPipe);
		//最后等待线程退出
		adapterPipePair.second.monitorThread->join();
		LOG_F(INFO, "网卡流量监视线程已结束,网卡名:%s", adapterPipePair.first.c_str());
		//清除流量统计数据
		adapterFlowTrendMonitorMap.clear();
	}
}
//获取所有网卡的流量统计数据
void TsharkManager::getAdaptersFlowTrendData(std::map<std::string, std::map<long, long>>& flowTrendData) {
    long timeNow = time(nullptr);
    //数据从最左边冒出来
	//一开始:以最开始监控时间为左起点，终点为未来300秒
    //随着时间的推移,数据逐渐填充完这300秒
    //超过300秒之后，结束节点就是当前，开始节点就是当前-300秒
    long startWindow = timeNow - adapterFlowTrendMonitorStartTime > 300 ? timeNow - 300 : adapterFlowTrendMonitorStartTime;
    long endWindow = timeNow - adapterFlowTrendMonitorStartTime > 300 ? timeNow : adapterFlowTrendMonitorStartTime + 300;
	adapterFlowTrendMapLock.lock();
    for (auto adapterPipePair : adapterFlowTrendMonitorMap) {
        flowTrendData.insert(std::make_pair<>(adapterPipePair.first, std::map<long, long>()));
		//从当前时间点开始，向前推300秒
        for (long t = startWindow; t <= endWindow; t++) {
			//如果trafficPerSencond中有这个时间戳，则添加到结果中,否则填充为0
            if (adapterPipePair.second.flowTrendDtata.find(t) != adapterPipePair.second.flowTrendDtata.end()) {
                flowTrendData[adapterPipePair.first][t] = adapterPipePair.second.flowTrendDtata.at(t);
            }
            else {
				flowTrendData[adapterPipePair.first][t] = 0; // 如果没有数据，则填充为0
            }
        }
    }
	adapterFlowTrendMapLock.unlock();
}