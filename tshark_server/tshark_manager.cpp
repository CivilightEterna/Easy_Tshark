
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
    std::set<std::string>specialInterfaces = { "sshdump","ciscodump","udpdump","randpkt" };
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
		int startPos = line.find(' ');
        if (startPos != std::string::npos) {
            int endPos = line.find(' ', startPos + 1);
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

    while (std::getline(ss, field, '\t')) {  // 假设字段用 tab 分隔
        fields.push_back(field);
    }

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