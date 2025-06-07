#include <iostream>
#include "tshark_manager.h"
#include "third_library/loguru/loguru.hpp"
static void ReadPkgGetXML2JSON(TsharkManager &tsharkManager) {
	std::string jsonString;
	std::string pcapFilePath;
	int frameTotalNumber;
	int frameNumber = 0;
	std::cout << "请输入pcap文件路径: " << std::endl;
	std::cin >> pcapFilePath;
	tsharkManager.analysisFile(pcapFilePath);
	frameTotalNumber = tsharkManager.getPacketsNum();
	std::cout << "请输入要获取数据包的序号(1-" << frameTotalNumber << "): " << std::endl;
	std::cin >> frameNumber;
	if(frameNumber < 1 || frameNumber > frameTotalNumber) {
		LOG_F(ERROR, "输入的包序号不合法，请输入1-%d之间的数字", frameTotalNumber);
		return;
	}
	else {
		tsharkManager.getPacketDetailInfo(frameNumber, jsonString);
		std::string fileName = std::to_string(frameTotalNumber) + ".json";
		std::ofstream outFile(fileName);
		if (outFile.is_open()) {
			outFile << jsonString;
			outFile.close();
			LOG_F(INFO, "数据包详情已保存到文件: %s", fileName.c_str());
		} else {
			LOG_F(ERROR, "无法打开文件 %s 进行写入", fileName.c_str());
		}
	}
}

void InitLog(int argc, char* argv[]) {
    // 初始化 Loguru
    loguru::init(argc, argv);

    // 设置日志文件路径
    loguru::add_file("app.log", loguru::Append, loguru::Verbosity_MAX);
}


int main(int argc, char* argv[]) {

    // 设置控制台环境编码为UTF-8格式，防止打印输出的内容乱码
    setlocale(LC_ALL, "zh_CN.UTF-8");
	
    InitLog(argc, argv);
	
    TsharkManager tsharkManager("E:/Easy_tshark/tshark_server/tshark_server");
    /*tsharkManager.analysisFile("E:/capture.pcap");*/
 //   std::vector<AdapterInfo>adaptors = tsharkManager.getNetworkAdapters();
 //   for(auto item : adaptors) {
 //       LOG_F(INFO, "网卡[%d]:name[%s] remark[%s]", item.id, item.name.c_str(), item.remark.c_str());
	//}
	//tsharkManager.startCapture("蓝牙网络连接");
 //   //主线程进入命令等待停止抓包
	//std::string input;
 //   while (true) {
 //       std::cout << "输入q停止抓包: ";
 //       std::cin >> input;
 //       if (input == "q") {
 //           tsharkManager.stopCapture();
 //           LOG_F(INFO, "停止抓包成功！");
 //           break;
 //       }
 //   }
 //   tsharkManager.printAllPackets();
    //启动进程
 //   tsharkManager.startMonitorAdaptersFlowTrend();
 //   //睡眠10秒,等待监控网卡数据
 //   std::this_thread::sleep_for(std::chrono::seconds(10));
 //   //读取监控到的数据
 //   std::map<std::string, std::map<long, long>>trendData;
 //   tsharkManager.getAdaptersFlowTrendData(trendData);
 //   //停止监控
 //   tsharkManager.stopMonitorAdaptersFlowTrend();
 //   //把获取到的数据打印输出
 //   rapidjson::Document resDoc;
	//rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
	//resDoc.SetObject();
 //   rapidjson::Value dataObject(rapidjson::kObjectType);
 //   for (const auto& adaptorItem : trendData) {
 //       rapidjson::Value adaptorDataList(rapidjson::kArrayType);
 //       for (const auto& timeItem : adaptorItem.second) {
 //           rapidjson::Value timeObj(rapidjson::kObjectType);
 //           timeObj.AddMember("time",(unsigned int)timeItem.first,allocator);
 //           timeObj.AddMember("bybtes", (unsigned int)timeItem.second, allocator);
	//		adaptorDataList.PushBack(timeObj, allocator);
 //       }
 //       dataObject.AddMember(rapidjson::StringRef(adaptorItem.first.c_str()),adaptorDataList,allocator);
 //   }
	//resDoc.AddMember("data", dataObject, allocator);
	////序列化为JSON字符串
	//rapidjson::StringBuffer buffer;
	//rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	//resDoc.Accept(writer);
	//LOG_F(INFO, "网卡流量趋势数据: %s", buffer.GetString());
	tsharkManager.analysisFile("E:/capture.pcap");
	ReadPkgGetXML2JSON(tsharkManager);
    return 0;
}