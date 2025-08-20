#include "../include/Logger.hpp"

Logger::Logger(const std::string& filePath) {
    logFile.open(filePath, std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "Failed to open log file: " << filePath << std::endl;
    }
}

Logger::~Logger() {
    if (logFile.is_open()) {
        logFile.close();
    }
}

void Logger::log(const std::string& entry) {
    std::lock_guard<std::mutex> lock(logMutex);
    logFile << entry << std::endl;
}