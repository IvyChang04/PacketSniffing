#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <iostream>
#include <string>
#include <fstream>
#include <ctime>
#include <mutex>

class Logger{
public:
    Logger(const std::string& filePath);
    ~Logger();

    void log(const std::string& entry);

private:
    std::ofstream logFile;
    std::mutex logMutex;
};

#endif