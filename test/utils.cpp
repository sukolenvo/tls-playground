#include <fstream>

#include "utils.hpp"

std::vector<char> read_file(const std::string &name)
{
    std::ifstream stream(name.data(), std::ios::binary | std::ios::ate);
    if (!stream.is_open())
    {
        throw std::runtime_error("Failed to open " + name);
    }
    const auto pos = stream.tellg();
    std::vector<char> result(pos);
    stream.seekg(0, std::ios::beg);
    if (!stream.read(result.data(), pos))
    {
        throw std::runtime_error("Failed to read " + name);
    }
    return result;
}