# 补丁脚本：限制 Boost.Asio resolver 地址拷贝到协议对应的 sockaddr 大小。
# 用法：cmake -P PatchBoostResolver.cmake <boost-source-dir>

if(NOT DEFINED CMAKE_ARGC OR CMAKE_ARGC LESS 4)
    message(FATAL_ERROR "usage: cmake -P PatchBoostResolver.cmake <source-dir>")
endif()

set(src_dir "${CMAKE_ARGV3}")
set(resolver_file "${src_dir}/boost/asio/ip/basic_resolver_results.hpp")
if(NOT EXISTS "${resolver_file}")
    message(FATAL_ERROR "Boost.Asio resolver source was not found: ${resolver_file}")
endif()

file(READ "${resolver_file}" content)
string(REPLACE "\r\n" "\n" content "${content}")

set(original [=[        using namespace std; // For memcpy.
        typename InternetProtocol::endpoint endpoint;
        endpoint.resize(static_cast<std::size_t>(address_info->ai_addrlen));
        memcpy(endpoint.data(), address_info->ai_addr,
            address_info->ai_addrlen);
        results.values_->push_back(
            basic_resolver_entry<InternetProtocol>(endpoint,
              actual_host_name, service_name));]=])

set(replacement [=[        const std::size_t expected_size =
            address_info->ai_family == BOOST_ASIO_OS_DEF(AF_INET)
            ? sizeof(boost::asio::detail::sockaddr_in4_type)
            : sizeof(boost::asio::detail::sockaddr_in6_type);
        if (static_cast<std::size_t>(address_info->ai_addrlen) >= expected_size)
        {
            using namespace std; // For memcpy.
            typename InternetProtocol::endpoint endpoint;
            endpoint.resize(expected_size);
            memcpy(endpoint.data(), address_info->ai_addr, expected_size);
            results.values_->push_back(
                basic_resolver_entry<InternetProtocol>(endpoint,
                  actual_host_name, service_name));
        }]=])

string(FIND "${content}" "${original}" original_offset)
if(original_offset EQUAL -1)
    string(FIND "${content}" "const std::size_t expected_size =" patched_offset)
    if(patched_offset EQUAL -1)
        message(FATAL_ERROR "Boost.Asio resolver source does not match the expected version")
    endif()
    message(STATUS "Boost.Asio resolver address copy is already bounded")
else()
    string(REPLACE "${original}" "${replacement}" content "${content}")
    file(WRITE "${resolver_file}" "${content}")
    message(STATUS "Boost.Asio resolver address copy is bounded by address family")
endif()
