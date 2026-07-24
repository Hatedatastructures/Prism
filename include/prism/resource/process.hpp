/**
 * @file process.hpp
 * @brief 进程级资源容器
 * @details 纯数据 struct，无函数。shared_ptr 由 main 持有，
 *          拷贝给所有 worker。持有 config、ssl、accounts。
 */
#pragma once

#include <prism/account/directory.hpp>
#include <prism/config/config.hpp>

#include <boost/asio/ssl.hpp>

#include <memory>


namespace psm::resource
{

/**
 * @struct process
 * @brief 进程级资源（L1）
 */
struct process
{
    /**
     * @brief 构造参数
     */
    struct options
    {
        std::shared_ptr<psm::config>                  cfg;
        std::shared_ptr<boost::asio::ssl::context>    ssl;
        std::shared_ptr<psm::account::directory>      accounts;
    };

    explicit process(options opts);

    process(const process&) = delete;
    auto operator=(const process&) -> process& = delete;

    std::shared_ptr<psm::config>                  cfg;
    std::shared_ptr<boost::asio::ssl::context>    ssl;
    std::shared_ptr<psm::account::directory>      accounts;
};

} // namespace psm::resource
