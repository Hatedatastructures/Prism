/**
 * @file Types.hpp
 * @brief DNS 编排层共享结果与配置类型
 * @details QueryResult 表示单次上游查询的摘要；UpstreamOptions 只描述
 *          上游列表和调度参数。传输、缓存和 single-flight 状态分别由
 *          其他 DNS 子模块拥有。
 */

#pragma once

#include "Answer.hpp"
#include "Config.hpp"
#include <Preview/Foundation/Fault/Failure.hpp>

#include <boost/asio.hpp>

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace Preview::Network::Dns
{

    namespace Net = boost::asio;

    /**
     * @struct QueryResult
     * @brief 单次上游查询结果
     * @note Response 同时是唯一地址事实与热路径扫描摘要；ServerAddr 和
     *       Error 保留给 Resolver 的聚合与错误策略使用。
     */
    struct QueryResult
    {
        AnswerSet Response;              ///< 唯一地址事实与响应摘要
        std::uint64_t RttMs{0};          ///< 往返耗时（毫秒）
        std::string ServerAddr;          ///< 响应来源上游地址
        Preview::Fault::Failure Error; ///< 失败分类及原生 cause；成功为默认值
    };

    /**
     * @struct UpstreamOptions
     * @brief 上游查询客户端配置
     * @details 将服务器列表、调度策略、超时和连接池容量收敛为一个
     *          配置对象；字段不拥有执行器或连接资源。
     */
    struct UpstreamOptions
    {
        std::vector<Server> Servers; ///< 上游服务器列表
        Mode QueryMode{Mode::Fastest}; ///< 多上游查询策略
        std::chrono::milliseconds DefaultTimeout{4000}; ///< 默认查询超时
        std::size_t MaxConnsPerServer{4}; ///< 每服务器最大闲置连接数
        std::size_t MaxIdleConnsPerPool{64}; ///< 每个协议连接池的闲置连接总数上限
    };

} // namespace Preview::Network::Dns
