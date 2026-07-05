/**
 * @file recognition.hpp
 * @brief Recognition 模块聚合头文件
 * @details 引入识别模块所有子模块头文件，提供统一的模块入口和完整的协议识别生命周期。
 * 新增 recognize() 统一入口，封装外层探测 + TLS 伪装方案识别。
 */

#pragma once

#include <prism/foundation/fault/code.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/foundation/memory/pool.hpp>
#include <prism/proto/protocol/common/target.hpp>
#include <prism/proto/protocol/types.hpp>
#include <prism/stealth/recognition/confidence.hpp>
#include <prism/stealth/recognition/pipeline.hpp>
#include <prism/stealth/recognition/probe/analyzer.hpp>
#include <prism/stealth/recognition/probe/probe.hpp>
#include <prism/stealth/recognition/result.hpp>
#include <prism/stealth/recognition/routes.hpp>
#include <prism/stealth/scheme.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>

#include <span>


// 前置声明
namespace psm
{

    struct config;
}

namespace psm::connect
{

    class router;
}

namespace psm::context
{

    struct session;
}

namespace psm::recognition
{

    namespace net = boost::asio;

    // 统一入口：recognize()（完整识别流程）

    /**
     * @struct recognize_result
     * @brief 完整识别流程输出结果
     * @details 包含识别完成后的所有输出，统一入口使用。
     */
    struct recognize_result
    {
        /** @brief 最终传输层（可能被加密或包装） */
        transport::shared_transmission transport;

        /** @brief 检测到的协议类型 */
        protocol::protocol_type detected{protocol::protocol_type::unknown};

        /** @brief 预读数据 */
        memory::vector<std::byte> preread;

        /** @brief 执行错误码 */
        fault::code error{fault::code::success};

        /** @brief 成功执行的方案名称（仅 TLS） */
        memory::string executed_scheme;

        /** @brief 是否成功识别 */
        bool success{false};
    };

    /**
     * @brief 执行完整协议识别流程
     * @param opts Stealth 层统一传参（含 transport / meta / trace / cfg / rt / session_keepalive / frame_arena）
     * @return 识别结果
     * @details 封装外层探测 + TLS 伪装方案识别的完整流程：
     *
     * Phase 1: Probe（外层探测）
     * 预读 24 字节
     * 检测 HTTP/SOCKS5/TLS/Shadowsocks
     *
     * Phase 2: Identify（仅当 TLS）
     * 读取完整 ClientHello
     * 特征分析
     * 方案执行
     */
    [[nodiscard]] auto recognize(stealth::stealth_opts &opts)
        -> net::awaitable<recognize_result>;

    // 伪装方案识别：identify()（仅 TLS）

    /**
     * @struct identify_result
     * @brief 协议识别结果
     * @details 包含识别完成后的所有输出：传输层、协议类型、预读数据。
     */
    struct identify_result
    {
        /** @brief 最终传输层（可能被加密或包装） */
        transport::shared_transmission transport;

        /** @brief 检测到的协议类型 */
        protocol::protocol_type detected{protocol::protocol_type::unknown};

        /** @brief 内层预读数据 */
        memory::vector<std::byte> preread;

        /** @brief 执行错误码 */
        fault::code error{fault::code::success};

        /** @brief 成功执行的方案名称 */
        memory::string executed_scheme;

        /** @brief 是否成功识别并建立传输层 */
        bool success{false};
    };

    /**
     * @brief 执行完整的协议识别生命周期
     * @param opts Stealth 层统一传参引用（内部修改 transport / preread 字段）
     * @return 识别结果
     * @details 封装完整的识别流程：
     *
     * Phase 1: Read（读取）
     * 从传输层读取完整 TLS ClientHello
     * 处理已预读的 24 字节
     *
     * Phase 2: Parse（解析）
     * 解析 ClientHello 结构
     * 提取 SNI、session_id、key_share 等特征
     *
     * Phase 3: Detect（检测）
     * 遍历所有 scheme 的 detect()
     * 收集候选方案列表
     *
     * Phase 4: Execute（执行）
     * 按候选顺序执行 scheme
     * 成功则返回结果
     * 失败则继续下一个或 fallback
     */
    [[nodiscard]] auto identify(stealth::stealth_opts &opts)
        -> net::awaitable<identify_result>;

} // namespace psm::recognition
