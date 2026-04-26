/**
 * @file recognition.hpp
 * @brief Recognition 模块聚合头文件
 * @details 引入识别模块所有子模块头文件，提供统一的模块入口和完整的协议识别生命周期。
 */

#pragma once

#include <span>
#include <boost/asio.hpp>
#include <prism/recognition/confidence.hpp>
#include <prism/recognition/feature.hpp>
#include <prism/recognition/result.hpp>
#include <prism/channel/transport/transmission.hpp>
#include <prism/memory/pool.hpp>
#include <prism/protocol/analysis.hpp>
#include <prism/fault/code.hpp>

// ClientHello 特征检测子模块
#include <prism/recognition/clienthello/analyzer.hpp>
#include <prism/recognition/clienthello/registry.hpp>
#include <prism/recognition/clienthello/reality.hpp>

// 握手后方案执行子模块
#include <prism/recognition/handshake/priority.hpp>
#include <prism/recognition/handshake/executor.hpp>

// 预留扩展（ECH, AnyTLS）
// #include <prism/recognition/clienthello/ech.hpp>
// #include <prism/recognition/clienthello/anytls.hpp>

namespace psm::recognition
{
    namespace net = boost::asio;

    /**
     * @struct identify_context
     * @brief 协议识别上下文（输入参数）
     * @details 包含识别所需的所有输入：传输层、配置、预读数据。
     */
    struct identify_context
    {
        /** @brief 传输层（socket 或已包装的传输） */
        channel::transport::shared_transmission transport;

        /** @brief 全局配置 */
        const psm::config *cfg{nullptr};

        /** @brief 已预读数据（来自 protocol::probe） */
        std::span<const std::byte> preread;

        /** @brief 路由器（fallback 用） */
        resolve::router *router{nullptr};

        /** @brief 会话上下文（可选，供方案使用） */
        agent::session_context *session{nullptr};

        /** @brief 帧内存池（用于预读数据分配） */
        memory::frame_arena *frame_arena{nullptr};
    };

    /**
     * @struct identify_result
     * @brief 协议识别结果
     * @details 包含识别完成后的所有输出：传输层、协议类型、预读数据。
     */
    struct identify_result
    {
        /** @brief 最终传输层（可能被加密或包装） */
        channel::transport::shared_transmission transport;

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
     * @param ctx 识别上下文
     * @return 识别结果
     * @details 封装完整的识别流程：
     *
     * **Phase 1: Read（读取）**
     * - 从传输层读取完整 TLS ClientHello
     * - 处理已预读的 24 字节
     *
     * **Phase 2: Parse（解析）**
     * - 解析 ClientHello 结构
     * - 提取 SNI、session_id、key_share 等特征
     *
     * **Phase 3: Analyze（分析）**
     * - 遍历所有 feature_analyzer
     * - 判断各方案置信度
     * - 生成候选方案列表
     *
     * **Phase 4: Dispatch（分流）**
     * - 按候选顺序执行方案
     * - 成功则返回结果
     * - 失败则继续下一个或 fallback
     *
     * **Phase 5: Execute（执行）**
     * - 调用 stealth::scheme::execute()
     * - 完成具体握手（Reality/ShadowTLS/RestLS/Native）
     *
     * **使用示例**：
     * ```cpp
     * auto result = co_await recognition::identify({
     *     .transport = *ctx_.inbound,
     *     .cfg = &ctx_.server.config(),
     *     .preread = detect_result.pre_read_data,
     *     .session = &ctx_
     * });
     *
     * if (result.success) {
     *     ctx_.inbound = result.transport;
     *     detect_result.type = result.detected;
     * }
     * ```
     */
    auto identify(identify_context ctx) -> net::awaitable<identify_result>;

    /**
     * @brief 解析 TLS ClientHello 并提取特征
     * @param raw_clienthello 完整的 TLS ClientHello 记录（含 5 字节 header）
     * @return 提取的特征结构
     * @details 复用 stealth/reality/request.cpp 的解析逻辑。
     */
    [[nodiscard]] auto parse_clienthello(std::span<const std::uint8_t> raw_clienthello)
        -> clienthello_features;

    /**
     * @brief 读取完整 TLS ClientHello 记录
     * @param transport 传输层
     * @param preread 已预读数据（来自 protocol::probe）
     * @return {错误码, ClientHello 数据}
     * @details 复用 stealth/reality/request.cpp 的读取逻辑。
     */
    auto read_clienthello(channel::transport::shared_transmission transport, std::span<const std::byte> preread)
        -> net::awaitable<std::pair<fault::code, memory::vector<std::uint8_t>>>;

} // namespace psm::recognition