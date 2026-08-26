/**
 * @file Recognition.hpp
 * @brief 协议识别流水线
 * @details 首包探测 → 协议类型判定 →（预读回注）。
 *          输出 detected（协议类型）+ preread（预读数据回注）。
 *          与 Middleware Context.detected 衔接。
 * @note 本测试库识别仅做首包魔数探测；TLS ClientHello 特征识别与
 *      SNI 路由（routes 参数）属生产 handshake/recognition 层能力，
 *      此处为接口契约保留（SniRouteTable 独立可用，见 route.hpp），
 *      查表逻辑未接通——探测层不解析 ClientHello 故无法取 SNI。
 */

#pragma once

#include <string_view>
#include <vector>

#include <common/Core/Memory/Container.hpp>
#include <common/Core/Recognition/Probe.hpp>
#include <common/Core/Recognition/Protocol.hpp>
#include <common/Core/Recognition/Route.hpp>
#include <common/Core/Transmission.hpp>

namespace Preview::Recognition
{

    namespace net = boost::asio;

    /**
     * @struct RecognizeResult
     * @brief 识别结果
     */
    struct RecognizeResult
    {
        ProtocolType detected{ProtocolType::Unknown}; ///< 检测到的协议
        SharedTransmission transport;                  ///< 回注预读后的传输
        std::vector<std::byte> preread;              ///< 预读数据（供 handler 消费）
        std::string scheme;                          ///< 命中的伪装方案（TLS 时；当前恒空）
        bool success{false};                            ///< 识别成功
    };

    /**
     * @class Pipeline
     * @brief 识别流水线（Probe → 类型 → 预读回注）
     * @details routes 为 TLS 分流预留接口契约（Runtime::Session 经
     *          SessionOptions.routes 注入）；当前探测层不解析
     *          ClientHello，查表未接通，scheme 恒空。
     */
    class Pipeline
    {
    public:
        /**
         * @brief 构造
         * @param routes SNI 路由表（可选；预留接口契约，当前未接通）
         */
        explicit Pipeline(SniRouteTable *routes = nullptr) : Routes_(routes)
        {
        }

        /**
         * @brief 执行识别
         * @param transport 入站传输（预读被消费，结果含回注）
         * @return 识别结果
         */
        [[nodiscard]] auto Recognize(SharedTransmission transport) -> net::awaitable<RecognizeResult>
        {
            RecognizeResult Result;
            if (!transport)
            {
                co_return Result;
            }

            auto ProbeRes = co_await Probe(*transport);
            // 预读数据保留（unknown 也回注，保持数据完整）
            Result.preread.assign(ProbeBytes(ProbeRes).begin(), ProbeBytes(ProbeRes).end());
            Result.transport = WrapPreread(std::move(transport), Result.preread);
            if (!ProbeRes.success)
            {
                // 未识别：透传原始传输（预读已回注）
                Result.success = false;
                co_return Result;
            }

            Result.detected = ProbeRes.Type;
            Result.success = true;
            co_return Result;
        }

    private:
        /**
         * @brief 探测结果的预读字节
         * @param res 探测结果
         * @return 预读字节 span
         */
        [[nodiscard]] static auto ProbeBytes(const ProbeResult &res) -> std::span<const std::byte>
        {
            return std::span<const std::byte>(res.PreRead.data(), res.PreReadSize);
        }

        /// SNI 路由表（预留，见类注释）
        SniRouteTable *Routes_;
    };

} // namespace Preview::Recognition
