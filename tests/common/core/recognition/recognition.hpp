/**
 * @file recognition.hpp
 * @brief 协议识别流水线
 * @details 首包探测 → 协议类型判定 →（预读回注）。
 *          输出 detected（协议类型）+ preread（预读数据回注）。
 *          与 middleware context.detected 衔接。
 * @note 本测试库识别仅做首包魔数探测；TLS ClientHello 特征识别与
 *      SNI 路由（routes 参数）属生产 handshake/recognition 层能力，
 *      此处为接口契约保留（sni_route_table 独立可用，见 route.hpp），
 *      查表逻辑未接通——探测层不解析 ClientHello 故无法取 SNI。
 */

#pragma once

#include <string_view>
#include <vector>

#include <common/core/memory/container.hpp>
#include <common/core/recognition/probe.hpp>
#include <common/core/recognition/protocol.hpp>
#include <common/core/recognition/route.hpp>
#include <common/core/transmission.hpp>

namespace preview::recognition
{

    namespace net = boost::asio;

    /**
     * @struct recognize_result
     * @brief 识别结果
     */
    struct recognize_result
    {
        protocol_type detected{protocol_type::unknown}; ///< 检测到的协议
        shared_transmission transport;                  ///< 回注预读后的传输
        memory::vector<std::byte> preread;              ///< 预读数据（供 handler 消费）
        memory::string scheme;                          ///< 命中的伪装方案（TLS 时；当前恒空）
        bool success{false};                            ///< 识别成功
    };

    /**
     * @class pipeline
     * @brief 识别流水线（probe → 类型 → 预读回注）
     * @details routes 为 TLS 分流预留接口契约（runtime::session 经
     *          session_options.routes 注入）；当前探测层不解析
     *          ClientHello，查表未接通，scheme 恒空。
     */
    class pipeline
    {
    public:
        /**
         * @brief 构造
         * @param routes SNI 路由表（可选；预留接口契约，当前未接通）
         */
        explicit pipeline(sni_route_table *routes = nullptr) : routes_(routes)
        {
        }

        /**
         * @brief 执行识别
         * @param transport 入站传输（预读被消费，结果含回注）
         * @return 识别结果
         */
        [[nodiscard]] auto recognize(shared_transmission transport) -> net::awaitable<recognize_result>
        {
            recognize_result result;
            if (!transport)
            {
                co_return result;
            }

            auto probe_res = co_await probe(*transport);
            // 预读数据保留（unknown 也回注，保持数据完整）
            result.preread.assign(probe_bytes(probe_res).begin(), probe_bytes(probe_res).end());
            result.transport = wrap_preread(std::move(transport), result.preread);
            if (!probe_res.success)
            {
                // 未识别：透传原始传输（预读已回注）
                result.success = false;
                co_return result;
            }

            result.detected = probe_res.type;
            result.success = true;
            co_return result;
        }

    private:
        /**
         * @brief 探测结果的预读字节
         * @param res 探测结果
         * @return 预读字节 span
         */
        [[nodiscard]] static auto probe_bytes(const probe_result &res) -> std::span<const std::byte>
        {
            return std::span<const std::byte>(res.pre_read.data(), res.pre_read_size);
        }

        /// SNI 路由表（预留，见类注释）
        sni_route_table *routes_;
    };

} // namespace preview::recognition
