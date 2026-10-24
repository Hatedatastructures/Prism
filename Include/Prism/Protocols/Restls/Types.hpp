/**
 * @file Types.hpp
 * @brief Restls 协议基础类型
 * @details Restls 是 TLS 探测抵抗伪装方案（对齐 restls-Client-go）：
 *          - 服务端使用 BLAKE3 keyed 派生 ServerMask，保护首个 TLS 记录；
 *          - 每条应用数据记录包含 8 字节 auth_mac 和 4 字节 XOR mask；
 *          - 方向标签固定为 Server-to-Client 或 Client-to-Server。
 *          本测试库实现纯逻辑认证编解码，不包含真实 TLS 传输。
 * @note 参考 restls-Client-go 协议规范。
 */

#pragma once

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <array>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <boost/asio/awaitable.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <system_error>
#include <string_view>
#include <vector>

namespace Prism::Restls
{
    namespace Net = boost::asio;
    /**
     * @brief Restls 单一失败事实：协议分类与原生 I/O cause。
     * @details 协议解析失败只设置 Code；传输与结构失败保留 Native 的 category/value，
     *          Bytes 记录失败前真实完成的 wire 进度。调用方按值接收，不借用连接或 executor；
     *          取消与最终关闭由传输 owner 承担。
     */
    struct Failure final
    {
        Prism::Error Code{Prism::Error::None}; ///< Restls 协议或传输分类。
        std::error_code Native{}; ///< 真实底层 I/O cause；无原生 cause 时为空。
        std::size_t Bytes{0}; ///< 失败前已由底层传输完成的 wire 字节数。

        /** @brief 检查协议与原生 cause 均为空。 */
        [[nodiscard]] auto Succeeded() const noexcept -> bool;

        /** @brief 检查失败分类或原生 cause 是否存在。 */
        [[nodiscard]] auto Failed() const noexcept -> bool;
    };

    template <class Value>
    using Result = std::expected<Value, Failure>;

    /** @brief 将 Restls 失败映射到唯一 data-plane Failure 并保留原生 cause。 */
    [[nodiscard]] auto ToFaultFailure(const Failure &Value) noexcept
        -> Prism::Fault::Failure;

    /** @brief 构造只含协议分类的失败值；不制造伪造的原生 cause。 */
    [[nodiscard]] auto ProtocolFailure(Prism::Error Code) noexcept -> Failure;

    /** @brief 保留最早失败；只有主操作成功时才采用关闭或 Drain 的失败。 */
    [[nodiscard]] auto PreserveFirstFailure(Failure Primary, Failure Cleanup) noexcept
        -> Failure;

    /// 握手阶段 MAC 长度（ServerMask，保持现有导出名称兼容）
    inline constexpr std::size_t HsMaclen = 16;

    /// 应用数据 MAC 长度（auth_mac，保持现有导出名称兼容）
    inline constexpr std::size_t AppdataMaclen = 8;

    /// XOR 掩码长度（保持现有导出名称兼容）
    inline constexpr std::size_t MaskLen = 4;

    /// 认证头总长度，等于 auth_mac 加 XOR mask
    inline constexpr std::size_t AuthHdrlen = AppdataMaclen + MaskLen;

    /// TLS 记录头长度
    inline constexpr std::size_t TlsHdrlen = 5;

    /// TLS ApplicationData 记录类型
    inline constexpr std::uint8_t TlsApplicationData = 0x17;

    /// 单个 Restls 记录的明文上限（不含认证头）
    inline constexpr std::size_t MaxDataLength = 16 * 1024;

    /// 单个 Restls TLS 记录的最大负载长度
    inline constexpr std::size_t MaxRecordPayload = AuthHdrlen + MaxDataLength;

    /// ActNoop 命令
    inline constexpr std::uint8_t CmdTypeNoop = 0x00;

    /// ActResponse 命令
    inline constexpr std::uint8_t CmdTypeResponse = 0x01;

    /// Restls response command 的控制 payload（不属于代理数据面）。
    inline constexpr std::string_view RandomResponseMagic = "restls-random-response";

    /// 服务端到客户端的方向标签（对齐 mihomo restls wire）
    inline constexpr std::string_view DirToclient = "server-to-client";
    /// 客户端到服务端的方向标签（对齐 mihomo restls wire）
    inline constexpr std::string_view DirToserver = "client-to-server";

    /// BLAKE3 DeriveKey 使用的固定上下文
    inline constexpr std::string_view SecretCtx = "restls-traffic-key";

    /// 数据流方向；枚举值参与认证输入，数值保持现有 wire 语义
    enum class FlowDirection : std::uint8_t
    {
        /// 服务端 → 客户端
        ToClient,
        /// 客户端 → 服务端
        ToServer,
    };

    /**
     * @struct Handover
     * @brief Restls 握手完成后交给数据传输层的所有 wire 状态
     * @details 对齐生产握手输出：首个服务端加密记录需要先应用 ServerMask，
     * 首个客户端 ApplicationData 的 auth_mac 需要包含 ClientFinished。
     */
    struct Handover final
    {
        std::array<std::uint8_t, 32> ServerRandom{}; ///< TLS ServerHello random
        std::vector<std::uint8_t> ClientFinished;     ///< 首个客户端加密记录
        std::vector<std::uint8_t> FirstEncrypted;     ///< 首个服务端加密记录
    };

    /** @brief Restls 服务端握手配置，由冷路径按值拥有。 */
    struct ServerConfig final
    {
        std::string password;
        bool Tls13{false};
    };

    /** @brief Restls 拨号能力由单个服务端会话按值拥有。 */
    using DialTargetFn = std::function<Net::awaitable<std::expected<SharedTransmission,
        Prism::Fault::Failure>>(std::span<const std::uint8_t>)>;

    /** @brief 供 Restls 服务端会话持有的类型化回调。 */
    struct ServerOptions final
    {
        DialTargetFn DialTarget;
    };

    /** @brief Restls 对外字节流句柄；协议状态由 Detail 私有 owner 持有。 */
    using SharedConn = std::shared_ptr<Prism::Transmission>;
} // namespace Prism::Restls
