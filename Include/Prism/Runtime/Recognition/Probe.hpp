/**
 * @file Probe.hpp
 * @brief 首包探测（预读 + 协议类型检测）
 * @details 从传输层预读最多 24 字节，检测协议类型。
 *          预读数据经 Preview 包装回注（不丢失）。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Runtime/Recognition/Protocol.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace Prism::Recognition
{

    namespace Net = boost::asio;

    /**
     * @struct ProbeResult
     * @brief 探测结果
     */
    struct ProbeResult
    {
        Prism::Contract::ProtocolType Type{Prism::Contract::ProtocolType::Unknown}; ///< 检测到的协议类型
        std::array<std::byte, 24> PreRead{};       ///< 预读数据
        std::size_t PreReadSize{0};               ///< 预读字节数
        bool success{false};                        ///< 检测成功（类型非 unknown）
    };

    /// 最大预读字节数
    inline constexpr std::size_t MaxProbeSize = 24;

    /**
     * @brief 判断当前字节是否仍可能是已知协议的前缀
     * @param Data 当前已预读字节
     * @return true = 继续等待更多字节可能得到确定分类
     * @details 未知首包不能无条件等待到 24 字节，否则协议专用
     *          AcceptProtocol 场景会因普通应用数据而永久阻塞。
     */
    [[nodiscard]] auto CouldBeProtocolPrefix(
        std::span<const std::uint8_t> Data) noexcept -> bool;

    /**
     * @brief 预读并检测协议类型
     * @param transport 底层传输
     * @param MaxSize 最大预读字节数（≤ 24）
     * @return 探测结果
     * @details 预读数据保留在结果中，调用方可用 WrapPreread 回注。
     */
    [[nodiscard]] auto Probe(Transmission &transport, std::size_t MaxSize = MaxProbeSize)
        -> Net::awaitable<ProbeResult>;

    /**
     * @brief 预读数据回注（Preview 包装）
     * @param transport 已消费预读的传输
     * @param preread 预读数据
     * @param bytes 真实有界池；前缀块由此取得并保活至耗尽
     * @return 包装后的传输（回放预读）；空前缀返回原载体，池失败返回空 owner
     */
    [[nodiscard]] auto WrapPreread(SharedTransmission transport, std::span<const std::byte> preread,
        std::shared_ptr<Prism::Memory::BytePool> bytes) -> SharedTransmission;

} // namespace Prism::Recognition
