/**
 * @file Tls.hpp
 * @brief TLS ClientHello 记录解析
 * @details 提取 SNI、supported_versions、session_id、key_share 和原始字节。
 *          解析器无状态，不执行 TLS 握手，也不修改底层传输。
 */

#pragma once

#include <array>
#include <boost/asio/awaitable.hpp>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Runtime/Recognition/ProbeBuffer.hpp>
#include <Prism/Runtime/Recognition/TlsRecordReader.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Recognition
{

    namespace Net = boost::asio;

    /// ClientHello 解析结果
    struct ClientHelloFeatures
    {
        std::string ServerName;
        std::vector<std::uint8_t> SessionId;
        std::vector<std::uint16_t> Versions;
        std::vector<std::uint16_t> KeyShareGroups;
        std::uint16_t LegacyVersion{0};
        std::array<std::uint8_t, 32> Random{};
        std::array<std::uint8_t, 32> X25519Key{};
        std::vector<std::uint8_t> RawMessage;
        std::vector<std::uint8_t> RawRecord;
        std::vector<std::string> AlpnProtocols;
        std::size_t ConsumedBytes{0};
        /// 是否存在可提取且可用的 32 字节 X25519 组件（独立组或混合组尾部）。
        bool HasX25519{false};
        /// 是否出现 X25519MLKEM768 命名组；仅表示组存在，不保证有可用 X25519 组件。
        bool HasX25519MLKEM768{false};
        bool HasAlpn{false};
        bool HasPsk{false};
        bool HasEch{false};
    };

    namespace detail
    {

        [[nodiscard]] auto ReadU16(std::span<const std::uint8_t> Data, std::size_t Offset,
                                   std::uint16_t &Value) noexcept -> bool;

        [[nodiscard]] auto ReadU24(std::span<const std::uint8_t> Data, std::size_t Offset,
                                   std::size_t &Value) noexcept -> bool;

        [[nodiscard]] auto ParseServerName(std::span<const std::uint8_t> Data,
                                                   std::string &ServerName) -> bool;

        [[nodiscard]] auto ParseAlpn(std::span<const std::uint8_t> Data,
                                             std::vector<std::string> &Protocols) -> bool;

        [[nodiscard]] auto ParseVersions(std::span<const std::uint8_t> Data,
                                                 std::vector<std::uint16_t> &Versions) -> bool;

        [[nodiscard]] auto ParseKeyShare(std::span<const std::uint8_t> Data,
                                                ClientHelloFeatures &Features) -> bool;

        struct ClientHelloScan
        {
            Error Status{Error::NeedMore};
            std::size_t Required{TlsRecordHeaderSize};
            std::size_t RecordEnd{0};
            std::size_t MessageSize{0};
            std::vector<std::uint8_t> Handshake;
        };

        [[nodiscard]] auto ScanClientHello(std::span<const std::uint8_t> Data) -> ClientHelloScan;

        [[nodiscard]] auto MapProbeFill(const ProbeFillResult &Fill) noexcept -> Error;

    } // namespace detail

    namespace detail
    {

        [[nodiscard]] auto ParseExtensions(std::span<const std::uint8_t> Message,
                                           std::size_t &Offset,
                                           ClientHelloFeatures &Features) -> bool;

        [[nodiscard]] auto ParseClientHelloMessage(std::span<const std::uint8_t> Message,
                                                   ClientHelloFeatures &Features) -> Error;

    } // namespace detail

    /**
     * @brief 解析包含一个或多个 TLS record 的 ClientHello
     * @param RecordSequence TLS record 序列
     * @return 错误码与解析结果
     */
    [[nodiscard]] auto ParseClientHelloProgress(std::span<const std::uint8_t> RecordSequence)
        -> std::pair<Error, ClientHelloFeatures>;

    /**
     * @brief 解析 ClientHello，并保持旧 API 对截断输入的错误映射
     * @param RecordSequence TLS record 序列
     * @return 错误码与解析结果
     */
    [[nodiscard]] auto ParseClientHello(std::span<const std::uint8_t> RecordSequence)
        -> std::pair<Error, ClientHelloFeatures>;

    /**
     * @brief 通过 ProbeBuffer 增量读取并解析 ClientHello
     * @param Transport 入站传输
     * @param Buffer 连接级预读缓冲
     * @return 错误码与解析结果
     * @details 每次只补齐下一条 record 边界；首个 ClientHello 完成后不再读取，
     *          因而同一 record 或 transport 中的后续数据仍可由调用方继续消费。
     */
    [[nodiscard]] auto ReadClientHello(Prism::Transmission &Transport, ProbeBuffer &Buffer)
        -> Net::awaitable<std::pair<Error, ClientHelloFeatures>>;

    /**
     * @brief 以缓冲优先参数顺序读取 ClientHello
     * @param Buffer 连接级预读缓冲
     * @param Transport 入站传输
     * @return 错误码与解析结果
     */
    [[nodiscard]] auto ReadClientHello(ProbeBuffer &Buffer, Prism::Transmission &Transport)
        -> Net::awaitable<std::pair<Error, ClientHelloFeatures>>;

} // namespace Prism::Recognition
