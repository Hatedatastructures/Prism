/** @file Frame.hpp @brief AnyTLS 独立 SETTINGS/SYN/PSH/FIN wire 与精确读取。 */
#pragma once
#include <boost/asio/awaitable.hpp>

#include <Prism/Transport/Transmission.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <vector>

namespace Prism::Anytls
{
    namespace Net = boost::asio;
    enum class Command : std::uint8_t
    {
        Waste = 0, Syn = 1, Push = 2, Fin = 3, Settings = 4, Alert = 5,
        UpdatePadding = 6, SynAck = 7, HeartRequest = 8, HeartResponse = 9, ServerSettings = 10
    };
    /** @brief 一条完整拥有的协议帧；producer/writer 不借用调用者 payload。 */
    struct Frame final
    {
        Command Kind{Command::Waste};
        std::uint32_t StreamId{0};
        std::vector<std::byte> Payload;
    };
    /**
     * @brief 持有 AnyTLS 连续帧读取状态。
     * @details 完整帧与同次读到的终态分两次交付；短字段立即报告并粘滞终态，
     *          后续读取不再触碰底层传输。持有传入的共享传输 owner；调用方须为同一
     *          字节流复用同一个 Reader，并串行调用。字段边界 EOF 返回
     *          Error::UnexpectedEof；字段截断映射为协议错误异常，其他传输失败保留原生异常。
     *          该对象不改变半关闭或最终关闭所有权。
     */
    class FrameReader final
    {
    public:
        /**
         * @brief 创建读取器并持有传输共享 owner。
         * @param Stream 被读取的共享传输；调用方仍拥有关闭和半关闭职责。
         */
        explicit FrameReader(Prism::SharedTransmission Stream);
        FrameReader(const FrameReader &) = delete;
        auto operator=(const FrameReader &) -> FrameReader & = delete;

        /**
         * @brief 读取下一条完整帧，完整帧后的终态留给下一次调用。
         * @return 完整帧或协议错误；字段边界 EOF 返回 UnexpectedEof，字段截断与其他传输失败抛出 system_error。
         */
        [[nodiscard]] auto Read() -> Net::awaitable<std::expected<Frame, Error>>;

    private:
        [[nodiscard]] auto ReadExact(std::span<std::byte> Bytes)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        Prism::SharedTransmission Stream_;
        std::optional<Prism::Fault::Failure> Terminal_{};
    };

    /** @brief 将拥有型帧编码为 wire；payload 超出长度字段时返回空缓冲。 */
    auto Encode(Frame Value) -> std::vector<std::byte>;
}
