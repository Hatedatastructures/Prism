/**
 * @file Conn.hpp
 * @brief gRPC (gun) 会话连接对象（Transmission 装饰器）
 * @details 将底层传输包装为 gun 连接（对齐 mihomo transport/gun）：
 * 1. WriteHandshake / ReadHandshake：HTTP/2 CONNECT 握手（简化）
 * 2. 数据面：gun-lite 模式裸透传（帧编解码由上层 h2 会话负责，
 *    Codec.hpp 纯函数供需要帧边界的测试直接使用）
 * @note 与 gun.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once

#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Gun/Codec.hpp>
#include <Preview/Protocols/Gun/Types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace Preview::Gun
{

    /**
     * @class Conn
     * @brief gRPC (gun) 会话连接（Transmission 装饰器）
     * @details 持有底层传输的独占所有权。握手成功后数据面透传。
     * @tparam Memory 会话内存策略（默认 8KB Arena；可注入自定义策略）
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Conn : public Preview::Transmission, public std::enable_shared_from_this<Conn<Memory>>
    {
    public:
        /// 内存策略类型（对外暴露，供嵌套层/测试使用）
        using MemoryType = Memory;

        /**
         * @brief 构造函数
         * @param Upstream 底层传输（所有权移交）
         */
        explicit Conn(SharedTransmission Upstream)
            : NextLayer_(std::move(Upstream))
        {
        }

        /**
         * @brief 获取执行器（委托底层传输）
         */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            if (!NextLayer_)
            {
                return {};
            }
            return NextLayer_->Executor();
        }

        /**
         * @brief 客户端握手：发送 CONNECT 帧（简化）
         * @param Host 目标主机
         * @return 错误码
         */
        [[nodiscard]] auto WriteHandshake(std::string_view Host) -> Net::awaitable<Error>
        {
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
            }
            Handshaken_ = false;
            PendingWire_.clear();
            PendingOffset_ = 0;
            const std::string Header = "CONNECT " + std::string(Host) + " HTTP/2\r\n\r\n";
            if (co_await SendBytes(AsU8Span(Header)))
                co_return Error::IoError;
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 服务端握手：解析 CONNECT 帧（简化）
         * @param Host 输出目标主机
         * @return 错误码；bad_magic = 非 CONNECT 帧
         */
        [[nodiscard]] auto ReadHandshake(std::string &Host) -> Net::awaitable<Error>
        {
            if (!NextLayer_)
            {
                co_return Error::NotOpen;
            }
            Handshaken_ = false;
            PendingWire_.clear();
            PendingOffset_ = 0;
            std::array<std::uint8_t, 256> Chunk{};
            std::string Header;
            for (int I = 0; I < 16; ++I)
            {
                std::error_code ErrorCode;
                const auto N = co_await NextLayer_->async_read_some(
                    AsBytes(std::span<std::uint8_t>(Chunk)),
                    ErrorCode);
                if (ErrorCode || N == 0)
                    break;
                if (N > Chunk.size())
                    co_return Error::BadLength;
                Header.append(reinterpret_cast<const char *>(Chunk.data()), N);
                if (Header.find("\r\n\r\n") != std::string::npos)
                    break;
            }
            const auto HeaderEnd = Header.find("\r\n\r\n");
            if (HeaderEnd == std::string::npos || Header.find("CONNECT ") != 0)
                co_return Error::BadMagic;
            const auto FirstLineEnd = Header.find("\r\n");
            if (FirstLineEnd == std::string::npos || FirstLineEnd > HeaderEnd)
                co_return Error::BadMagic;
            const auto HostEnd = Header.find(' ', 8);
            if (HostEnd == std::string::npos || HostEnd > FirstLineEnd || HostEnd == 8)
                co_return Error::BadMagic;
            Host = Header.substr(8, HostEnd - 8);
            PreserveHandshakeTail(Header, HeaderEnd + 4);
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 透传读取（数据面原样）
         */
        [[nodiscard]] auto async_read_some(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            if (!NextLayer_ || !Handshaken_)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            ErrorCode.clear();
            if (Buffer.empty())
            {
                co_return 0;
            }
            if (PendingOffset_ < PendingWire_.size())
            {
                const auto Count = (std::min)(Buffer.size(), PendingWire_.size() - PendingOffset_);
                std::memcpy(Buffer.data(), PendingWire_.data() + PendingOffset_, Count);
                PendingOffset_ += Count;
                if (PendingOffset_ == PendingWire_.size())
                {
                    PendingWire_.clear();
                    PendingOffset_ = 0;
                }
                co_return Count;
            }
            co_return co_await NextLayer_->async_read_some(Buffer, ErrorCode);
        }

        /**
         * @brief 透传写入（数据面原样）
         */
        [[nodiscard]] auto async_write_some(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            if (!NextLayer_ || !Handshaken_)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            co_return co_await NextLayer_->async_write_some(Buffer, ErrorCode);
        }

        /**
         * @brief 关闭底层传输
         */
        auto Close() -> void override
        {
            Handshaken_ = false;
            if (NextLayer_)
            {
                NextLayer_->Close();
            }
        }

        /**
         * @brief 取消挂起操作
         */
        auto Cancel() -> void override
        {
            if (NextLayer_)
            {
                NextLayer_->Cancel();
            }
        }

        /**
         * @brief 获取底层传输（装饰器链导航）
         */
        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 获取底层传输（const 版本）
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         */
        [[nodiscard]] auto Release() -> SharedTransmission override
        {
            Handshaken_ = false;
            return std::move(NextLayer_);
        }

    private:
        /**
         * @brief 发送全部字节
         * @param Data 数据
         * @return true = 失败
         */
        [[nodiscard]] auto SendBytes(std::span<const std::uint8_t> Data) const
            -> Net::awaitable<bool>
        {
            if (!NextLayer_)
            {
                co_return true;
            }
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                std::error_code ErrorCode;
                const auto N = co_await NextLayer_->async_write_some(
                    AsBytes(Data.subspan(Done)),
                    ErrorCode);
                if (ErrorCode)
                    co_return true;
                if (N == 0 || N > Data.size() - Done)
                    co_return true;
                Done += N;
            }
            co_return false;
        }

        auto PreserveHandshakeTail(const std::string &Data, std::size_t Offset) -> void
        {
            PendingWire_.clear();
            PendingOffset_ = 0;
            if (Offset < Data.size())
            {
                const auto *Begin = reinterpret_cast<const std::byte *>(Data.data() + Offset);
                PendingWire_.assign(Begin, Begin + (Data.size() - Offset));
            }
        }

        SharedTransmission NextLayer_;  ///< 底层传输（独占所有权）
        bool Handshaken_{false};          ///< 握手完成标志
        std::vector<std::byte> PendingWire_; ///< 握手读取时回注的后续数据
        std::size_t PendingOffset_{0};       ///< 回注数据消费位置
    };

    /// 流连接共享指针（默认内存策略）
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Gun
