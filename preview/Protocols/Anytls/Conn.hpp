/**
 * @file Conn.hpp
 * @brief AnyTLS 会话连接对象（Transmission 装饰器）
 * @details 将底层传输包装为 AnyTLS 连接（对齐 mihomo transport/anytls）：
 * 1. WriteHandshake：发送认证帧 [SHA-256(password)][padlen][padding]
 * 2. ReadHandshake：服务端读取认证帧并校验密码哈希
 * 3. 数据面：内部多路复用（Session 帧），测试库简化透传
 * @note 与 anytls.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once

#include <preview/Foundation/ByteSpan.hpp>
#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Foundation/Memory/Pointer.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Anytls/Codec.hpp>
#include <preview/Protocols/Anytls/Types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace Preview::Anytls
{

    /**
     * @class Conn
     * @brief AnyTLS 会话连接（Transmission 装饰器）
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
         * @param upstream 底层传输（所有权移交）
         * @param password 认证密码
         */
        explicit Conn(SharedTransmission upstream, std::string password)
            : NextLayer_(std::move(upstream)), Password_(std::move(password))
        {
        }

        /**
         * @brief 获取执行器（委托底层传输）
         */
        [[nodiscard]] auto Executor() const 
            -> net::any_io_executor override
        {
            return NextLayer_->Executor();
        }

        /**
         * @brief 客户端握手：发送认证帧
         * @param PadLen Padding 长度（默认 16）
         * @return 错误码
         */
        [[nodiscard]] auto WriteHandshake(std::uint16_t PadLen = 16)
            -> net::awaitable<Error>
        {
            std::string Frame;
            auto Err = BuildAuthFrame(Password_, PadLen, Frame);
            if (Err != Error::None)
                co_return Err;
            if (co_await SendBytes(AsU8Span(Frame)))
                co_return Error::IoError;
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 服务端握手：读取并校验认证帧
         * @return 错误码；bad_auth = 密码哈希不匹配
         */
        [[nodiscard]] auto ReadHandshake()
            -> net::awaitable<Error>
        {
            // 头：Hash(32) + PadLen(2 BE)
            std::array<std::uint8_t, AuthFrameHdrlen> head{};
            if (co_await ReadExact(std::span<std::uint8_t>(head)))
                co_return Error::UnexpectedEof;
            std::array<std::uint8_t, PasswordHashLen> Hash{};
            std::memcpy(Hash.data(), head.data(), PasswordHashLen);
            const auto PadLen = static_cast<std::uint16_t>(head[PasswordHashLen]) << 8 |
                                 head[PasswordHashLen + 1];
            if (PadLen > 0)
            {
                std::vector<std::uint8_t> padding(PadLen);
                if (co_await ReadExact(padding))
                    co_return Error::UnexpectedEof;
            }
            if (!VerifyAuth(Password_, Hash))
                co_return Error::BadAuth;
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 透传读取（数据面原样）
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (!Handshaken_)
            {
                ec = make_error_code(Error::NotOpen);
                co_return 0;
            }
            co_return co_await NextLayer_->async_read_some(Buffer, ec);
        }

        /**
         * @brief 透传写入（数据面原样）
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (!Handshaken_)
            {
                ec = make_error_code(Error::NotOpen);
                co_return 0;
            }
            co_return co_await NextLayer_->async_write_some(Buffer, ec);
        }

        /**
         * @brief 关闭底层传输
         */
        void Close() override
        {
            NextLayer_->Close();
        }

        /**
         * @brief 取消挂起操作
         */
        void Cancel() override
        {
            NextLayer_->Cancel();
        }

        /**
         * @brief 获取底层传输（装饰器链导航）
         */
        [[nodiscard]] auto NextLayer() noexcept 
            -> Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 获取底层传输（const 版本）
         */
        [[nodiscard]] auto NextLayer() const noexcept
             -> const Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         */
        [[nodiscard]] auto Release() 
            -> SharedTransmission override
        {
            return std::move(NextLayer_);
        }

    private:
        /**
         * @brief 精确读取指定字节数
         * @param dst 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         */
        [[nodiscard]] auto ReadExact(std::span<std::uint8_t> dst)
            -> net::awaitable<bool>
        {
            std::size_t Done = 0;
            while (Done < dst.size())
            {
                std::error_code ec;
                const auto N = co_await NextLayer_->async_read_some(AsBytes(dst.subspan(Done)), ec);
                if (ec || N == 0)
                    co_return true;
                Done += N;
            }
            co_return false;
        }

        /**
         * @brief 发送全部字节
         * @param Data 数据
         * @return true = 失败
         */
        [[nodiscard]] auto SendBytes(std::span<const std::uint8_t> Data) const
            -> net::awaitable<bool>
        {
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                std::error_code ec;
                const auto N = co_await NextLayer_->async_write_some(AsBytes(Data.subspan(Done)), ec);
                if (ec)
                    co_return true;
                Done += N;
            }
            co_return false;
        }

        SharedTransmission NextLayer_;  ///< 底层传输（独占所有权）
        std::string Password_;            ///< 认证密码
        bool Handshaken_{false};          ///< 握手完成标志
    };

    /// 流连接共享指针（默认内存策略）
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Anytls
