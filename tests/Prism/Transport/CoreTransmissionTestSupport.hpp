/**
 * @file CoreTransmissionTestSupport.hpp
 * @brief CoreTransmission.cpp 拆分后的模块共享测试夹具与构造辅助。
 */
#pragma once

/**
 * @file CoreTransmission.cpp
 * @brief Prism/Transport/Transmission.hpp 单元测试
 * @details 覆盖 Prism::Transmission 传输抽象接口：
 * 1. 内存 mock（可配置读/写行为）验证全部纯虚方法：async_read_some、
 *    async_write_some、Close、Cancel、Executor
 * 2. 组合操作 AsyncRead/AsyncWrite 的正常、分块、EOF、错误分支
 * 3. completion-handler 桥接路径（co_spawn + ToEc 错误映射三分支）
 * 4. 装饰器链：TransportType 委托、NextLayer 默认、lowest_layer 转型
 * 5. Release() 默认与覆写、TransmissionLike 概念
 */

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Compatible.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <cstddef>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;

    /// 叶子传输：仅实现纯虚方法，不覆写任何默认实现（测基类默认分支）
    class LeafTransmission final : public Prism::Transmission
    {
    public:
        explicit LeafTransmission(Net::any_io_executor Ex) : Prism::Transmission(Ex), Ex_(std::move(Ex))
        {
        }

        auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            std::error_code OperationFailure;
            std::memset(Buffer.data(), 0, Buffer.size());
            OperationFailure.clear();
            { std::move(Handler)(Prism::IoResult{Buffer.size(), Prism::Fault::FromNative(OperationFailure)}); return; }
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            std::error_code OperationFailure;
            (void)Buffer;
            OperationFailure.clear();
            { std::move(Handler)(Prism::IoResult{Buffer.size(), Prism::Fault::FromNative(OperationFailure)}); return; }
        }

        auto OnClose() -> ControlResult override
        {
            Closed_ = true;

            return {};
        }

        auto OnCancel() -> ControlResult override
        {
            Canceled_ = true;

            return {};
        }

        bool Closed_{false};
        bool Canceled_{false};

    private:
        Net::any_io_executor Ex_;

        /** @brief 测试替身显式兑现半关闭；装饰器沿实际inner转交。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto* Inner = NextLayer()) { Inner->WriteShutdown(std::move(Handler)); return; }
            Prism::Transport::Detail::PostResult(Executor(), std::move(Handler), Prism::IoResult{0, {}});
        }
    };

    /// 装饰器 mock：可配置读/写行为，支持 Inner 链与 Release 所有权转移
    class MockTransmission : public Prism::Transmission
    {
    public:
        explicit MockTransmission(Net::any_io_executor Ex, Prism::Transmission *Inner = nullptr)
            : Prism::Transmission(Ex), Ex_(std::move(Ex)), Inner_(Inner)
        {
        }

        auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            std::error_code OperationFailure;
            if (ReadErr_)
            {
                OperationFailure = *ReadErr_;
                { std::move(Handler)(Prism::IoResult{0, Prism::Fault::FromNative(OperationFailure)}); return; }
            }
            if (ReadBuf_.empty())
            {
                OperationFailure.clear();
                { std::move(Handler)(Prism::IoResult{0, {Prism::Fault::Code::Eof}}); return; } // EOF
            }
            const auto ByteCount = std::min(Buffer.size(), std::min(ReadBuf_.size(), ReadMax_));
            std::memcpy(Buffer.data(), ReadBuf_.data(), ByteCount);
            ReadBuf_.erase(ReadBuf_.begin(), ReadBuf_.begin() + static_cast<std::ptrdiff_t>(ByteCount));
            OperationFailure.clear();
            { std::move(Handler)(Prism::IoResult{ByteCount, Prism::Fault::FromNative(OperationFailure)}); return; }
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            std::error_code OperationFailure;
            if (WriteErr_)
            {
                OperationFailure = *WriteErr_;
                { std::move(Handler)(Prism::IoResult{0, Prism::Fault::FromNative(OperationFailure)}); return; }
            }
            if (WriteZero_)
            {
                OperationFailure.clear();
                { std::move(Handler)(Prism::IoResult{0, Prism::Fault::FromNative(OperationFailure)}); return; }
            }
            const auto ByteCount = std::min(Buffer.size(), WriteMax_);
            Written_ += ByteCount;
            OperationFailure.clear();
            { std::move(Handler)(Prism::IoResult{ByteCount, Prism::Fault::FromNative(OperationFailure)}); return; }
        }

        auto OnClose() -> ControlResult override
        {
            Closed_ = true;

            return {};
        }

        auto OnCancel() -> ControlResult override
        {
            Canceled_ = true;

            return {};
        }

        auto NextLayer() noexcept -> Prism::Transmission * override
        {
            return Inner_;
        }

        auto NextLayer() const noexcept -> const Prism::Transmission * override
        {
            return Inner_;
        }

        auto Release() -> std::shared_ptr<Prism::Transmission> override
        {
            auto ReadCarrier = std::move(Released_);
            Released_.reset();
            return ReadCarrier;
        }

        /// 配置：设置预读数据
        auto SetReadData(std::vector<std::byte> Data) -> void
        {
            ReadBuf_ = std::move(Data);
        }

        /// 配置：设置单次最大读取字节数（0 = 无限）
        auto SetReadMax(std::size_t Maximum) -> void
        {
            ReadMax_ = Maximum;
        }

        /// 配置：设置读错误（覆盖 EOF 行为）
        auto SetReadError(std::error_code Error) -> void
        {
            ReadErr_ = Error;
        }

        /// 配置：设置单次最大写入字节数（0 = 无限）
        auto SetWriteMax(std::size_t Maximum) -> void
        {
            WriteMax_ = Maximum;
        }

        /// 配置：写返回 0（模拟 broken pipe）
        auto SetWriteZero(bool Enabled) -> void
        {
            WriteZero_ = Enabled;
        }

        /// 配置：设置写错误
        auto SetWriteError(std::error_code Error) -> void
        {
            WriteErr_ = Error;
        }

        /// 配置：设置 Release() 转移的底层传输
        auto SetRelease(std::shared_ptr<Prism::Transmission> Transmission) -> void
        {
            Released_ = std::move(Transmission);
        }

        std::size_t Written_{0};
        bool Closed_{false};
        bool Canceled_{false};

    private:
        Net::any_io_executor Ex_;
        Prism::Transmission *Inner_{nullptr};
        std::vector<std::byte> ReadBuf_;
        std::optional<std::error_code> ReadErr_;
        std::size_t ReadMax_{SIZE_MAX};
        std::size_t WriteMax_{SIZE_MAX};
        bool WriteZero_{false};
        std::optional<std::error_code> WriteErr_;
        std::shared_ptr<Prism::Transmission> Released_;

        /** @brief 测试替身显式兑现半关闭；装饰器沿实际inner转交。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto* Inner = NextLayer()) { Inner->WriteShutdown(std::move(Handler)); return; }
            Prism::Transport::Detail::PostResult(Executor(), std::move(Handler), Prism::IoResult{0, {}});
        }
    };

    /// UDP 装饰器：覆写 TransportType 返回 udp
    class UdpDecorator final : public MockTransmission
    {
    public:
        using MockTransmission::MockTransmission;

        auto TransportType() const noexcept -> Type override
        {
            return Type::Udp;
        }
    };

    /// 非 final 中间类：仅实现纯虚方法，不覆写默认实现（阻止 devirtualize 内联）
    class IntermediateTransmission : public Prism::Transmission
    {
    public:
        explicit IntermediateTransmission(Net::any_io_executor Ex) : Prism::Transmission(Ex), Ex_(std::move(Ex))
        {
        }

        auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            std::error_code OperationFailure;
            std::memset(Buffer.data(), 0, Buffer.size());
            OperationFailure.clear();
            { std::move(Handler)(Prism::IoResult{Buffer.size(), Prism::Fault::FromNative(OperationFailure)}); return; }
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            std::error_code OperationFailure;
            (void)Buffer;
            OperationFailure.clear();
            { std::move(Handler)(Prism::IoResult{Buffer.size(), Prism::Fault::FromNative(OperationFailure)}); return; }
        }

        auto OnClose() -> ControlResult override
        {

            return {};
        }

        auto OnCancel() -> ControlResult override
        {

            return {};
        }

    private:
        Net::any_io_executor Ex_;

        /** @brief 测试替身显式兑现半关闭；装饰器沿实际inner转交。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto* Inner = NextLayer()) { Inner->WriteShutdown(std::move(Handler)); return; }
            Prism::Transport::Detail::PostResult(Executor(), std::move(Handler), Prism::IoResult{0, {}});
        }
    };

    class ThrowingTransmission final : public Prism::Transmission
    {
    public:
        explicit ThrowingTransmission(Net::any_io_executor Ex) : Prism::Transmission(Ex), Ex_(std::move(Ex))
        {
        }

        auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            throw std::runtime_error("read failure");
        }

        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            throw std::runtime_error("write failure");
        }

        auto OnClose() -> ControlResult override
        {

            return {};
        }

        auto OnCancel() -> ControlResult override
        {

            return {};
        }

    private:
        Net::any_io_executor Ex_;

        /** @brief 测试替身显式兑现半关闭；装饰器沿实际inner转交。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto* Inner = NextLayer()) { Inner->WriteShutdown(std::move(Handler)); return; }
            Prism::Transport::Detail::PostResult(Executor(), std::move(Handler), Prism::IoResult{0, {}});
        }
    };






























} // namespace
