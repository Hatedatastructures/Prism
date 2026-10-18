/**
 * @file CarrierStream.hpp
 * @brief Reality carrier 的 TLS 1.3 record Transmission wrapper。
 * @details 负责应用数据的 TLS record 加解密，并把关闭、取消、半关闭、
 *          超时和底层导航委托给被包装的 Transmission。
 */
#pragma once
#include <Prism/Protocols/Reality/Detail/Record.hpp>
#include <Prism/Protocols/Reality/Detail/Tls.hpp>
#include <Prism/Protocols/Reality/Detail/Key.hpp>
#include <Prism/Protocols/Reality/Detail/Authentication.hpp>
#include <Prism/Protocols/Reality/Types.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <system_error>
#include <utility>

namespace Prism::Reality::Detail
{

    /**
     * @brief 对应用数据执行 TLS 1.3 record 加解密的传输装饰器。
     * @details 读方向使用 client application key，写方向使用 server
     *          application key；底层的 Close/Cancel/Shutdown 仍由 owner
     *          传输执行，保持半关闭语义。
     */
    class TlsRecordStream final : public Prism::Transmission
    {
    public:
        TlsRecordStream(Prism::SharedTransmission Transport, Tls13Keys Keys)
            : Prism::Transmission(Transport ? Transport->Executor() : Net::any_io_executor{}),
              NextLayer_(std::move(Transport)), Keys_(std::move(Keys))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return NextLayer_ ? NextLayer_->Executor() : Net::any_io_executor{};
        }

        /** @brief 读取一部分明文；结果与借用沿正式前门交付一次。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<ReadWork>(RecordRead{std::static_pointer_cast<TlsRecordStream>(Transmission::shared_from_this()), Buffer},
                     std::move(Handler));
        }

        /** @brief 写入一部分明文并封装为 application record。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<WriteWork>(RecordWrite{std::static_pointer_cast<TlsRecordStream>(Transmission::shared_from_this()), Buffer},
                     std::move(Handler));
        }

        /** @brief 真实写半关闭转交底层载体；反向读取仍然可用。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (!NextLayer_)
            {
                Prism::Transport::Detail::PostResult(
                    Executor(),
                    std::move(Handler), Prism::IoResult{0, {Prism::Fault::Code::IoError}});
                return;
            }
            NextLayer_->WriteShutdown(std::move(Handler));
        }

        /** @brief 封止并交付底层关闭；实际退出由 Activity()->Drain() 另行等待。 */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            if (!NextLayer_)
            {
                return {};
            }
            return NextLayer_->Close();
        }

        /** @brief 可重复取消底层挂起操作；成功只表示命令已接管。 */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            if (!NextLayer_)
            {
                return {};
            }
            return NextLayer_->Cancel();
        }

        auto SetTimeout(const std::chrono::milliseconds Timeout) -> void override
        {
            if (NextLayer_)
            {
                NextLayer_->SetTimeout(Timeout);
            }
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return NextLayer_ && NextLayer_->IsOpen();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission * override
        {
            return NextLayer_.get();
        }

        [[nodiscard]] auto NextLayer() const noexcept -> const Prism::Transmission * override
        {
            return NextLayer_.get();
        }

        [[nodiscard]] auto Release() -> Prism::SharedTransmission override
        {
            return std::move(NextLayer_);
        }

    private:
        /** @brief 原协程体：读取并解密 record，保留干净 EOF 与 record 边界语义。 */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            while (PendingOffset_ == Pending_.size())
            {
                auto Record = co_await ReadRecord(NextLayer_);
                if (!Record)
                {
                    co_return Prism::IoResult{0, Record.error()};
                }
                auto [DecryptError, Plaintext] = DecryptTlsRecord(
                    Tls13RecordOpenInput{*Record, Keys_.ClientApplicationKey,
                                         std::span<const std::uint8_t, 12>(Keys_.ClientApplicationIv),
                                         ReadSequence_++});
                if (DecryptError != Prism::Error::None)
                {
                    co_return Prism::IoResult{0, Prism::Fault::FromNative(
                        Prism::make_error_code(DecryptError))};
                }
                if (Plaintext.ContentType != 0x17)
                {
                    auto Code = Prism::Fault::Code::ProtocolError;
                    if (Plaintext.ContentType == 0x15)
                    {
                        Code = Prism::Fault::Code::Eof;
                    }
                    else if (Plaintext.ContentType == 0x16)
                    {
                        Code = Prism::Fault::Code::TlsHsfail;
                    }
                    co_return Prism::IoResult{0, {Code}};
                }
                Pending_ = std::move(Plaintext.Data);
                PendingOffset_ = 0;
            }
            const auto Count = (std::min)(Buffer.size(), Pending_.size() - PendingOffset_);
            std::memcpy(Buffer.data(), Pending_.data() + PendingOffset_, Count);
            PendingOffset_ += Count;
            co_return Prism::IoResult{Count, {}};
        }

        /** @brief 原协程体：加密并完整写出 application record。 */
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            const auto Data = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(Buffer.data()), Buffer.size());
            auto [EncryptError, Record] = EncryptTlsRecord(
                Tls13RecordSealInput{Keys_.ServerApplicationKey,
                                     std::span<const std::uint8_t, 12>(Keys_.ServerApplicationIv),
                                     WriteSequence_++, 0x17, Data});
            if (EncryptError != Prism::Error::None)
            {
                co_return Prism::IoResult{0, Prism::Fault::FromNative(
                    Prism::make_error_code(EncryptError))};
            }
            const auto WriteResult = co_await WriteAll(
                NextLayer_, std::as_bytes(std::span<const std::uint8_t>(Record)));
            if (WriteResult.Failure.Failed())
            {
                co_return Prism::IoResult{0, WriteResult.Failure};
            }
            co_return Prism::IoResult{Buffer.size(), {}};
        }

        struct RecordRead final { std::shared_ptr<TlsRecordStream> Owner; std::span<std::byte> Buffer; };
        struct RecordWrite final { std::shared_ptr<TlsRecordStream> Owner; std::span<const std::byte> Buffer; };
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, RecordRead Input) const -> void
            {
                Prism::Transport::Detail::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->ReadPartial(Input.Buffer), Net::deferred);
                co_return std::tuple{Result};
            }
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, RecordWrite Input) const -> void
            {
                Prism::Transport::Detail::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WritePartial(Input.Buffer), Net::deferred);
                co_return std::tuple{Result};
            }
        };
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(Work{}, Executor()), Handler, std::move(Value));
        }

        Prism::SharedTransmission NextLayer_;
        Tls13Keys Keys_;
        std::uint64_t ReadSequence_{0};
        std::uint64_t WriteSequence_{0};
        Bytes Pending_;
        std::size_t PendingOffset_{0};
    };

} // namespace Prism::Reality::Detail
