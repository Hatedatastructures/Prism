/**
 * @file Common.hpp
 * @brief adapter 公共工具（handler 共享，避免重复实现）
 */

#pragma once

#include <boost/asio/system_executor.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <Preview/Account/Authenticator.hpp>
#include <Preview/Account/Directory.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Runtime::Detail
{

    [[nodiscard]] inline auto HexIdentity(std::span<const std::uint8_t> Bytes) -> std::string
    {
        constexpr char Hex[] = "0123456789abcdef";
        std::string Result;
        Result.reserve(Bytes.size() * 2U);
        for (const auto Byte : Bytes)
        {
            Result.push_back(Hex[(Byte >> 4U) & 0x0fU]);
            Result.push_back(Hex[Byte & 0x0fU]);
        }
        return Result;
    }

    /**
     * @class ReplayTransmission
     * @brief 为多候选协议握手缓存有限的入站字节
     * @details 候选密钥只参与握手读取；失败候选不会关闭底层传输，
     *          成功后立即切换为直通模式。缓存有硬上限且不打印内容。
     */
    class ReplayTransmission final : public Preview::Transmission
    {
    public:
        explicit ReplayTransmission(Preview::SharedTransmission Inner,
                                    const std::size_t MaxBytes = 64U * 1024U)
            : Inner_(std::move(Inner)), MaxBytes_(MaxBytes)
        {
        }

        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Inner_ ? Inner_->TransportType() : Type::Tcp;
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Inner_ ? Inner_->Executor() : Net::system_executor();
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer,
                                           std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t> override
        {
            if (Committed_)
            {
                co_return co_await Inner_->async_read_some(Buffer, ErrorCode);
            }
            if (!Inner_ || Buffer.empty())
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            if (ReplayOffset_ < Cached_.size())
            {
                const auto Count = (std::min)(Buffer.size(), Cached_.size() - ReplayOffset_);
                std::memcpy(Buffer.data(), Cached_.data() + ReplayOffset_, Count);
                ReplayOffset_ += Count;
                ErrorCode.clear();
                co_return Count;
            }
            if (ReplayError_)
            {
                ErrorCode = ReplayError_;
                co_return 0;
            }
            if (Cached_.size() >= MaxBytes_)
            {
                ErrorCode = make_error_code(Error::BadLength);
                ReplayError_ = ErrorCode;
                co_return 0;
            }

            const auto Available = MaxBytes_ - Cached_.size();
            auto ReadBuffer = Buffer.first((std::min)(Buffer.size(), Available));
            const auto Count = co_await Inner_->async_read_some(ReadBuffer, ErrorCode);
            if (Count > ReadBuffer.size())
            {
                ErrorCode = make_error_code(Error::BrokenPipe);
                ReplayError_ = ErrorCode;
                co_return 0;
            }
            Cached_.insert(Cached_.end(), ReadBuffer.begin(), ReadBuffer.begin() + Count);
            ReplayOffset_ += Count;
            if (ErrorCode)
            {
                ReplayError_ = ErrorCode;
            }
            co_return Count;
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer,
                                            std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t> override
        {
            if ((!Committed_ && !WritesEnabled_) || !Inner_)
            {
                ErrorCode = make_error_code(Error::NotOpen);
                co_return 0;
            }
            co_return co_await Inner_->async_write_some(Buffer, ErrorCode);
        }

        void Close() override
        {
            if (Committed_ && Inner_)
            {
                Inner_->Close();
            }
        }

        void Cancel() override
        {
            if (Committed_ && Inner_)
            {
                Inner_->Cancel();
            }
        }

        void Shutdown() override
        {
            if (Committed_ && Inner_)
            {
                Inner_->Shutdown();
            }
        }

        void SetTimeout(const std::chrono::milliseconds Timeout) override
        {
            if (Inner_)
            {
                Inner_->SetTimeout(Timeout);
            }
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return Inner_ && Inner_->IsOpen();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return Inner_.get();
        }

        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission * override
        {
            return Inner_.get();
        }

        [[nodiscard]] auto Release() -> Preview::SharedTransmission override
        {
            if (!Committed_)
            {
                return {};
            }
            return std::move(Inner_);
        }

        void ResetForRetry() noexcept
        {
            ReplayOffset_ = 0;
        }

        void Commit() noexcept
        {
            Committed_ = true;
            ClearCache();
            ReplayError_.clear();
        }

        /**
         * @brief 为候选协议的认证后握手响应打开真实写侧
         * @details 多凭据 trial 的读侧仍保持可回放；Vmess/SS2022
         *          Accept 会在自身 parser/auth gate 通过后才真正写响应。
         */
        void EnableWrites() noexcept
        {
            WritesEnabled_ = true;
        }

        void CloseUnderlying() noexcept
        {
            if (Inner_)
            {
                Inner_->Close();
            }
        }

    private:
        void ClearCache() noexcept
        {
            std::fill(Cached_.begin(), Cached_.end(), std::byte{0});
            Cached_.clear();
            Cached_.shrink_to_fit();
            ReplayOffset_ = 0;
        }

        Preview::SharedTransmission Inner_;
        const std::size_t MaxBytes_;
        std::vector<std::byte> Cached_;
        std::size_t ReplayOffset_{0};
        std::error_code ReplayError_;
        bool Committed_{false};
        bool WritesEnabled_{false};
    };

    using AccountRecords = std::vector<Preview::Account::SharedAccountRecord>;

    [[nodiscard]] inline auto RecordsForCredential(
        const std::shared_ptr<const Preview::Account::AccountDirectory> &Directory,
        const Preview::Account::CredentialKind Kind) -> AccountRecords
    {
        AccountRecords Records;
        if (!Directory)
        {
            return Records;
        }
        Directory->ForEach([&Records, Kind](const Preview::Account::SharedAccountRecord &Record)
        {
            if (Record && Record->Credential().Kind() == Kind)
            {
                Records.push_back(Record);
            }
        });
        return Records;
    }

    [[nodiscard]] inline auto CopyUuid(const Preview::Account::CredentialView Credential)
        -> std::optional<std::array<std::uint8_t, 16>>
    {
        if (Credential.Kind() != Preview::Account::CredentialKind::Uuid ||
            Credential.Size() != 16U)
        {
            return std::nullopt;
        }
        std::array<std::uint8_t, 16> Value{};
        for (std::size_t Index = 0; Index < Value.size(); ++Index)
        {
            Value[Index] = std::to_integer<std::uint8_t>(Credential.Bytes()[Index]);
        }
        return Value;
    }

    [[nodiscard]] inline auto CopyPsk(const Preview::Account::CredentialView Credential)
        -> std::optional<std::array<std::uint8_t, 16>>
    {
        if (Credential.Kind() != Preview::Account::CredentialKind::Psk ||
            Credential.Size() != 16U)
        {
            return std::nullopt;
        }
        std::array<std::uint8_t, 16> Value{};
        for (std::size_t Index = 0; Index < Value.size(); ++Index)
        {
            Value[Index] = std::to_integer<std::uint8_t>(Credential.Bytes()[Index]);
        }
        return Value;
    }

} // namespace Preview::Runtime::Detail
