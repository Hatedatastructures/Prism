/** @file ProbeBuffer.cpp @brief 连接级增量探测缓冲区实现。 */
#include <Prism/Runtime/Recognition/ProbeBuffer.hpp>

#include <Prism/Foundation/Fault/Handling.hpp>

#include <algorithm>
#include <memory>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Recognition
{
    namespace
    {
        [[nodiscard]] auto IsEof(const Prism::Fault::Failure& Failure) noexcept -> bool
        {
            return Failure.Code == Prism::Fault::Code::Eof ||
                (Failure.Native && Prism::Fault::ToCode(Failure.Native) == Prism::Fault::Code::Eof);
        }

        [[nodiscard]] auto StatusForTerminal(const Prism::Fault::Failure& Failure) noexcept
            -> RecognitionStatus
        {
            return IsEof(Failure) ? RecognitionStatus::EndOfStream : RecognitionStatus::IoError;
        }
    }

    ProbeBuffer::ProbeBuffer(
        const std::size_t MaxBytes,
        std::shared_ptr<Prism::Memory::BytePool> Bytes)
        : MaxBytes_((std::min)(MaxBytes, MaxSupportedBytes)),
          Storage_(std::make_shared<std::vector<std::byte>>())
    {
        Storage_->reserve(MaxBytes_);
        Bytes_ = std::move(Bytes);
    }

    auto ProbeBuffer::Seed(const std::span<const std::byte> Data) -> bool
    {
        if (Data.size() > MaxBytes_ || Size() > MaxBytes_ - Data.size())
        {
            return false;
        }
        EnsureWritable();
        Storage_->insert(Storage_->end(), Data.begin(), Data.end());
        return true;
    }

    auto ProbeBuffer::Ensure(Prism::Transmission& Transport, const std::size_t Minimum)
        -> Net::awaitable<ProbeFillResult>
    {
        ProbeFillResult Result;
        if (Minimum <= Size())
        {
            co_return Result;
        }
        if (Minimum > MaxBytes_)
        {
            Result.Status = RecognitionStatus::BudgetExceeded;
            co_return Result;
        }
        if (Terminal_.Failed())
        {
            Result.Status = StatusForTerminal(Terminal_);
            Result.Error = Prism::Fault::ToNative(Terminal_);
            co_return Result;
        }

        while (Size() < Minimum)
        {
            EnsureWritable();
            const auto OriginalSize = Storage_->size();
            const auto Need = Minimum - OriginalSize;
            Storage_->resize(Minimum);

            const auto Part = co_await Transport.ReadSome(
                std::span<std::byte>(Storage_->data() + OriginalSize, Need));
            const auto Read = Part.Bytes;
            if (Read > Need)
            {
                Storage_->resize(OriginalSize);
                Result.Status = RecognitionStatus::IoError;
                Terminal_ = Part.Failure;
                if (!Terminal_.Failed())
                {
                    Terminal_ = Prism::Fault::FromNative(
                        std::make_error_code(std::errc::value_too_large));
                }
                Result.Error = Prism::Fault::ToNative(Terminal_);
                co_return Result;
            }

            Storage_->resize(OriginalSize + Read);
            Result.Added += Read;
            if (Part.Failure.Failed())
            {
                Terminal_ = Part.Failure;
                Result.Status = RecognitionStatus::IoError;
                if (Read == 0 && IsEof(Terminal_))
                {
                    Result.Status = RecognitionStatus::EndOfStream;
                }
                Result.Error = Prism::Fault::ToNative(Terminal_);
                co_return Result;
            }
            if (Read == 0)
            {
                Terminal_ = Prism::Fault::Failure{Prism::Fault::Code::Eof};
                Result.Status = RecognitionStatus::EndOfStream;
                co_return Result;
            }
        }

        co_return Result;
    }

    auto ProbeBuffer::ReadSome(Prism::Transmission& Transport, const std::size_t Maximum)
        -> Net::awaitable<ProbeFillResult>
    {
        const auto Read = co_await ReadSomeWithTerminal(Transport, Maximum);
        co_return ProbeFillResult{
            Read.Status, Read.Added, Prism::Fault::ToNative(Read.Failure)};
    }

    auto ProbeBuffer::ReadSomeWithTerminal(
        Prism::Transmission& Transport,
        const std::size_t Maximum)
        -> Net::awaitable<ProbeReadResult>
    {
        ProbeReadResult Result;
        if (Maximum == 0)
        {
            co_return Result;
        }
        if (Terminal_.Failed())
        {
            Result.Status = StatusForTerminal(Terminal_);
            Result.Failure = Terminal_;
            co_return Result;
        }
        if (Size() >= MaxBytes_)
        {
            Result.Status = RecognitionStatus::BudgetExceeded;
            co_return Result;
        }

        EnsureWritable();
        const auto OriginalSize = Storage_->size();
        const auto ReadSize = (std::min)(Maximum, MaxBytes_ - OriginalSize);
        Storage_->resize(OriginalSize + ReadSize);

        const auto Part = co_await Transport.ReadSome(
            std::span<std::byte>(Storage_->data() + OriginalSize, ReadSize));
        const auto Read = Part.Bytes;
        if (Read > ReadSize)
        {
            Storage_->resize(OriginalSize);
            Result.Status = RecognitionStatus::IoError;
            Terminal_ = Part.Failure;
            if (!Terminal_.Failed())
            {
                Terminal_ = Prism::Fault::FromNative(
                    std::make_error_code(std::errc::value_too_large));
            }
            Result.Failure = Terminal_;
            co_return Result;
        }

        Storage_->resize(OriginalSize + Read);
        Result.Added = Read;
        if (Part.Failure.Failed())
        {
            Terminal_ = Part.Failure;
            Result.Status = RecognitionStatus::IoError;
            if (Read == 0 && IsEof(Terminal_))
            {
                Result.Status = RecognitionStatus::EndOfStream;
            }
            Result.Failure = Terminal_;
            co_return Result;
        }
        if (Read == 0)
        {
            Terminal_ = Prism::Fault::Failure{Prism::Fault::Code::Eof};
            Result.Status = RecognitionStatus::EndOfStream;
        }
        co_return Result;
    }

    auto ProbeBuffer::Replay(Prism::SharedTransmission Transport) const
        -> Prism::SharedTransmission
    {
        auto Result = Replay(std::move(Transport), Terminal_);
        if (!Result)
        {
            return {};
        }
        return std::move(*Result);
    }

    auto ProbeBuffer::Replay(
        Prism::SharedTransmission Transport,
        Prism::Fault::Failure Terminal) const
        -> std::expected<Prism::SharedTransmission, Prism::Fault::Failure>
    {
        if (Terminal_.Failed())
        {
            Terminal = Terminal_;
        }
        if (Data().empty() && !Terminal.Failed())
        {
            return Transport;
        }
        return Prism::Transport::PreviewTransport::Create(
            Transport, Prism::Transport::PrefixInput{Data(), Bytes_, std::move(Terminal)});
    }

    auto ProbeBuffer::EnsureWritable() -> void
    {
        if (Storage_.use_count() > 1)
        {
            Storage_ = std::make_shared<std::vector<std::byte>>(*Storage_);
            Storage_->reserve(MaxBytes_);
        }
    }
}
