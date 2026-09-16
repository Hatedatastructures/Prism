/**
 * @file FacadeCarrier.hpp
 * @brief Preview-owned carrier facade contract。
 * @details 载体只负责把 owner-held transport、握手状态和预读回放一起交给
 *          异步 carrier callback。失败结果保留原始 transport，调用方可以
 *          安全地尝试下一个候选；成功结果必须明确声明 wire 已完成。
 */
#pragma once

#include <Preview/Foundation/Error.hpp>
#include <Preview/Transport/Preview.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace Preview::Composition::Carrier
{

    namespace Net = boost::asio;

    enum class CarrierKind : std::uint8_t
    {
        Reality,
        Shadowtls,
        Restls,
    };

    enum class HandshakeStage : std::uint8_t
    {
        Idle,
        Preparing,
        Committing,
        Accepted,
        Rejected,
        Cancelled,
    };

    enum class CarrierError : std::uint8_t
    {
        None,
        NoTransport,
        MissingCallback,
        WireUnavailable,
        InvalidResult,
        InvalidState,
        NeedMore,
        UnexpectedEof,
        AuthFailed,
        Timeout,
        Cancelled,
        TransportFailure,
        ProtocolFailure,
        CryptoFailure,
        Unsupported,
    };

    class CarrierErrorCategory final : public std::error_category
    {
    public:
        [[nodiscard]] auto name() const noexcept -> const char * override
        {
            return "prism.preview.carrier";
        }

        [[nodiscard]] auto message(const int Value) const -> std::string override
        {
            switch (static_cast<CarrierError>(Value))
            {
            case CarrierError::None: return "no carrier error";
            case CarrierError::NoTransport: return "carrier transport is missing";
            case CarrierError::MissingCallback: return "carrier callback is missing";
            case CarrierError::WireUnavailable: return "carrier wire implementation is unavailable";
            case CarrierError::InvalidResult: return "carrier returned an invalid result";
            case CarrierError::InvalidState: return "carrier handshake state is invalid";
            case CarrierError::NeedMore: return "carrier needs more input";
            case CarrierError::UnexpectedEof: return "carrier input ended during handshake";
            case CarrierError::AuthFailed: return "carrier authentication failed";
            case CarrierError::Timeout: return "carrier handshake timed out";
            case CarrierError::Cancelled: return "carrier handshake was cancelled";
            case CarrierError::TransportFailure: return "carrier transport failed";
            case CarrierError::ProtocolFailure: return "carrier protocol failed";
            case CarrierError::CryptoFailure: return "carrier cryptography failed";
            case CarrierError::Unsupported: return "carrier feature is unsupported";
            }
            return "unknown carrier error";
        }
    };

    [[nodiscard]] inline auto CarrierCategory() noexcept -> const std::error_category &
    {
        static const CarrierErrorCategory Category;
        return Category;
    }

    [[nodiscard]] inline auto make_error_code(const CarrierError ErrorCode) noexcept
        -> std::error_code
    {
        return {static_cast<int>(ErrorCode), CarrierCategory()};
    }

    struct CarrierFailure final
    {
        CarrierError Code{CarrierError::None};
        Preview::Error ProtocolCode{Preview::Error::None};
        std::error_code NativeCode{};
        HandshakeStage Stage{HandshakeStage::Idle};
        std::string Detail;
    };

    [[nodiscard]] inline auto MapError(const Preview::Error ErrorCode,
                                       const HandshakeStage Stage,
                                       std::string Detail = {}) -> CarrierFailure
    {
        CarrierError Mapped = CarrierError::ProtocolFailure;
        switch (ErrorCode)
        {
        case Preview::Error::None: Mapped = CarrierError::None; break;
        case Preview::Error::NeedMore: Mapped = CarrierError::NeedMore; break;
        case Preview::Error::UnexpectedEof: Mapped = CarrierError::UnexpectedEof; break;
        case Preview::Error::BadAuth:
        case Preview::Error::AuthFailed: Mapped = CarrierError::AuthFailed; break;
        case Preview::Error::Timeout: Mapped = CarrierError::Timeout; break;
        case Preview::Error::Canceled: Mapped = CarrierError::Cancelled; break;
        case Preview::Error::NotOpen:
        case Preview::Error::BrokenPipe:
        case Preview::Error::IoError: Mapped = CarrierError::TransportFailure; break;
        case Preview::Error::KdfError:
        case Preview::Error::CryptoError: Mapped = CarrierError::CryptoFailure; break;
        case Preview::Error::NotSupported:
        case Preview::Error::Unsupported: Mapped = CarrierError::Unsupported; break;
        case Preview::Error::BadLength:
        case Preview::Error::BadMagic:
        case Preview::Error::VersionMismatch:
        case Preview::Error::BadMessage:
        case Preview::Error::BadAddress:
        case Preview::Error::ProtocolError: Mapped = CarrierError::ProtocolFailure; break;
        }
        return CarrierFailure{Mapped, ErrorCode, {}, Stage, std::move(Detail)};
    }

    [[nodiscard]] inline auto MapError(const std::error_code &ErrorCode,
                                       const HandshakeStage Stage,
                                       std::string Detail = {}) -> CarrierFailure
    {
        if (!ErrorCode)
        {
            return CarrierFailure{CarrierError::None,
                                  Preview::Error::None,
                                  {},
                                  Stage,
                                  std::move(Detail)};
        }
        CarrierError Mapped = CarrierError::TransportFailure;
        if (ErrorCode == std::make_error_code(std::errc::operation_canceled))
        {
            Mapped = CarrierError::Cancelled;
        }
        else if (ErrorCode == std::make_error_code(std::errc::timed_out))
        {
            Mapped = CarrierError::Timeout;
        }
        else if (ErrorCode == std::make_error_code(std::errc::result_out_of_range))
        {
            Mapped = CarrierError::ProtocolFailure;
        }
        return CarrierFailure{Mapped, Preview::Error::None, ErrorCode, Stage, std::move(Detail)};
    }

    class HandshakeState final
    {
    public:
        explicit HandshakeState(const CarrierKind Kind) : Kind_(Kind)
        {
        }

        [[nodiscard]] auto Kind() const noexcept -> CarrierKind
        {
            return Kind_;
        }

        [[nodiscard]] auto Current() const noexcept -> HandshakeStage
        {
            return Stage_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto Advance(const HandshakeStage Expected,
                                   const HandshakeStage Next) noexcept -> bool
        {
            auto Value = Expected;
            return Stage_.compare_exchange_strong(
                Value, Next, std::memory_order_acq_rel, std::memory_order_acquire);
        }

        auto Reject(const CarrierError ErrorCode) noexcept -> void
        {
            Failure_.store(ErrorCode, std::memory_order_release);
            Stage_.store(ErrorCode == CarrierError::Cancelled ? HandshakeStage::Cancelled
                                                               : HandshakeStage::Rejected,
                         std::memory_order_release);
        }

        [[nodiscard]] auto Failure() const noexcept -> CarrierError
        {
            return Failure_.load(std::memory_order_acquire);
        }

    private:
        CarrierKind Kind_;
        std::atomic<HandshakeStage> Stage_{HandshakeStage::Idle};
        std::atomic<CarrierError> Failure_{CarrierError::None};
    };

    class ReplayBuffer final
    {
    public:
        ReplayBuffer() : Storage_(std::make_shared<const std::vector<std::byte>>())
        {
        }

        explicit ReplayBuffer(const std::span<const std::byte> Bytes)
            : Storage_(std::make_shared<const std::vector<std::byte>>(Bytes.begin(), Bytes.end()))
        {
        }

        [[nodiscard]] auto Data() const noexcept -> std::span<const std::byte>
        {
            return Storage_ ? std::span<const std::byte>(*Storage_) : std::span<const std::byte>{};
        }

        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return Storage_ ? Storage_->size() : 0;
        }

        [[nodiscard]] auto Empty() const noexcept -> bool
        {
            return Size() == 0;
        }

        [[nodiscard]] auto Wrap(Preview::SharedTransmission Transport) const
            -> Preview::SharedTransmission
        {
            return Preview::Transport::WrapWithPreview(std::move(Transport), Data());
        }

    private:
        std::shared_ptr<const std::vector<std::byte>> Storage_;
    };

    struct CarrierMetadata final
    {
        CarrierKind Kind{CarrierKind::Reality};
        bool WireComplete{false};
        std::size_t ReplayBytes{0};
        std::string Detail;
    };

    struct CarrierAcceptRequest final
    {
        Preview::SharedTransmission Transport;
        ReplayBuffer Replay;
        std::shared_ptr<HandshakeState> State;
    };

    struct CarrierAcceptResult final
    {
        CarrierFailure Failure{};
        Preview::SharedTransmission Transport;
        ReplayBuffer Replay;
        CarrierMetadata Metadata{};
        std::shared_ptr<HandshakeState> State;

        [[nodiscard]] auto Accepted() const noexcept -> bool
        {
            return Failure.Code == CarrierError::None &&
                   Metadata.WireComplete && static_cast<bool>(Transport);
        }

        [[nodiscard]] auto ReplayedTransport() const -> Preview::SharedTransmission
        {
            return Replay.Wrap(Transport);
        }

        [[nodiscard]] static auto Accepted(Preview::SharedTransmission Transport,
                                           ReplayBuffer Replay,
                                           CarrierMetadata Metadata,
                                           std::shared_ptr<HandshakeState> State)
            -> CarrierAcceptResult
        {
            return CarrierAcceptResult{
                {}, std::move(Transport), std::move(Replay), std::move(Metadata), std::move(State)};
        }

        [[nodiscard]] static auto Rejected(CarrierFailure Failure,
                                           Preview::SharedTransmission Transport,
                                           ReplayBuffer Replay,
                                           std::shared_ptr<HandshakeState> State)
            -> CarrierAcceptResult
        {
            return CarrierAcceptResult{
                std::move(Failure), std::move(Transport), std::move(Replay), {}, std::move(State)};
        }
    };

    class FacadeCarrier final
    {
    public:
        using AcceptHandler =
            std::function<Net::awaitable<CarrierAcceptResult>(CarrierAcceptRequest)>;

        [[nodiscard]] static auto Ready(CarrierKind Kind, AcceptHandler Handler) -> FacadeCarrier
        {
            return FacadeCarrier(Kind, true, {}, std::move(Handler));
        }

        [[nodiscard]] static auto Unavailable(CarrierKind Kind, std::string Blocker)
            -> FacadeCarrier
        {
            return FacadeCarrier(Kind, false, std::move(Blocker), {});
        }

        [[nodiscard]] auto Kind() const noexcept -> CarrierKind
        {
            return Kind_;
        }

        [[nodiscard]] auto WireReady() const noexcept -> bool
        {
            return WireReady_;
        }

        [[nodiscard]] auto Blocker() const noexcept -> std::string_view
        {
            return Blocker_;
        }

        [[nodiscard]] auto Accept(CarrierAcceptRequest Request) const
            -> Net::awaitable<CarrierAcceptResult>
        {
            auto Original = Request.Transport;
            auto Replay = Request.Replay;
            auto State = std::make_shared<HandshakeState>(Kind_);
            Request.State = State;

            if (!Original)
            {
                co_return Reject(MapError(Preview::Error::NotOpen,
                                          HandshakeStage::Idle,
                                          "carrier admission received no transport"),
                                 {}, std::move(Replay), std::move(State));
            }
            if (!WireReady_)
            {
                co_return Reject(CarrierFailure{CarrierError::WireUnavailable,
                                                Preview::Error::NotSupported,
                                                {},
                                                HandshakeStage::Idle,
                                                Blocker_},
                                 std::move(Original), std::move(Replay), std::move(State));
            }
            if (!Handler_)
            {
                co_return Reject(CarrierFailure{CarrierError::MissingCallback,
                                                Preview::Error::NotSupported,
                                                {},
                                                HandshakeStage::Idle,
                                                "carrier callback is required for a ready facade"},
                                 std::move(Original), std::move(Replay), std::move(State));
            }
            if (!State->Advance(HandshakeStage::Idle, HandshakeStage::Preparing))
            {
                co_return Reject(CarrierFailure{CarrierError::InvalidState,
                                                Preview::Error::ProtocolError,
                                                {},
                                                HandshakeStage::Idle,
                                                "carrier state did not enter preparing"},
                                 std::move(Original), std::move(Replay), std::move(State));
            }

            CarrierAcceptResult Result;
            try
            {
                Result = co_await Handler_(std::move(Request));
            }
            catch (const std::system_error &Error)
            {
                co_return Reject(MapError(Error.code(), HandshakeStage::Preparing),
                                 std::move(Original), std::move(Replay), std::move(State));
            }
            catch (const std::exception &Error)
            {
                co_return Reject(CarrierFailure{CarrierError::ProtocolFailure,
                                                Preview::Error::ProtocolError,
                                                {},
                                                HandshakeStage::Preparing,
                                                Error.what()},
                                 std::move(Original), std::move(Replay), std::move(State));
            }

            if (Result.Failure.Code == CarrierError::None)
            {
                const auto ReplayPreserved = SameReplay(Replay, Result.Replay);
                const auto MetadataConsistent = Result.Metadata.Kind == Kind_ &&
                                                Result.Metadata.ReplayBytes == Result.Replay.Size();
                if (!Result.Transport || !Result.Metadata.WireComplete || !ReplayPreserved ||
                    !MetadataConsistent ||
                    !State->Advance(HandshakeStage::Preparing, HandshakeStage::Committing) ||
                    !State->Advance(HandshakeStage::Committing, HandshakeStage::Accepted))
                {
                    co_return Reject(CarrierFailure{CarrierError::InvalidResult,
                                                    Preview::Error::ProtocolError,
                                                    {},
                                                    HandshakeStage::Committing,
                                                    "successful carrier result lacks completed wire ownership"},
                                     std::move(Original), std::move(Replay), std::move(State));
                }
                Result.State = std::move(State);
                co_return Result;
            }

            if (!Result.Transport)
            {
                Result.Transport = std::move(Original);
            }
            if (Result.Replay.Empty() && !Replay.Empty())
            {
                Result.Replay = Replay;
            }
            Result.Metadata.WireComplete = false;
            Result.State = State;
            State->Reject(Result.Failure.Code);
            co_return Result;
        }

    private:
        FacadeCarrier(CarrierKind Kind, bool WireReady, std::string Blocker, AcceptHandler Handler)
            : Kind_(Kind), WireReady_(WireReady), Blocker_(std::move(Blocker)),
              Handler_(std::move(Handler))
        {
        }

        [[nodiscard]] static auto Reject(CarrierFailure Failure,
                                         Preview::SharedTransmission Transport,
                                         ReplayBuffer Replay,
                                         std::shared_ptr<HandshakeState> State)
            -> CarrierAcceptResult
        {
            if (State)
            {
                State->Reject(Failure.Code);
            }
            return CarrierAcceptResult::Rejected(
                std::move(Failure), std::move(Transport), std::move(Replay), std::move(State));
        }

        [[nodiscard]] static auto SameReplay(const ReplayBuffer &Left,
                                             const ReplayBuffer &Right) noexcept -> bool
        {
            return Left.Size() == Right.Size() &&
                   std::equal(Left.Data().begin(), Left.Data().end(), Right.Data().begin());
        }

        CarrierKind Kind_;
        bool WireReady_{false};
        std::string Blocker_;
        AcceptHandler Handler_;
    };

} // namespace Preview::Composition::Carrier

namespace std
{
    template <>
    struct is_error_code_enum<Preview::Composition::Carrier::CarrierError> : true_type
    {
    };
} // namespace std
