/**
 * @file Dgram.cpp
 * @brief TrustTunnel 数据报传输 facade 与私有状态实现。
 */

#include <Prism/Protocols/Trusttunnel/TransportTypes.hpp>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/ForwardedActivity.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Trusttunnel
{
    struct Dgram::SendRequest final
    {
        std::string_view Host;
        std::uint16_t Port;
        std::span<const std::uint8_t> Payload;
    };

    struct Dgram::ReceiveRequest final
    {
        std::string *Host;
        std::uint16_t *Port;
        std::vector<std::uint8_t> *Payload;
    };

    struct Dgram::State final
    {
        explicit State(SharedTransmission Value)
            : NextLayer(std::move(Value))
        {
        }

        SharedTransmission NextLayer;
        std::shared_ptr<Detail::ForwardedActivity> Activity;
        std::optional<Prism::Fault::Failure> PendingReadFailure;
    };

    Dgram::Dgram(DgramRequest Request)
        : Prism::Transmission(Request.Upstream->Executor()),
          State_(std::make_shared<State>(std::move(Request.Upstream)))
    {
        State_->Activity = std::make_shared<Detail::ForwardedActivity>(
            Prism::Transmission::Activity(), State_->NextLayer->Activity(), CloseReceipt());
    }

    Dgram::~Dgram() = default;

    auto Dgram::Create(DgramRequest Request)
        -> std::expected<std::shared_ptr<Dgram>, Prism::Fault::Failure>
    {
        if (!Request.Upstream)
        {
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        return std::shared_ptr<Dgram>(new Dgram(std::move(Request)));
    }

    auto Dgram::Executor() const -> ExecutorType
    {
        if (!State_->NextLayer) return {};
        return State_->NextLayer->Executor();
    }

    auto Dgram::Activity() const noexcept
        -> std::shared_ptr<Prism::Contract::CarrierActivity>
    {
        return State_->Activity;
    }

    auto Dgram::RequiresExternalCloseReceipt() const noexcept -> bool
    {
        return true;
    }

    auto Dgram::TransportType() const noexcept -> Type
    {
        return Type::Udp;
    }

    auto Dgram::AsyncSendTo(
        std::string_view Host,
        std::uint16_t Port,
        std::span<const std::uint8_t> Payload)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        return SendToState(State_, SendRequest{Host, Port, Payload});
    }

    auto Dgram::SendToState(
        std::shared_ptr<State> Value,
        SendRequest Request)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (!Value->NextLayer)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        if (Request.Host.size() > std::numeric_limits<std::uint8_t>::max())
        {
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        }

        std::vector<std::uint8_t> Wire;
        Wire.reserve(1 + Request.Host.size() + 2 + Request.Payload.size());
        Wire.push_back(static_cast<std::uint8_t>(Request.Host.size()));
        Wire.insert(Wire.end(), Request.Host.begin(), Request.Host.end());
        Wire.push_back(static_cast<std::uint8_t>(Request.Port >> 8));
        Wire.push_back(static_cast<std::uint8_t>(Request.Port & 0xFF));
        Wire.insert(Wire.end(), Request.Payload.begin(), Request.Payload.end());

        std::size_t Done = 0;
        while (Done < Wire.size())
        {
            const auto Part = co_await Value->NextLayer->WriteSome(
                AsBytes(std::span<const std::uint8_t>(Wire)).subspan(Done));
            const auto N = Part.Bytes;
            if (N > Wire.size() - Done)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            Done += N;
            if (Part.Failure.Failed()) co_return std::unexpected(Part.Failure);
            if (N == 0)
            {
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::WouldBlock});
            }
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto Dgram::AsyncReceiveFrom(
        std::string &Host,
        std::uint16_t &Port,
        std::vector<std::uint8_t> &Payload)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        return ReceiveFromState(State_, ReceiveRequest{&Host, &Port, &Payload});
    }

    auto Dgram::ReceiveFromState(
        std::shared_ptr<State> Value,
        ReceiveRequest Request)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (!Value->NextLayer)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        Request.Host->clear();
        *Request.Port = 0;
        Request.Payload->clear();
        if (Value->PendingReadFailure)
        {
            co_return std::unexpected(*Value->PendingReadFailure);
        }

        std::array<std::uint8_t, 1> HostLength{};
        auto Read = co_await ReadExact(Value, HostLength);
        if (!Read) co_return std::unexpected(Read.error());
        std::vector<std::uint8_t> HostBuf(HostLength[0]);
        Read = co_await ReadExact(Value, HostBuf);
        if (!Read) co_return std::unexpected(Read.error());
        Request.Host->assign(reinterpret_cast<const char *>(HostBuf.data()), HostBuf.size());

        std::array<std::uint8_t, 2> PortBuf{};
        Read = co_await ReadExact(Value, PortBuf);
        if (!Read) co_return std::unexpected(Read.error());
        *Request.Port = static_cast<std::uint16_t>(PortBuf[0]) << 8 | PortBuf[1];
        if (Value->PendingReadFailure)
        {
            co_return std::unexpected(*Value->PendingReadFailure);
        }

        std::array<std::uint8_t, 512> Chunk{};
        const auto Part = co_await Value->NextLayer->ReadSome(
            AsBytes(std::span<std::uint8_t>(Chunk)));
        const auto N = Part.Bytes;
        if (N > Chunk.size())
        {
            Value->PendingReadFailure =
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument};
            co_return std::unexpected(*Value->PendingReadFailure);
        }
        Request.Payload->assign(
            Chunk.begin(), Chunk.begin() + static_cast<std::ptrdiff_t>(N));
        if (Part.Failure.Failed())
        {
            Value->PendingReadFailure = Part.Failure;
            if (N == 0U) co_return std::unexpected(*Value->PendingReadFailure);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        if (N == 0)
        {
            Value->PendingReadFailure = Prism::Fault::Failure{Prism::Fault::Code::Eof};
            co_return std::unexpected(*Value->PendingReadFailure);
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto Dgram::ReadExact(std::shared_ptr<State> Value, std::span<std::uint8_t> Buffer)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (Buffer.empty()) co_return std::expected<void, Prism::Fault::Failure>{};
        if (Value->PendingReadFailure)
        {
            co_return std::unexpected(*Value->PendingReadFailure);
        }
        std::size_t Done = 0;
        while (Done < Buffer.size())
        {
            const auto Part = co_await Value->NextLayer->ReadSome(
                AsBytes(Buffer.subspan(Done)));
            if (Part.Bytes > Buffer.size() - Done)
            {
                Value->PendingReadFailure =
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument};
                co_return std::unexpected(*Value->PendingReadFailure);
            }
            Done += Part.Bytes;
            if (Part.Failure.Failed())
            {
                Value->PendingReadFailure = Part.Failure;
                if (Done == Buffer.size())
                {
                    co_return std::expected<void, Prism::Fault::Failure>{};
                }
                co_return std::unexpected(*Value->PendingReadFailure);
            }
            if (Part.Bytes == 0)
            {
                Value->PendingReadFailure = Prism::Fault::Failure{Prism::Fault::Code::Eof};
                co_return std::unexpected(*Value->PendingReadFailure);
            }
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto Dgram::StartRead(std::span<std::byte> Buffer, Completion Handler) -> void
    {
        if (!State_->NextLayer)
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler),
                Prism::IoResult{0, Prism::Fault::FromNative(make_error_code(Error::NotOpen))});
            return;
        }
        if (State_->PendingReadFailure && !Buffer.empty())
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), Prism::IoResult{0, *State_->PendingReadFailure});
            return;
        }
        State_->NextLayer->ReadSome(Buffer, std::move(Handler));
    }

    auto Dgram::StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void
    {
        if (!State_->NextLayer)
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler),
                Prism::IoResult{0, Prism::Fault::FromNative(make_error_code(Error::NotOpen))});
            return;
        }
        State_->NextLayer->WriteSome(Buffer, std::move(Handler));
    }

    auto Dgram::StartWriteShutdown(Completion Handler) -> void
    {
        if (!State_->NextLayer)
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler),
                Prism::IoResult{0, Prism::Fault::FromNative(make_error_code(Error::NotOpen))});
            return;
        }
        State_->NextLayer->WriteShutdown(std::move(Handler));
    }

    auto Dgram::OnClose() -> ControlResult
    {
        const auto Result = State_->NextLayer ? State_->NextLayer->Close() : ControlResult{};
        State_->Activity->Seal();
        return Result;
    }

    auto Dgram::OnCancel() -> ControlResult
    {
        if (!State_->NextLayer) return {};
        return State_->NextLayer->Cancel();
    }

    auto Dgram::NextLayer() noexcept -> Prism::Transmission *
    {
        return State_->NextLayer.get();
    }

    auto Dgram::NextLayer() const noexcept -> const Prism::Transmission *
    {
        return State_->NextLayer.get();
    }

    auto Dgram::Release() -> SharedTransmission
    {
        State_->Activity->ReleaseChild();
        return std::move(State_->NextLayer);
    }

    auto Dgram::Stream() const noexcept -> SharedTransmission
    {
        return State_->NextLayer;
    }

    static_assert(Prism::TransmissionLike<Dgram>);
}
