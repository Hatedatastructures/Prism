/** @file RealityCarrier.cpp @brief Reality server carrier adapter 实现。 */

#include <Prism/Composition/Recognition/Detail/CarrierRunners.hpp>
#include <Prism/Composition/Recognition/Detail/CarrierFailure.hpp>

#include <Prism/Protocols/Common/ExactIo.hpp>
#include <Prism/Protocols/Reality/CarrierPreparation.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace Prism::Composition::Recognition
{
    [[nodiscard]] auto RejectRealityAccept(
        Prism::SharedTransmission Inbound,
        Prism::Fault::Failure Cause) -> Net::awaitable<Core::CarrierAcceptResult>
    {
        Core::CarrierAcceptResult Result;
        Result.Metadata.Carrier = "reality";
        const auto Failure = co_await Detail::RetireCarrierInput(std::move(Inbound), Cause);
        Detail::SetCarrierFailure(Result, Failure);
        co_return Result;
    }

    [[nodiscard]] auto RunRealityServerAccept(
        Prism::Reality::PreparedConfig Config,
        Core::CarrierAcceptPreparedInput Input)
        -> Net::awaitable<Core::CarrierAcceptResult>
    {
        const auto Features = std::static_pointer_cast<const Core::ClientHelloFeatures>(
            std::move(Input.PreparedState));
        if (!Input.Inbound || !Features || !Features->HasX25519 ||
            Features->RawMessage.empty() || Features->RawRecord.empty() ||
            Features->ConsumedBytes != Features->RawRecord.size() || Config.ShortIds.empty())
        {
            co_return co_await RejectRealityAccept(
                std::move(Input.Inbound),
                Detail::FailureFromProtocolError(Prism::Error::ProtocolError));
        }

        std::vector<std::byte> ClientHello(Features->ConsumedBytes);
        std::size_t Offset = 0;
        while (Offset < ClientHello.size())
        {
            const auto Part = co_await Prism::Protocol::Common::ReadExactIo(
                Input.Inbound,
                std::span<std::uint8_t>(
                    reinterpret_cast<std::uint8_t *>(ClientHello.data() + Offset),
                    ClientHello.size() - Offset));
            const auto Read = Part.Bytes;
            if (Part.Failure.Failed())
            {
                co_return co_await RejectRealityAccept(std::move(Input.Inbound), Part.Failure);
            }
            Offset += Read;
        }
        const auto ExpectedRecord = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Features->RawRecord.data()),
            Features->RawRecord.size());
        if (!std::equal(ClientHello.begin(), ClientHello.end(),
                        ExpectedRecord.begin(), ExpectedRecord.end()))
        {
            co_return co_await RejectRealityAccept(
                std::move(Input.Inbound),
                Detail::FailureFromProtocolError(Prism::Error::BadMessage));
        }

        auto Accepted = co_await Prism::Reality::AcceptPrepared(
            Prism::Reality::PreparedRequest{
                Input.Inbound, std::move(Config),
                std::span<const std::uint8_t>(Features->Random),
                std::span<const std::uint8_t>(Features->SessionId),
                std::span<const std::uint8_t>(Features->X25519Key),
                std::span<const std::uint8_t>(Features->RawMessage), Features->ServerName});
        if (!Accepted)
        {
            Core::CarrierAcceptResult Result;
            Result.Metadata.Carrier = "reality";
            Detail::SetCarrierFailure(Result, Accepted.error());
            co_return Result;
        }

        Core::CarrierAcceptResult Result;
        Result.Metadata.Carrier = "reality";
        Result.Transport = std::move(*Accepted);
        co_return Result;
    }

    [[nodiscard]] auto MakeRealityServerAccept(
        Prism::Reality::PreparedConfig Config)
        -> CarrierAcceptPreparedFn
    {
        return [Config = std::move(Config)](Core::CarrierAcceptPreparedInput Input)
            -> Net::awaitable<Core::CarrierAcceptResult>
        {
            co_return co_await RunRealityServerAccept(Config, std::move(Input));
        };
    }
} // namespace Prism::Composition::Recognition
