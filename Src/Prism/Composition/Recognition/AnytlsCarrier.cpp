/** @file AnytlsCarrier.cpp @brief Native TLS + AnyTLS Recognition adapter 实现。 */

#include <Prism/Composition/Recognition/AnytlsCarrier.hpp>
#include <Prism/Composition/Recognition/CandidateFactory.hpp>
#include <Prism/Composition/Recognition/LayeredCandidateFactory.hpp>

#include <Prism/Transport/NativeTls.hpp>

#include <utility>

namespace Prism::Composition::Recognition
{

    auto NativeTlsCarrier::Run(Request Value) -> Net::awaitable<Core::CarrierAcceptResult>
    {
        Core::CarrierAcceptResult Result;
        Result.Metadata.Carrier = "native";
        if (!Value.Context)
        {
            Result.Code = Prism::Fault::Code::NotSupported;
            Result.Transport = std::move(Value.Inbound);
            co_return Result;
        }
        const auto TlsResult = co_await Prism::Transport::UpgradeNativeTls(
            Prism::Transport::NativeTlsRequest{
                std::move(Value.Inbound), Value.Context, Value.Timeout, std::move(Value.Bytes)});
        Result.Code = TlsResult.Failure.Code;
        Result.Transport = std::move(TlsResult.Transport);
        Result.NativeError = TlsResult.Failure.Native;
        if (Result.Code == Prism::Fault::Code::Success && !TlsResult.Attempted)
        {
            Result.Code = Prism::Fault::Code::TlsHsfail;
        }
        co_return Result;
    }

    auto NativeTlsCarrier::operator()(Core::CarrierAcceptInput Input) const
        -> Net::awaitable<Core::CarrierAcceptResult>
    {
        return Run(Request{std::move(Input.Inbound), Context, Timeout, std::move(Input.Bytes)});
    }

    auto MakeNativeTlsCarrier(std::shared_ptr<Net::ssl::context> Context,
        const std::chrono::steady_clock::duration Timeout) -> CarrierAcceptFn
    {
        return CarrierAcceptFn{NativeTlsCarrier{std::move(Context), Timeout}};
    }

    auto MakeNativeTlsAnytlsCandidate(AnytlsCarrierOptions Options) -> CandidateBinding
    {
        TlsCandidateOptions Outer;
        Outer.Id = Options.Candidate.Id;
        Outer.Name = Options.Candidate.Name;
        Outer.Scheme = "native";
        Outer.ServerNames = std::move(Options.ServerNames);
        Outer.Alpn = std::move(Options.Alpn);
        Outer.Fallback = Options.Candidate.Fallback;
        Outer.Carrier = TlsCarrier::Native;

        auto Inner = CandidateFactory::MakeAnytls(
            std::move(Options.Candidate), std::move(Options.Config));
        auto Result = LayeredCandidateFactory::Make(
            std::move(Outer),
            MakeNativeTlsCarrier(std::move(Options.NativeTls), Options.Timeout),
            std::move(Inner));
        Result.Spec.RequiresAuthentication = true;
        return Result;
    }

} // namespace Prism::Composition::Recognition
