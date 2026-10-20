/** @file Pad.cpp @brief 填充装饰器 owning graph 的冷装配实现。 */
#include <Prism/Transport/Pad.hpp>

#include <Prism/Transport/ActivityGroupFactory.hpp>
#include <Prism/Transport/Writer.hpp>

#include <memory>
#include <utility>
#include <vector>

namespace Prism::Transport
{
    PadTransport::PadTransport(SharedTransmission Inner, PadOptions Options)
        : Transmission(Inner->Executor()), Inner_(std::move(Inner)),
          Driver_(std::make_shared<Detail::PadDriver>(Inner_, Detail::PadDriver::Options{std::move(Options.Policy), std::move(Options.Random)})),
          Writer_(std::make_shared<Writer>(std::move(Options.Bytes), Driver_)),
          Activity_(MakeActivityGroup(Transmission::Activity(),
              std::vector<std::shared_ptr<Contract::CarrierActivity>>{Writer_->Activity()}))
    {
    }

    auto PadTransport::StartRead(std::span<std::byte> Buffer, Completion Handler) -> void
    {
        Inner_->ReadSome(Buffer, std::move(Handler));
    }

    auto PadTransport::StartWrite(
        std::span<const std::byte> Buffer, Completion Handler) -> void
    {
        Writer_->Write(Buffer, std::move(Handler));
    }

    auto PadTransport::StartWriteShutdown(Completion Handler) -> void
    {
        Writer_->WriteShutdown(std::move(Handler));
    }

    auto PadTransport::OnClose() -> ControlResult
    {
        return Writer_->Close();
    }

    auto PadTransport::OnCancel() -> ControlResult
    {
        return Writer_->Cancel();
    }
}
