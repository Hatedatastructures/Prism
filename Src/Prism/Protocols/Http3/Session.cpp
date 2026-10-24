/**
 * @file Session.cpp
 * @brief HTTP/3 帧会话的公开 owning façade 实现。
 */
#include <Prism/Protocols/Http3/Session.hpp>
#include <Prism/Protocols/Http3/Detail/SessionContract.hpp>

#include <utility>

namespace Prism::Http3
{
    Session::Session(const Prism::Memory::ResourcePointer Resource)
        : Engine_(std::make_unique<Detail::Session>(Resource))
    {
    }

    Session::~Session() noexcept = default;

    auto Session::Init(std::function<std::int64_t()> OpenUniStream) -> bool
    {
        return Engine_->Init(std::move(OpenUniStream));
    }

    auto Session::Feed(
        const std::int64_t StreamId,
        const std::span<const std::byte> Data,
        const bool Fin) -> Fault::Code
    {
        return Engine_->Feed(StreamId, Data, Fin);
    }

    auto Session::Feed(
        const std::int64_t StreamId,
        std::vector<std::byte> Data,
        const bool Fin) -> Fault::Code
    {
        return Engine_->Feed(StreamId, std::move(Data), Fin);
    }

    auto Session::TakeEvent() -> std::optional<ServerEvent>
    {
        return Engine_->TakeEvent();
    }

    auto Session::PumpOutput(std::vector<OutPacket> &Output) -> bool
    {
        return Engine_->PumpOutput(Output);
    }

    auto Session::AddWriteOffset(const std::int64_t StreamId, const std::size_t Written) -> void
    {
        Engine_->AddWriteOffset(StreamId, Written);
    }

    auto Session::SubmitResponse(ResponseHead Response) -> Fault::Code
    {
        return Engine_->SubmitResponse(std::move(Response));
    }

    auto Session::Close() noexcept -> void
    {
        Engine_->Close();
    }

    auto Session::IsOpen() const noexcept -> bool
    {
        return Engine_->IsOpen();
    }

    auto Session::Native() const noexcept -> bool
    {
        return Engine_->IsOpen();
    }
}
