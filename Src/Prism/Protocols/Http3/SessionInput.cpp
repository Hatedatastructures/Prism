/**
 * @file SessionInput.cpp
 * @brief HTTP/3 输入流喂入和 payload 所有权职责。
 */


#include <Prism/Protocols/Http3/Detail/SessionContract.hpp>

#include <chrono>
#include <cstdint>
#include <utility>

namespace Prism::Http3::Detail
{

    [[nodiscard]] auto Session::NowTstamp() -> std::uint64_t
    {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                                                std::chrono::steady_clock::now().time_since_epoch())
                                                .count());
    }

    auto Session::Feed(
        const std::int64_t StreamId,
        const std::span<const std::byte> Data,
        const bool Fin) -> Fault::Code
    {
        if (!Conn_)
        {
            return Fault::Code::ProtocolError;
        }
        const auto FinValue = static_cast<int>(Fin);
        const auto Result = nghttp3_conn_read_stream2(
            Conn_, StreamId, AsU8(Data).data(), Data.size(), FinValue, NowTstamp());
        if (Result < 0)
        {
            return Fault::Code::ProtocolError;
        }
        return Fault::Code::Success;
    }

    auto Session::Feed(
        const std::int64_t StreamId,
        std::vector<std::byte> Data,
        const bool Fin) -> Fault::Code
    {
        ActiveData_ = std::move(Data);
        ActiveDataPointer_ = nullptr;
        if (!ActiveData_.empty())
        {
            ActiveDataPointer_ = ActiveData_.data();
        }
        const auto Result = Feed(
            StreamId,
            std::span<const std::byte>(ActiveData_.data(), ActiveData_.size()),
            Fin);
        ActiveData_.clear();
        ActiveDataPointer_ = nullptr;
        return Result;
    }

} // namespace Prism::Http3::Detail
