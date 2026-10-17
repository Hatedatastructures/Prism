/** @file MuxRootCloseTestSupport.hpp @brief Mux RootSession 生命周期 fixture。 */
#pragma once

#include <memory>

#include <Preview/Protocols/Mux/Detail/Root/RootSession.hpp>

namespace Preview::Mux::Testing
{
    class RootSessionStateFixture final
    {
    public:
        [[nodiscard]] static auto State(const std::shared_ptr<Detail::RootSession> &Root)
            -> std::shared_ptr<Detail::RootState>
        {
            return Root->State_;
        }

        /** @brief 暴露 H2 Run 结果分类，测试关闭取消与显式取消的首因边界。 */
        static auto RecordHttp2RunFailure(
            const std::shared_ptr<Detail::RootState> &State,
            const Preview::Fault::Failure Failure) noexcept -> void
        {
            Detail::RecordHttp2RunFailure(State, Failure);
        }

        [[nodiscard]] static auto CreateSession(
            const std::shared_ptr<Detail::RootState> &State)
            -> std::shared_ptr<Detail::RootSession>
        {
            return std::shared_ptr<Detail::RootSession>(new Detail::RootSession(
                State, std::make_shared<Detail::RootRegistryNode>()));
        }
    };
}
