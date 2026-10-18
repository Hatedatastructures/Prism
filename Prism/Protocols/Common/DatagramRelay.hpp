/**
 * @file DatagramRelay.hpp
 * @brief Trojan/Vmess 共用的类型化数据报会话前门。
 */
#pragma once

#include <Prism/Contract/Ingress/DatagramSession.hpp>
#include <Prism/Protocols/Common/DatagramRetirement.hpp>

#include <memory>
#include <expected>
#include <utility>

namespace Prism::Protocols
{
    /**
     * @brief 把协议 Wire 与配置转交给完整拥有数据面和退休状态的 state。
     * @details 外层仅实现稳定的 DatagramSession 契约；State 自持有 Run，
     *          并在其资源真实退休前由 Activity 与 ClosingStorage 保活。
     */
    template<class Wire>
    class DatagramRelay : public Prism::Contract::DatagramSession
    {
    public:
        using Options = DatagramRelayOptions;

        DatagramRelay(Wire Value, Options Configuration)
            : State_(std::make_shared<DatagramRetirement<Wire>>(
                  std::move(Value), std::move(Configuration))) {}

        DatagramRelay(const DatagramRelay&) = delete;
        auto operator=(const DatagramRelay&) -> DatagramRelay& = delete;

        /** @brief 启动唯一 Run；State 持有 coroutine 与全部交换资源到退栈。 */
        [[nodiscard]] auto Run()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            return State_->Run();
        }

        /** @brief 返回 Run 与 carrier 全层退出的同一生命周期能力。 */
        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        {
            return State_;
        }

        /** @brief 取消正在等待的 resolver、UDP I/O 与 carrier。 */
        auto Cancel() noexcept -> void override { State_->Cancel(); }
        /** @brief 请求最终关闭；实际释放只由 State 的 drain owner 确认。 */
        auto Close() noexcept -> void override { State_->Close(); }

    private:
        std::shared_ptr<DatagramRetirement<Wire>> State_;
    };
}
