/** @file RawDatagramIngress.hpp @brief 原始数据报所有权交接；不依赖 Boundary 分类。 */
#pragma once
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Generation/Lifetime.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>
#include <span>
#include <vector>
#include <cstdint>
#include <memory>
#include <expected>
#include <utility>
namespace Preview::Contract
{
    struct DatagramView final
    {
        std::span<const std::byte> Payload;
        boost::asio::ip::udp::endpoint Peer;
        std::uint64_t Sequence{0};
    };
    struct DatagramPacket final
    {
        std::vector<std::byte> Payload;
        boost::asio::ip::udp::endpoint Peer;
        std::uint64_t Sequence{0};
        Preview::Foundation::GenerationUseLease GenerationUse;
    };
    /** @brief Matches 严格借用到返回且不取租约；Consume 接管载荷，协议拥有 peer/egress。
     * @details Close 封止并取消协议 I/O，Drain 等待退栈；公共入口 socket 始终由 Boundary 关闭。
     * 数据报无半关闭；操作在 binding executor 驱动，Close 可从任意线程发起。
     */
    class RawDatagramIngress
    {
    public:
        virtual ~RawDatagramIngress() = default;
        [[nodiscard]] virtual auto Matches(DatagramView Packet) const -> bool = 0;
        /** @brief 只匹配本 binding 已有的 datagram association；不得创建新 association。 */
        [[nodiscard]] virtual auto MatchesExistingAssociation(DatagramView Packet) const -> bool = 0;
        /** @brief 是否仍有已建立的 association 应留在后续 generation 的路由快照中。 */
        [[nodiscard]] virtual auto HasActiveAssociations() const noexcept -> bool = 0;
        virtual auto Consume(DatagramPacket Packet) -> void = 0;
        virtual auto Close() noexcept -> void = 0;
        /** @brief 等待协议拥有的任务实际退栈；失败保留首因与仍在途 owner。 */
        [[nodiscard]] virtual auto Drain()
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>> = 0;
    };

    /** @brief 单一 generation 的只读 raw ingress binding 快照及独立活动使用计数。 */
    class RawDatagramIngressSnapshot final
    {
    public:
        struct Binding final
        {
            std::shared_ptr<RawDatagramIngress> Owner;
            std::shared_ptr<Preview::Foundation::GenerationUseState> UseState;

            [[nodiscard]] auto AcquireUse() const
                -> std::expected<Preview::Foundation::GenerationUseLease, Preview::Fault::Failure>
            {
                if (!UseState)
                {
                    return std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                }
                return UseState->Acquire();
            }
        };

        struct Options final
        {
            Preview::GenerationId Generation{};
            std::shared_ptr<Preview::Foundation::GenerationUseState> UseState;
            std::vector<Binding> Current;
            std::vector<Binding> Retired;
        };

        explicit RawDatagramIngressSnapshot(Options OptionsValue)
            : Generation_(OptionsValue.Generation),
              UseState_(std::move(OptionsValue.UseState)),
              Current_(std::move(OptionsValue.Current)),
              Retired_(std::move(OptionsValue.Retired))
        {
        }

        [[nodiscard]] auto Generation() const noexcept -> Preview::GenerationId
        {
            return Generation_;
        }

        /** @brief 冷路径读取 generation 活动预约 owner 身份；不取得、不复制活动预约。 */
        [[nodiscard]] auto UseStateOwner() const noexcept
            -> const std::shared_ptr<Preview::Foundation::GenerationUseState> &
        {
            return UseState_;
        }

        [[nodiscard]] auto AcquireUse() const
            -> std::expected<Preview::Foundation::GenerationUseLease, Preview::Fault::Failure>
        {
            if (!UseState_)
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            return UseState_->Acquire();
        }

        [[nodiscard]] auto Bindings() const noexcept
            -> std::span<const Binding>
        {
            return Current_;
        }

        [[nodiscard]] auto RetiredBindings() const noexcept -> std::span<const Binding>
        {
            return Retired_;
        }

        [[nodiscard]] auto OutstandingUses() const noexcept -> std::uint64_t
        {
            if (!UseState_)
            {
                return 0U;
            }
            return UseState_->Outstanding();
        }

    private:
        const Preview::GenerationId Generation_;
        const std::shared_ptr<Preview::Foundation::GenerationUseState> UseState_;
        const std::vector<Binding> Current_;
        const std::vector<Binding> Retired_;
    };
}
