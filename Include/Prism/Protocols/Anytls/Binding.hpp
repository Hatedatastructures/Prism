/** @file Binding.hpp @brief AnyTLS 的冷密码 wire 配置与 ingress 服务绑定。 */
#pragma once
#include <Prism/Account/Credential.hpp>
#include <Prism/Contract/Ingress/ProviderFailure.hpp>
#include <Prism/Contract/Services/Authentication.hpp>
#include <Prism/Contract/Services/Stream.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Anytls/IngressFactory.hpp>

#include <boost/asio/awaitable.hpp>

#include <atomic>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace Prism::Anytls
{
    /** @brief 将 AnyTLS 密码封装为正式 password 凭据。 */
    [[nodiscard]] auto PrepareAccountCredential(std::string_view Value) -> Prism::Account::Credential;

    struct PreparedBinding final
    {
        std::string Instance;
        IngressOptions Options;
    };

    /**
     * @brief AnyTLS 冷配置与候选投影的 provider owner。
     * @details 派生候选接管投影得到的值并按自身 generation 生命周期释放；本 owner 的回执
     *          只覆盖其冷配置材料和候选构造中的投影租约。
     */
    class Binding final
    {
        struct State final
        {
            explicit State(IngressOptions Value) : Options(std::move(Value)) {}
            std::atomic<std::uint64_t> ProjectionGate{0U};
            std::atomic<bool> DrainInProgress{false};
            std::atomic<bool> Retired{false};
            std::optional<IngressOptions> Options;
        };

    public:
        /** @brief 构造持有配置材料的唯一 AnyTLS provider owner。 */
        explicit Binding(IngressOptions Value);

        Binding(const Binding&) = delete;
        auto operator=(const Binding&) -> Binding& = delete;

        /** @brief 封止新的候选投影；已取得的投影租约仍可完成当前同步构造。 */
        auto Close() const noexcept -> void;

        /** @brief 保活一次同步候选构造，直至派生 ingress owner 已建立。 */
        class Projection final
        {
        public:
            Projection(const Projection&) = delete;
            auto operator=(const Projection&) -> Projection& = delete;
            Projection(Projection&& Other) noexcept;
            auto operator=(Projection&& Other) noexcept -> Projection&;
            ~Projection();

            [[nodiscard]] auto Options() const noexcept -> const IngressOptions&
            {
                return *State_->Options;
            }

        private:
            friend class Binding;
            explicit Projection(std::shared_ptr<State> Value) noexcept
                : State_(std::move(Value))
            {
            }
            auto Release() noexcept -> void;
            std::shared_ptr<State> State_;
        };

        /** @brief 封止后不再创建候选；租约存活期间 Drain 返回 Blocked 且保留配置。 */
        [[nodiscard]] auto BeginProjection() const noexcept -> std::optional<Projection>;

        /** @brief 释放本 provider 的冷配置；并发投影未退出时保留材料并报告 Blocked。 */
        [[nodiscard]] auto Drain() const
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;

        [[nodiscard]] auto IsRetired() const noexcept -> bool;

        /** @brief 返回独立持久失败回执；活动投影导致的 Blocked 仅属于本轮 attempt。 */
        [[nodiscard]] auto DrainFailure() const noexcept -> Prism::Fault::Failure
        {
            return {};
        }

    private:
        static constexpr std::uint64_t ClosedBit = std::uint64_t{1} << 63U;
        static constexpr std::uint64_t ProjectionMask = ClosedBit - 1U;
        std::shared_ptr<State> State_;
    };

    /** @brief 校验认证与 stream 服务并准备 AnyTLS ingress 选项。 */
    [[nodiscard]] auto PrepareProviderBinding(
        std::string Instance,
        Prism::Contract::AuthenticationServices Authentication,
        Prism::Contract::StreamServices Streams)
        -> std::expected<PreparedBinding, Prism::Contract::ProviderFailure>;

    /** @brief 以已准备选项建立唯一 provider binding owner。 */
    [[nodiscard]] auto BindProvider(PreparedBinding Prepared) -> std::shared_ptr<const Binding>;
}
