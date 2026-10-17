/** @file PayloadBudget.hpp
 * @brief 逻辑有效载荷发送前授权与部分成功结算，不计封装和重传。
 */
#pragma once
#include <Preview/Foundation/Fault/Failure.hpp>
#include <boost/asio/awaitable.hpp>
#include <cstdint>
#include <expected>
#include <memory>
#include <utility>
#include <algorithm>

namespace Preview::Contract
{
    enum class PayloadDirection : std::uint8_t { Upload, Download };

    /** @brief 每个调用最多申请一个有界 I/O；数据报要求完整信用，不允许截断。 */
    struct PayloadRequest final
    {
        std::uint64_t Bytes{0};
        PayloadDirection Direction{PayloadDirection::Upload};
        bool Datagram{false};
    };

    /** @brief 仅同步原子结算，不访问数据库或关闭连接；最后拥有者保活信用。 */
    class PayloadSettlement
    {
    public:
        virtual ~PayloadSettlement() = default;
        virtual auto Complete(std::uint64_t Granted, std::uint64_t Transferred) noexcept -> void = 0;
    };

    /** @brief move-only I/O 授权，成功量只能提交一次；未提交析构按零成功归还预约内信用。 */
    class PayloadPermit final
    {
    public:
        PayloadPermit() = default;
        PayloadPermit(std::uint64_t Bytes, std::shared_ptr<PayloadSettlement> Owner = {}) noexcept
            : Bytes_(Bytes), Owner_(std::move(Owner)) {}
        PayloadPermit(const PayloadPermit&) = delete;
        auto operator=(const PayloadPermit&) -> PayloadPermit& = delete;
        PayloadPermit(PayloadPermit&& Other) noexcept
            : Bytes_(std::exchange(Other.Bytes_, 0)), Owner_(std::move(Other.Owner_)) {}
        auto operator=(PayloadPermit&& Other) noexcept -> PayloadPermit&
        {
            if (this != &Other)
            {
                Finish(0);
                Bytes_ = std::exchange(Other.Bytes_, 0);
                Owner_ = std::move(Other.Owner_);
            }
            return *this;
        }
        ~PayloadPermit() { Finish(0); }
        [[nodiscard]] auto Bytes() const noexcept -> std::uint64_t { return Bytes_; }
        /** @brief 超过授权的成功量为调用者契约错误；仍最多按授权量保守记账。 */
        auto Finish(const std::uint64_t Transferred) noexcept -> void
        {
            if (Owner_) Owner_->Complete(Bytes_, (std::min)(Transferred, Bytes_));
            Owner_.reset();
            Bytes_ = 0;
        }
    private:
        std::uint64_t Bytes_{0};
        std::shared_ptr<PayloadSettlement> Owner_;
    };

    /**
     * @brief 跨 Worker 的账户数据面能力；输入拥有值，等待可取消，结果回调用 executor。
     * @details 先持久预约后授权。限额或存储失败返回完整 Failure；最后关闭者仍是 relay。
     */
    class PayloadBudget
    {
    public:
        virtual ~PayloadBudget() = default;
        [[nodiscard]] virtual auto Acquire(PayloadRequest Request)
            -> boost::asio::awaitable<std::expected<PayloadPermit, Fault::Failure>> = 0;
    };
}
