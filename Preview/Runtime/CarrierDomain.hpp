/** @file CarrierDomain.hpp @brief 在移交载体前固定真实 executor 与完成源。 */
#pragma once
#include <Preview/Contract/Io/CarrierActivity.hpp>
#include <memory>
#include <utility>
namespace Preview::Runtime
{
    /** @brief 不拥有载体的准入前执行域证明；生产 owner 先创建本值，再移交 owning 输入。
     * @details 缺少 Activity 允许保留原 executor 的拒绝资源，但不能证明 I/O 完成。
     * 不得传入已移动的 Domain；调用者不得用当前线程 executor 冒充载体原域。
     */
    class CarrierDomain final
    {
    public:
        /** @brief 冷验证真实执行域；失败尚未接管任何载体，输入 owner 仍归生产方。 */
        [[nodiscard]] static auto Create(boost::asio::any_io_executor Executor,
            std::shared_ptr<Preview::Contract::CarrierActivity> Activity)
            -> std::expected<CarrierDomain, Preview::Fault::Failure>
        {
            if (!Executor) return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            if (Activity && Activity->Executor() != Executor)
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            return CarrierDomain(std::move(Executor), std::move(Activity));
        }
        /** @brief 复制已固定的真实 executor，原 context 由安装后的资源槽 pin。 */
        [[nodiscard]] auto Executor() const -> boost::asio::any_io_executor { return Executor_; }
        /** @brief 共享实际完成源；空值明确表示尚未接入 M12/协议真实 completion。 */
        [[nodiscard]] auto Activity() const -> std::shared_ptr<Preview::Contract::CarrierActivity> { return Activity_; }
    private:
        CarrierDomain(boost::asio::any_io_executor Executor, std::shared_ptr<Preview::Contract::CarrierActivity> Activity)
            : Executor_(std::move(Executor)), Activity_(std::move(Activity)) {}
        boost::asio::any_io_executor Executor_;
        std::shared_ptr<Preview::Contract::CarrierActivity> Activity_;
    };
}
