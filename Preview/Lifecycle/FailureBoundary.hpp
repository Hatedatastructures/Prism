/**
 * @file FailureBoundary.hpp
 * @brief 协程异常的单一收口边界
 * @details 业务协程异常被转换为 exception_ptr 并交给调用方；异常处理器
 *          自身的异常不会穿过 detached completion handler。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <exception>
#include <functional>
#include <utility>

namespace Preview::Lifecycle
{

    namespace Net = boost::asio;

    class FailureBoundary final
    {
    public:
        using Handler = std::function<void(std::exception_ptr)>;

        explicit FailureBoundary(Handler OnFailure = {}) : OnFailure_(std::move(OnFailure)) {}

        /**
         * @brief 执行一个 awaitable，并将异常交给 failure handler
         */
        template <typename Awaitable>
        [[nodiscard]] auto Run(Awaitable Operation) const -> Net::awaitable<void>
        {
            return Execute(OnFailure_, std::move(Operation));
        }

        template <typename Awaitable>
        [[nodiscard]] static auto Execute(Handler OnFailure, Awaitable Operation) -> Net::awaitable<void>
        {
            try
            {
                co_await std::move(Operation);
            }
            catch (...)
            {
                const auto Failure = std::current_exception();
                try
                {
                    if (OnFailure)
                    {
                        OnFailure(Failure);
                    }
                }
                catch (...)
                {
                }
            }
        }

    private:
        Handler OnFailure_;
    };

} // namespace Preview::Lifecycle
