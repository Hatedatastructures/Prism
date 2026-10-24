/** @file RunContext.cpp
 * @brief 线程/进程入口唯一不可恢复异常收口。
 */
#include <Prism/Foundation/Executor/RunContext.hpp>
#include <Prism/Foundation/Executor/FatalState.hpp>

#include <exception>

namespace Prism::Executor
{
    auto RunContext(boost::asio::io_context& Context) -> std::exception_ptr
    {
        const auto Fatal = FatalState::Bind(Context);
        try
        {
            Context.run();
        }
        catch (...)
        {
            Fatal->Publish(std::current_exception());
        }
        return Fatal->Error();
    }
}
