/** @file RunContext.hpp @brief 线程/进程入口唯一不可恢复异常收口。 */
#pragma once
#include <Prism/Foundation/Executor/FatalState.hpp>
namespace Prism::Executor
{
    /**
     * @brief 冷绑定实际io_context后驱动run，返回原fatal，绝不将它写为业务成功。
     * @details 仅由线程/进程入口调用，调用者持context到真实资源退出；fatal后停止本域，
     *          尚未退休的实体仍由各自ClosingStorage持有，禁止普通清空伪造完成。
     */
    [[nodiscard]] inline auto RunContext(boost::asio::io_context& Context) -> std::exception_ptr
    {
        const auto Fatal = FatalState::Bind(Context);
        try { Context.run(); }
        catch (...) { Fatal->Publish(std::current_exception()); }
        return Fatal->Error();
    }
}
