/**
 * @file boost_thunk_fix.cpp
 * @brief 强制生成 boost::wrapexcept 的 non-virtual thunk
 * @details GCC 16 + boost 1.89 header-only 在 --coverage 下，
 * wrapexcept<std::logic_error> 的虚析构 thunk 未被任何 TU 实例化，
 * 导致 Prism.exe 链接缺失 non-virtual thunk 符号。
 * 本 TU 通过"基类指针 delete 派生对象"的调用路径强制生成 thunk。
 * @note 仅编译进静态库，无运行时调用（符号由链接器解析）。
 */

#include <boost/throw_exception.hpp>

#include <stdexcept>

namespace psm::detail
{

    /**
     * @brief 强制生成 wrapexcept 虚析构 thunk
     * @details 通过 std::logic_error 基类指针 delete boost::wrapexcept
     * 派生对象，触发编译器生成 non-virtual thunk（多继承虚析构调整）。
     * 函数本身不被调用，仅用于符号生成。
     */
    [[maybe_unused]] auto force_boost_wrapexcept_thunk() -> void
    {
        boost::wrapexcept<std::logic_error> *obj =
            new boost::wrapexcept<std::logic_error>(std::logic_error("unused"));
        std::logic_error *base = obj;
        delete base; // 通过基类指针删除 → 生成 non-virtual thunk
    }

} // namespace psm::detail
