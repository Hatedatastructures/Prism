/**
 * @file SessionModuleContractTest.cpp
 * @brief Session 拆分后的公共生命周期与 owner 头契约测试
 */

#include <gtest/gtest.h>

#include <memory>
#include <type_traits>

#include <Preview/Runtime/Session/ClosePolicy.hpp>
#include <Preview/Runtime/Session/DataPlaneRelay.hpp>
#include <Preview/Runtime/Session/RecognitionAdmission.hpp>
#include <Preview/Runtime/Session.hpp>

namespace
{

    TEST(SessionModuleContract, PublicLifecycleSurfaceRemainsConstructible)
    {
        using Session = Preview::Runtime::Session;
        using Options = Preview::Runtime::SessionOptions;

        static_assert(std::is_constructible_v<Session, Options>);
        static_assert(requires(Session &Value)
                      {
                          Value.Control();
                          Value.Services();
                          Value.Cancel();
                          Value.Close();
                      });

        SUCCEED();
    }

    TEST(SessionModuleContract, OwnerHeadersExposeConcreteRuntimeContracts)
    {
        static_assert(std::is_class_v<Preview::Runtime::SessionClosePolicy>);
        static_assert(std::is_class_v<Preview::Runtime::SessionDataPlaneRelay>);
        static_assert(std::is_class_v<Preview::Runtime::SessionRecognitionAdmission>);

        SUCCEED();
    }

} // namespace
