/**
 * @file ValidationHeadersTest.cpp
 * @brief 配置校验职责头的独立包含和公共入口回归测试。
 */

#include <gtest/gtest.h>

#include <Prism/Application/Configuration/ConfigurationValidator.hpp>
#include <Prism/Application/Configuration/Validation/Detail/Capability.hpp>
#include <Prism/Application/Configuration/Validation/Detail/Carrier.hpp>
#include <Prism/Application/Configuration/Validation/Detail/Configuration.hpp>
#include <Prism/Application/Configuration/Validation/Detail/Protocol.hpp>
#include <Prism/Application/Configuration/Validation/Detail/Reference.hpp>
#include <Prism/Application/Configuration/Validation/Detail/Schema.hpp>
#include <Prism/Application/Configuration/Validation/Detail/Secret.hpp>

#include <optional>

namespace
{

    using Prism::Application::Configuration::ConfigurationValidator;
    using Prism::Application::Configuration::PrismConfiguration;
    using Prism::Composition::Builtin::Capability;

    TEST(ConfigurationValidationHeaders, KeepIndependentOwnersSelfContained)
    {
        const PrismConfiguration Configuration;
        EXPECT_TRUE(Prism::Application::Configuration::Validation::ValidateSchema(Configuration));
        EXPECT_EQ(ConfigurationValidator::CapabilityFromName("Mux"),
                  std::optional<Capability>{Capability::Multiplex});
        EXPECT_EQ(Prism::Application::Configuration::Validation::CapabilityFromName("Metrics"),
                  std::optional<Capability>{Capability::Observability});
    }

    TEST(ConfigurationValidationHeaders, OwnerAndFacadePreserveFirstCrossStageError)
    {
        const PrismConfiguration Configuration;
        Prism::Application::Configuration::ValidationOptions Options;
        const auto OwnerResult = Prism::Application::Configuration::Validation::
            ReferenceValidationOwner(Configuration, Options).Validate();
        const auto FacadeResult = Prism::Application::Configuration::Validation::
            ValidateConfiguration({Configuration, Options});

        ASSERT_EQ(OwnerResult.has_value(), FacadeResult.has_value());
        if (!OwnerResult && !FacadeResult)
        {
            EXPECT_EQ(OwnerResult.error().Code, FacadeResult.error().Code);
            EXPECT_EQ(OwnerResult.error().Path, FacadeResult.error().Path);
            EXPECT_EQ(OwnerResult.error().Message, FacadeResult.error().Message);
        }
    }

} // namespace
