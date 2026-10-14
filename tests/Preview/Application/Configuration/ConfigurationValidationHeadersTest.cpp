/**
 * @file ConfigurationValidationHeadersTest.cpp
 * @brief 配置校验职责头的独立包含和公共入口回归测试。
 */

#include <gtest/gtest.h>

#include <Preview/Application/Configuration/ConfigurationValidator.hpp>
#include <Preview/Application/Configuration/Validation/CapabilityValidation.hpp>
#include <Preview/Application/Configuration/Validation/CarrierValidation.hpp>
#include <Preview/Application/Configuration/Validation/ConfigurationValidation.hpp>
#include <Preview/Application/Configuration/Validation/ProtocolIndependentValidation.hpp>
#include <Preview/Application/Configuration/Validation/ReferenceValidation.hpp>
#include <Preview/Application/Configuration/Validation/SchemaValidation.hpp>
#include <Preview/Application/Configuration/Validation/SecretValidation.hpp>

#include <optional>

namespace
{

    using Preview::Application::Configuration::ConfigurationValidator;
    using Preview::Application::Configuration::PreviewConfiguration;
    using Preview::Composition::Builtin::Capability;

    TEST(ConfigurationValidationHeaders, KeepIndependentOwnersSelfContained)
    {
        const PreviewConfiguration Configuration;
        EXPECT_TRUE(Preview::Application::Configuration::Validation::ValidateSchema(Configuration));
        EXPECT_EQ(ConfigurationValidator::CapabilityFromName("Mux"),
                  std::optional<Capability>{Capability::Multiplex});
        EXPECT_EQ(Preview::Application::Configuration::Validation::CapabilityFromName("Metrics"),
                  std::optional<Capability>{Capability::Observability});
    }

    TEST(ConfigurationValidationHeaders, OwnerAndFacadePreserveFirstCrossStageError)
    {
        const PreviewConfiguration Configuration;
        Preview::Application::Configuration::ValidationOptions Options;
        const auto OwnerResult = Preview::Application::Configuration::Validation::
            ReferenceValidationOwner(Configuration, Options).Validate();
        const auto FacadeResult = Preview::Application::Configuration::Validation::
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
