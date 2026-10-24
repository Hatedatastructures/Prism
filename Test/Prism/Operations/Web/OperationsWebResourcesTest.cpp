/** @file OperationsWebResourcesTest.cpp @brief 同源资源目录、正文完整性及缓存边界。 */
#include "OperationsWebTestSupport.hpp"

#include <gtest/gtest.h>
#include <Prism/Operations/Web/Loader.hpp>
#include <Prism/Operations/Web/Response.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <utility>

namespace
{
    namespace Web = Prism::Operations::Web;

    /** @brief 每例拥有唯一临时目录；只清理本 fixture 成功创建的完整路径。 */
    class OperationsWebResources : public ::testing::Test
    {
    protected:
        auto SetUp() -> void override
        {
            const auto Tick = std::chrono::steady_clock::now().time_since_epoch().count();
            Path_ = std::filesystem::temp_directory_path() /
                ("Prism-WebResources-" + std::to_string(Tick) + "-" + std::to_string(Next_.fetch_add(1)));
            std::error_code Error;
            Created_ = std::filesystem::create_directory(Path_, Error);
            ASSERT_FALSE(Error);
            ASSERT_TRUE(Created_);
        }

        auto TearDown() -> void override
        {
            if (!Created_) return;
            std::error_code Error;
            const auto Base = std::filesystem::canonical(std::filesystem::temp_directory_path(), Error);
            ASSERT_FALSE(Error);
            const auto Actual = std::filesystem::canonical(Path_, Error);
            ASSERT_FALSE(Error);
            ASSERT_EQ(Actual.parent_path(), Base);
            ASSERT_TRUE(Actual.filename().string().starts_with("Prism-WebResources-"));
            std::filesystem::remove_all(Actual, Error);
            EXPECT_FALSE(Error);
        }

        auto Add(std::string Path, std::string Body) -> void
        {
            ASSERT_TRUE(Web::IsResourcePath(Path));
            std::filesystem::create_directories((Path_ / Path).parent_path());
            std::ofstream Output(Path_ / Path, std::ios::binary);
            ASSERT_TRUE(Output);
            Output.write(Body.data(), static_cast<std::streamsize>(Body.size()));
            ASSERT_TRUE(Output);
            const auto Digest = Prism::Testing::OperationsWeb::Sha256Hex(Body);
            ASSERT_TRUE(Digest);
            Manifest_.Assets.push_back(Web::ResourceDescriptor{Path,
                std::string(Web::ContentTypeFor(Path)), std::move(*Digest), Body.size(),
                Path.starts_with("assets/")});
        }

        auto WriteManifest() -> void
        {
            Manifest_.Version = 1;
            const auto Json = glz::write_json(Manifest_);
            ASSERT_TRUE(Json);
            std::ofstream Output(Path_ / "catalog.json", std::ios::binary);
            ASSERT_TRUE(Output);
            Output.write(Json->data(), static_cast<std::streamsize>(Json->size()));
            ASSERT_TRUE(Output);
        }

        inline static std::atomic<unsigned> Next_{0};
        std::filesystem::path Path_;
        Web::ResourceManifest Manifest_;
        bool Created_{false};
    };

    TEST_F(OperationsWebResources, ServesSevenPagesAndKeepsApiAndUnknownPathsSeparate)
    {
        Add("index.html", "<html>actual</html>");
        Add("assets/index-AbCd1234.js", "export const Value=1;");
        WriteManifest();
        const auto Loaded = Web::LoadCatalog(Path_);
        ASSERT_TRUE(Loaded);
        const auto &Catalog = **Loaded;
        for (const auto Page : {"/", "/workers", "/accounts", "/sessions", "/events",
            "/configuration", "/operations"})
        {
            const auto Resource = Catalog.Lookup(Page);
            ASSERT_NE(Resource, nullptr);
            EXPECT_EQ(Resource->Body, "<html>actual</html>");
        }
        EXPECT_NE(Catalog.Lookup("/sessions?cursor=18446744073709551615"), nullptr);
        for (const auto Target : {"/Operations/Health", "/Operations/missing", "/unknown",
            "/assets/missing.js", "/assets/../index.html", "/assets/%2e%2e/index.html", "//index.html"})
            EXPECT_EQ(Catalog.Lookup(Target), nullptr) << Target;
    }

    TEST_F(OperationsWebResources, VerifiesHashAndSizeBeforePublication)
    {
        Add("index.html", "<html>first</html>");
        WriteManifest();
        std::ofstream Changed(Path_ / "index.html", std::ios::binary);
        Changed << "<html>other</html>";
        Changed.close();
        const auto Loaded = Web::LoadCatalog(Path_);
        ASSERT_FALSE(Loaded);
        EXPECT_EQ(Loaded.error().Code, Prism::Fault::Code::BadMessage);
    }

    TEST_F(OperationsWebResources, RejectsTraversalAndHeaderInjectionDescriptors)
    {
        Add("index.html", "<html></html>");
        Manifest_.Assets[0].Path = "../outside.html";
        WriteManifest();
        auto Loaded = Web::LoadCatalog(Path_);
        ASSERT_FALSE(Loaded);
        EXPECT_EQ(Loaded.error().Code, Prism::Fault::Code::BadMessage);
        Manifest_.Assets[0].Path = "index.html";
        Manifest_.Assets[0].ContentType = "text/html\r\nInjected: yes";
        WriteManifest();
        Loaded = Web::LoadCatalog(Path_);
        ASSERT_FALSE(Loaded);
        EXPECT_EQ(Loaded.error().Code, Prism::Fault::Code::BadMessage);
    }

    TEST_F(OperationsWebResources, RejectsDuplicateEntriesAndMissingIndex)
    {
        Add("index.html", "<html></html>");
        Manifest_.Assets.push_back(Manifest_.Assets[0]);
        WriteManifest();
        auto Loaded = Web::LoadCatalog(Path_);
        ASSERT_FALSE(Loaded);
        EXPECT_EQ(Loaded.error().Code, Prism::Fault::Code::BadMessage);
        Manifest_.Assets.clear();
        Add("assets/index-AbCd1234.js", "export{};");
        WriteManifest();
        Loaded = Web::LoadCatalog(Path_);
        ASSERT_FALSE(Loaded);
        EXPECT_EQ(Loaded.error().Code, Prism::Fault::Code::BadMessage);
    }

    TEST_F(OperationsWebResources, RejectsResourceOverFixedByteBudget)
    {
        Add("index.html", std::string(Web::MaxResourceBytes + 1, 'x'));
        WriteManifest();
        const auto Loaded = Web::LoadCatalog(Path_);
        ASSERT_FALSE(Loaded);
        EXPECT_EQ(Loaded.error().Code, Prism::Fault::Code::BadMessage);
    }

    TEST_F(OperationsWebResources, PublishedBodySurvivesFileChangeAndHasExplicitCachePolicy)
    {
        Add("index.html", "<html>ready</html>");
        Add("assets/index-AbCd1234.js", "export{};");
        WriteManifest();
        const auto Loaded = Web::LoadCatalog(Path_);
        ASSERT_TRUE(Loaded);
        std::ofstream Changed(Path_ / "index.html", std::ios::binary);
        Changed << "changed";
        Changed.close();
        const auto Page = Web::MakeResourceResponse(**Loaded, "/workers");
        ASSERT_TRUE(Page);
        EXPECT_NE(Page->find("Cache-Control: no-store\r\n"), std::string::npos);
        EXPECT_NE(Page->find("<html>ready</html>"), std::string::npos);
        EXPECT_NE(Page->find("Content-Security-Policy:"), std::string::npos);
        const auto Script = Web::MakeResourceResponse(**Loaded, "/assets/index-AbCd1234.js");
        ASSERT_TRUE(Script);
        EXPECT_NE(Script->find("Cache-Control: public, max-age=31536000, immutable\r\n"), std::string::npos);
        EXPECT_FALSE(Web::MakeResourceResponse(**Loaded, "/Operations/missing"));
        EXPECT_FALSE(Web::MakeResourceResponse(**Loaded, "/unknown"));
    }
}
