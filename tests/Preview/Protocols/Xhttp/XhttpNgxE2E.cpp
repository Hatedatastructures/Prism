#include "XhttpNgxE2ESupport.hpp"

TEST(XhttpNgxE2E, StreamOneEcho)
{
    auto IoContext = std::make_shared<Net::io_context>();
    auto ServerContext = std::make_shared<SSL::context>(SSL::context::tlsv13);
    LoadSelfSigned(*ServerContext);

    auto ClientContext = std::make_shared<SSL::context>(SSL::context::tlsv13);
    ClientContext->set_verify_mode(SSL::verify_none);

    auto [A, B] = Preview::MakeMemoryPair(IoContext->get_executor());
    auto ClientRaw = std::make_shared<Preview::MemoryStream>(std::move(A));
    auto ServerRaw = std::make_shared<Preview::MemoryStream>(std::move(B));

    const std::string Payload = "xhttp-Stream-one-echo";
    auto ClientSucceeded = std::make_shared<bool>(false);
    auto ServerSucceeded = std::make_shared<bool>(false);
    auto TimedOut = std::make_shared<bool>(false);
    StreamOneScenarioRequest Request{
        IoContext->get_executor(),
        EchoRequest{ClientRaw, ClientContext, Payload, ClientSucceeded},
        EchoRequest{ServerRaw, ServerContext, Payload, ServerSucceeded},
        TimedOut};

    RunCoroutine(IoContext, RunStreamOneScenario(std::move(Request)));
    EXPECT_FALSE(*TimedOut);
    EXPECT_TRUE(*ServerSucceeded);
    EXPECT_TRUE(*ClientSucceeded);
}
