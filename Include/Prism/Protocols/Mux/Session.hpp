/**
 * @file Session.hpp
 * @brief 多路复用共享会话框架聚合入口。
 * @details 会话契约、状态、流控、writer、帧分发和拆除分别由职责头拥有，
 *          对外仍通过本文件提供原有的 Mux::Session API。
 */

#pragma once

#include <Prism/Protocols/Mux/Detail/Session/SessionContract.hpp>
#include <Prism/Protocols/Mux/Detail/Session/SessionState.hpp>
#include <Prism/Protocols/Mux/Detail/Session/SessionFlowControl.hpp>
#include <Prism/Protocols/Mux/Detail/Session/SessionWriter.hpp>
#include <Prism/Protocols/Mux/Detail/Session/SessionFrames.hpp>
#include <Prism/Protocols/Mux/Detail/Session/SessionTeardown.hpp>
