/**
 * @file Session.hpp
 * @brief 多路复用共享会话框架聚合入口。
 * @details 会话契约、状态、流控、writer、帧分发和拆除分别由职责头拥有，
 *          对外仍通过本文件提供原有的 Mux::Session API。
 */

#pragma once

#include <Prism/Protocols/Mux/Session/Contract.hpp>
#include <Prism/Protocols/Mux/Session/State.hpp>
#include <Prism/Protocols/Mux/Session/FlowControl.hpp>
#include <Prism/Protocols/Mux/Session/Writer.hpp>
#include <Prism/Protocols/Mux/Session/Frames.hpp>
#include <Prism/Protocols/Mux/Session/Teardown.hpp>
