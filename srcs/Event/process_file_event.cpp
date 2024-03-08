#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdio>
#include <iostream>
#include <map>
#include <utility>
#include "Event.hpp"
#include "Debug.hpp"
#include "Error.hpp"
#include "HttpResponse.hpp"
#include "Socket.hpp"
#include "StringHandler.hpp"


ProcResult Event::process_file_event() {
    switch (this->event_state_) {
        case kReadingFile: {
            // unused
            break;
        }

            // call from process_client_event
        case kExecuteCGI: {
            DEBUG_PRINT(YELLOW, "   CGI Executing");
            ProcResult exec_result = this->response_->exec_cgi_process();
            if (exec_result == Failure) {
                this->set_event_phase(kCreatingCGIBody);
                return Failure;
            }
            DEBUG_PRINT(YELLOW, "    success -> send");
            this->set_event_phase(kSendingRequestBodyToCgi);
            return ExecutingCgi;
        }

        case kSendingRequestBodyToCgi: {
            DEBUG_PRINT(YELLOW, "   CGI Send");
            ProcResult send_result = this->response_->send_request_body_to_cgi();
            if (send_result == Continue) {
                DEBUG_PRINT(YELLOW, "    send continue");
                return Continue;
            }
            if (send_result == Success) {
                DEBUG_PRINT(YELLOW, "    send finish");
                this->set_event_phase(kReceivingCgiResponse);
            } else {
                // error -> response 500
                DEBUG_PRINT(YELLOW, "    send error");
                // this->set_session_state(kCreatingResponseBody);
                this->set_event_phase(kCreatingCGIBody);
            }
            break;
        }

        case kReceivingCgiResponse: {
            DEBUG_PRINT(YELLOW, "   CGI Recv");
            ProcResult recv_result = this->response_->recv_to_cgi_buf();
            if (recv_result == Continue) {
                DEBUG_PRINT(YELLOW, "    recv continue");
                return Continue;
            }
            if (recv_result == Success) {
                DEBUG_PRINT(YELLOW, "    recv finish");
                this->set_event_phase(kCreatingCGIBody);
            } else {
                DEBUG_PRINT(YELLOW, "    recv error");
                // error -> response 500
                // this->set_session_state(kCreatingResponseBody);
                this->set_event_phase(kCreatingCGIBody);
            }
            break;
        }

        default: {
            // const std::string error_msg = CREATE_ERROR_INFO_STR("error: unknown session in file event");
            return Failure;
        }
    }
    return Success;
}
