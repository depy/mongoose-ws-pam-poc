#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <security/pam_appl.h>
#include "mongoose.h"

#define TRY(x) ret = (x); printf("PAM: %s\n", pam_strerror(handle, ret)); if (ret != PAM_SUCCESS) goto finally

static const char *s_listen_on = "ws://localhost:8000";
static const char *s_web_root = ".";

int len = 1000;
const char service[] = "check_user";
struct pam_conv conv;
pam_handle_t* handle;
int ret;

char* user = NULL;
char* password = NULL;

int test_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
    const struct pam_message* msg_ptr = *msg;
    int x = 0;
    *resp = calloc(sizeof(struct pam_response), num_msg);
    for (x = 0; x < num_msg; x++, msg_ptr++){
        char* resp_str;
        switch (msg_ptr->msg_style){
            case PAM_PROMPT_ECHO_OFF:
            case PAM_PROMPT_ECHO_ON:
                resp_str = password;
                resp[x]->resp= strdup(resp_str);
                break;

            case PAM_ERROR_MSG:
            case PAM_TEXT_INFO:
            default:
                assert(0);

        }
    }
    return PAM_SUCCESS;
}

static void fn(struct mg_connection *c, int ev, void *ev_data) {
  if (ev == MG_EV_OPEN) {
    // c->is_hexdumping = 1;
  } else if (ev == MG_EV_HTTP_MSG) {
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    if (mg_match(hm->uri, mg_str("/websocket"), NULL)) {
      mg_ws_upgrade(c, hm, NULL);
    } else if (mg_match(hm->uri, mg_str("/rest"), NULL)) {
      mg_http_reply(c, 200, "", "{\"result\": %d}\n", 123);
    } else {
      struct mg_http_serve_opts opts = {.root_dir = s_web_root};
      mg_http_serve_dir(c, ev_data, &opts);
    }
  } else if (ev == MG_EV_WS_MSG) {
    struct mg_ws_message *wm = (struct mg_ws_message *) ev_data;

    // Get username and password (u,p) by splitting the send string on comma
    struct mg_str u, p;
    mg_span(wm->data, &u, &p, ',');

    // Assign read values to user and password variables
    // They need to be turned into null terminated strings
    // sing mongoose mg_str is not null terminated
    user = (char*)malloc(u.len);
    strncpy(user, u.buf, u.len+1);
    user[u.len] = '\0';

    password = (char*)malloc(p.len);
    strncpy(password, p.buf, p.len+1);
    password[p.len] = '\0';

    // Echo back username and password sent
    //mg_ws_send(c, u.buf, u.len, WEBSOCKET_OP_TEXT);
    //mg_ws_send(c, p.buf, p.len, WEBSOCKET_OP_TEXT);

    // Do PAM auth
    TRY(pam_start(service, user, &conv, &handle ));
    TRY(pam_authenticate(handle, 0));
    TRY(pam_acct_mgmt(handle, 0));

    // Send "Success!" back via WebSocket
    if(ret == PAM_SUCCESS) {
      struct mg_str success = mg_str("Success!");
      mg_ws_send(c, success.buf, success.len, WEBSOCKET_OP_TEXT);
    }

    finally:
      pam_end(handle, ret);
      if(ret != PAM_SUCCESS) {
        struct mg_str fail = mg_str("Failure!");
        mg_ws_send(c, fail.buf, fail.len, WEBSOCKET_OP_TEXT);
      }
      free(user);
      free(password);
  }
}

int main(void) {
  conv.conv=test_conv;

  struct mg_mgr mgr;  // Event manager
  mg_mgr_init(&mgr);  // Initialise event manager
  printf("Starting WS listener on %s/websocket\n", s_listen_on);
  mg_http_listen(&mgr, s_listen_on, fn, NULL);  // Create HTTP listener
  for (;;) mg_mgr_poll(&mgr, 1000);             // Infinite event loop
  mg_mgr_free(&mgr);
  return 0;
}
