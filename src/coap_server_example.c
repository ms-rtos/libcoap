/* CoAP server Example
   This example code is in the Public Domain (or CC0 licensed, at your option.)
   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "coap.h"

/* Set this to 9 to get verbose logging from within libcoap */
/* If want to change log level num to open log, don't forget to enlarge coap_example_task size*/
#define COAP_LOGGING_LEVEL 0

static char test_data[100];
static int test_data_len = 0;

/*
 * The resource handler
 */
static void
hnd_test_get(coap_context_t *ctx, coap_resource_t *resource,
             coap_session_t *session,
             coap_pdu_t *request, coap_binary_t *token,
             coap_string_t *query, coap_pdu_t *response)
{
    coap_add_data_blocked_response(resource, session, request, response, token,
                                   COAP_MEDIATYPE_TEXT_PLAIN, 0,
                                   (size_t)test_data_len,
                                   (const u_char *)test_data);
}

static void
hnd_test_put(coap_context_t *ctx,
             coap_resource_t *resource,
             coap_session_t *session,
             coap_pdu_t *request,
             coap_binary_t *token,
             coap_string_t *query,
             coap_pdu_t *response)
{
    size_t size;
    unsigned char *data;

    coap_resource_notify_observers(resource, NULL);

    if (strcmp (test_data, "no data") == 0) {
        response->code = COAP_RESPONSE_CODE(201);
    } else {
        response->code = COAP_RESPONSE_CODE(204);
    }

    /* coap_get_data() sets size to 0 on error */
    (void)coap_get_data(request, &size, &data);

    if (size == 0) {      /* re-init */
        snprintf(test_data, sizeof(test_data), "no data");
        test_data_len = strlen(test_data);
    } else {
        test_data_len = size > sizeof (test_data) ? sizeof (test_data) : size;
        memcpy (test_data, data, test_data_len);
    }
}

static void
hnd_test_delete(coap_context_t *ctx,
                  coap_resource_t *resource,
                  coap_session_t *session,
                  coap_pdu_t *request,
                  coap_binary_t *token,
                  coap_string_t *query,
                  coap_pdu_t *response)
{
    coap_resource_notify_observers(resource, NULL);
    snprintf(test_data, sizeof(test_data), "no data");
    test_data_len = strlen(test_data);
    response->code = COAP_RESPONSE_CODE(202);
}

int main(int argc, char **argv)
{
    coap_context_t *ctx = NULL;
    coap_address_t serv_addr;
    coap_resource_t *resource = NULL;

    snprintf(test_data, sizeof(test_data), "no data");
    test_data_len = strlen(test_data);
    coap_set_log_level(COAP_LOGGING_LEVEL);

    while (1) {
        coap_endpoint_t *ep_udp = NULL;
        coap_endpoint_t *ep_tcp = NULL;
        unsigned wait_ms;

        ctx = coap_new_context(NULL);
        if (!ctx) {
           continue;
        }

        /* Prepare the CoAP server socket */
        coap_address_init(&serv_addr);
        serv_addr.addr.sin.sin_family      = AF_INET;
        serv_addr.addr.sin.sin_addr.s_addr = INADDR_ANY;
        serv_addr.addr.sin.sin_port        = htons(COAP_DEFAULT_PORT);
        ep_udp = coap_new_endpoint(ctx, &serv_addr, COAP_PROTO_UDP); //Add IPv4 endpoint
        if (!ep_udp) {
           goto clean_up;
        }

        ep_tcp = coap_new_endpoint(ctx, &serv_addr, COAP_PROTO_TCP);
        if (!ep_tcp) {
           goto clean_up;
        }

        resource = coap_resource_init(coap_make_str_const("test"), 0);
        if (!resource) {
           goto clean_up;
        }
        coap_register_handler(resource, COAP_REQUEST_GET, hnd_test_get);
        coap_register_handler(resource, COAP_REQUEST_PUT, hnd_test_put);
        coap_register_handler(resource, COAP_REQUEST_DELETE, hnd_test_delete);
        /* We possibly want to Observe the GETs */
        coap_resource_set_get_observable(resource, 1);
        coap_add_resource(ctx, resource);

        wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;

        while (1) {
            int result = coap_io_process(ctx, wait_ms);
            if (result < 0) {
                break;
            } else if (result && (unsigned)result < wait_ms) {
                /* decrement if there is a result wait time returned */
                wait_ms -= result;
            }
            if (result) {
                /* result must have been >= wait_ms, so reset wait_ms */
                wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
            }
        }
    }
clean_up:
    coap_free_context(ctx);
    coap_cleanup();
    return 0;
}
