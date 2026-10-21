/*
 * NAPI surface of the Yanshu native core.
 *
 * Kept in C and free of the C++ runtime so the module has no libc++_shared.so
 * dependency to ship. Every call forwards to a C ABI exported by the Rust
 * cdylib (yanshu-core); this file only translates JS values.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "napi/native_api.h"

extern int32_t mh_init(const char* dir);
extern int32_t mh_wg_key(char* out, int32_t capacity);
extern int32_t mh_rotate_key(char* out, int32_t capacity);
extern int32_t mh_wg_key_readonly(char* out, int32_t capacity);
extern int32_t mh_clear_key(void);
extern int32_t mh_open_udp(const char* host, int32_t port);
extern int32_t mh_attach_tun(int32_t fd, int32_t mtu);
extern int32_t mh_open_relay_socket(int32_t family);
extern int32_t mh_stats(char* out, int32_t capacity);
extern void mh_set_direct_allowed(int32_t allowed);
extern int32_t mh_api_login(const char* account, const char* pubkey, char* out, int32_t capacity);
extern int32_t mh_api_devices(const char* token, char* out, int32_t capacity);
extern int32_t mh_api_remove_device(const char* token, const char* id, char* out, int32_t capacity);
extern int32_t mh_api_account(const char* token, char* out, int32_t capacity);
extern int32_t mh_api_relays(char* out, int32_t capacity);
extern int32_t mh_tunnel_start(int32_t fd, int32_t mtu, const char* peer_key, const char* endpoint_ip,
    int32_t endpoint_port, const char* bridge, char* out, int32_t capacity);
extern int32_t mh_tunnel_status(char* out, int32_t capacity);
extern void mh_tunnel_stop(void);
extern void mh_set_diagnostics(int32_t enabled);
extern void mh_set_ip_version(int32_t families);
extern int32_t mh_log_marker(const char* text);
extern int32_t mh_log_line(const char* text);
extern void mh_stop(void);

static napi_value WrapInit(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    char dir[1024] = { 0 };
    size_t length = 0;
    if (argc >= 1) {
        napi_get_value_string_utf8(env, argv[0], dir, sizeof(dir), &length);
    }

    napi_value result;
    napi_create_int32(env, mh_init(dir), &result);
    return result;
}

static napi_value WrapWgKey(napi_env env, napi_callback_info info)
{
    (void)info;
    char buffer[256] = { 0 };
    int32_t written = mh_wg_key(buffer, (int32_t)sizeof(buffer));
    size_t length = written > 0 ? (size_t)written : 0;

    napi_value result;
    napi_create_string_utf8(env, buffer, length, &result);
    return result;
}


static napi_value WrapDeviceKey(napi_env env, napi_callback_info info)
{
    (void)info;
    char buffer[256] = { 0 };
    int32_t written = mh_wg_key_readonly(buffer, (int32_t)sizeof(buffer));
    size_t length = written > 0 ? (size_t)written : 0;
    napi_value result;
    napi_create_string_utf8(env, buffer, length, &result);
    return result;
}

static napi_value WrapRotateKey(napi_env env, napi_callback_info info)
{
    (void)info;
    char buffer[256] = { 0 };
    int32_t written = mh_rotate_key(buffer, (int32_t)sizeof(buffer));
    size_t length = written > 0 ? (size_t)written : 0;
    napi_value result;
    napi_create_string_utf8(env, buffer, length, &result);
    return result;
}

static napi_value WrapClearKey(napi_env env, napi_callback_info info)
{
    (void)info;
    napi_value result;
    napi_create_int32(env, mh_clear_key(), &result);
    return result;
}

typedef struct {
    napi_async_work work;
    napi_deferred deferred;
    int kind;
    char a[4096];
    char b[256];
    char* out;
    int capacity;
} ApiJob;

static void ExecuteApi(napi_env env, void* data)
{
    (void)env;
    ApiJob* job = (ApiJob*)data;
    switch (job->kind) {
        case 0:
            mh_api_login(job->a, job->b, job->out, job->capacity);
            break;
        case 1:
            mh_api_devices(job->a, job->out, job->capacity);
            break;
        case 2:
            mh_api_remove_device(job->a, job->b, job->out, job->capacity);
            break;
        case 3:
            mh_api_account(job->a, job->out, job->capacity);
            break;
        default:
            mh_api_relays(job->out, job->capacity);
            break;
    }
}

static void CompleteApi(napi_env env, napi_status status, void* data)
{
    ApiJob* job = (ApiJob*)data;
    napi_value result;
    if (status != napi_ok || job->out[0] == '\0') {
        napi_create_string_utf8(env, "{\"ok\":false,\"error\":\"native call failed\"}",
            NAPI_AUTO_LENGTH, &result);
    } else {
        napi_create_string_utf8(env, job->out, NAPI_AUTO_LENGTH, &result);
    }
    napi_resolve_deferred(env, job->deferred, result);
    napi_delete_async_work(env, job->work);
    free(job->out);
    free(job);
}

/*
 * Runs the blocking Rust call on a libuv worker thread and answers with a Promise.
 * Doing this on the JS thread froze the UI for the whole fronted handshake and tripped
 * the ANR watchdog.
 */
static napi_value StartApiJob(napi_env env, napi_callback_info info, int kind, int arguments,
    int capacity)
{
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    ApiJob* job = (ApiJob*)calloc(1, sizeof(ApiJob));
    if (job == NULL) {
        napi_value result;
        napi_create_string_utf8(env, "{\"ok\":false,\"error\":\"out of memory\"}", NAPI_AUTO_LENGTH,
            &result);
        return result;
    }
    job->kind = kind;
    job->capacity = capacity;
    job->out = (char*)calloc(1, (size_t)capacity);
    if (job->out == NULL) {
        free(job);
        napi_value result;
        napi_create_string_utf8(env, "{\"ok\":false,\"error\":\"out of memory\"}", NAPI_AUTO_LENGTH,
            &result);
        return result;
    }

    size_t length = 0;
    if (argc >= 1) {
        napi_get_value_string_utf8(env, argv[0], job->a, sizeof(job->a), &length);
    }
    if (arguments >= 2 && argc >= 2) {
        napi_get_value_string_utf8(env, argv[1], job->b, sizeof(job->b), &length);
    }

    napi_value promise;
    napi_create_promise(env, &job->deferred, &promise);
    napi_value name;
    napi_create_string_utf8(env, "yanshuApi", NAPI_AUTO_LENGTH, &name);
    napi_create_async_work(env, NULL, name, ExecuteApi, CompleteApi, job, &job->work);
    napi_queue_async_work(env, job->work);
    return promise;
}

static napi_value WrapSetDirectAllowed(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    bool allowed = false;
    if (argc >= 1) {
        napi_get_value_bool(env, argv[0], &allowed);
    }
    mh_set_direct_allowed(allowed ? 1 : 0);

    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

static napi_value WrapLogMarker(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    char text[256] = { 0 };
    size_t length = 0;
    if (argc >= 1) {
        napi_get_value_string_utf8(env, argv[0], text, sizeof(text), &length);
    }
    mh_log_marker(text);
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

static napi_value WrapLogLine(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    char text[512] = { 0 };
    size_t length = 0;
    if (argc >= 1) {
        napi_get_value_string_utf8(env, argv[0], text, sizeof(text), &length);
    }
    mh_log_line(text);
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

static napi_value WrapSetDiagnostics(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    bool enabled = false;
    if (argc >= 1) {
        napi_get_value_bool(env, argv[0], &enabled);
    }
    mh_set_diagnostics(enabled ? 1 : 0);
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

static napi_value WrapSetIpVersion(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    int32_t families = 3;
    if (argc >= 1) {
        napi_get_value_int32(env, argv[0], &families);
    }
    mh_set_ip_version(families);
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

static napi_value WrapTunnelStart(napi_env env, napi_callback_info info)
{
    size_t argc = 6;
    napi_value argv[6] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    int32_t fd = -1;
    int32_t mtu = 1420;
    int32_t port = 51820;
    char peer_key[128] = { 0 };
    char endpoint[128] = { 0 };
    char bridge[128] = { 0 };
    size_t length = 0;
    if (argc >= 1) {
        napi_get_value_int32(env, argv[0], &fd);
    }
    if (argc >= 2) {
        napi_get_value_int32(env, argv[1], &mtu);
    }
    if (argc >= 3) {
        napi_get_value_string_utf8(env, argv[2], peer_key, sizeof(peer_key), &length);
    }
    if (argc >= 4) {
        napi_get_value_string_utf8(env, argv[3], endpoint, sizeof(endpoint), &length);
    }
    if (argc >= 5) {
        napi_get_value_int32(env, argv[4], &port);
    }
    if (argc >= 6) {
        napi_get_value_string_utf8(env, argv[5], bridge, sizeof(bridge), &length);
    }

    char buffer[512] = { 0 };
    int32_t written = mh_tunnel_start(fd, mtu, peer_key, endpoint, port, bridge, buffer,
        (int32_t)sizeof(buffer));
    napi_value result;
    napi_create_string_utf8(env, buffer, written > 0 ? (size_t)written : 0, &result);
    return result;
}

static napi_value WrapTunnelStatus(napi_env env, napi_callback_info info)
{
    (void)info;
    char buffer[512] = { 0 };
    int32_t written = mh_tunnel_status(buffer, (int32_t)sizeof(buffer));
    napi_value result;
    napi_create_string_utf8(env, buffer, written > 0 ? (size_t)written : 0, &result);
    return result;
}

static napi_value WrapTunnelStop(napi_env env, napi_callback_info info)
{
    (void)info;
    mh_tunnel_stop();
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

static napi_value WrapApiLogin(napi_env env, napi_callback_info info)
{
    return StartApiJob(env, info, 0, 2, 8192);
}

static napi_value WrapApiDevices(napi_env env, napi_callback_info info)
{
    return StartApiJob(env, info, 1, 1, 8192);
}

static napi_value WrapApiRemoveDevice(napi_env env, napi_callback_info info)
{
    return StartApiJob(env, info, 2, 2, 1024);
}

static napi_value WrapApiAccount(napi_env env, napi_callback_info info)
{
    return StartApiJob(env, info, 3, 1, 2048);
}

static napi_value WrapApiRelays(napi_env env, napi_callback_info info)
{
    return StartApiJob(env, info, 4, 0, 1024);
}

static napi_value WrapOpenUdp(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    char host[256] = { 0 };
    size_t length = 0;
    int32_t port = 0;
    if (argc >= 1) {
        napi_get_value_string_utf8(env, argv[0], host, sizeof(host), &length);
    }
    if (argc >= 2) {
        napi_get_value_int32(env, argv[1], &port);
    }

    napi_value result;
    napi_create_int32(env, mh_open_udp(host, port), &result);
    return result;
}

static napi_value WrapAttachTun(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    int32_t fd = -1;
    int32_t mtu = 1420;
    if (argc >= 1) {
        napi_get_value_int32(env, argv[0], &fd);
    }
    if (argc >= 2) {
        napi_get_value_int32(env, argv[1], &mtu);
    }

    napi_value result;
    napi_create_int32(env, mh_attach_tun(fd, mtu), &result);
    return result;
}

static napi_value WrapOpenRelaySocket(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    int32_t family = 4;
    if (argc >= 1) {
        napi_get_value_int32(env, argv[0], &family);
    }
    napi_value result;
    napi_create_int32(env, mh_open_relay_socket(family), &result);
    return result;
}

static napi_value WrapStats(napi_env env, napi_callback_info info)
{
    (void)info;
    char buffer[512] = { 0 };
    int32_t written = mh_stats(buffer, (int32_t)sizeof(buffer));
    size_t length = written > 0 ? (size_t)written : 0;

    napi_value result;
    napi_create_string_utf8(env, buffer, length, &result);
    return result;
}

static napi_value WrapStop(napi_env env, napi_callback_info info)
{
    (void)info;
    mh_stop();

    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

EXTERN_C_START
static napi_value Init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        { "init", NULL, WrapInit, NULL, NULL, NULL, napi_default, NULL },
        { "wgKey", NULL, WrapWgKey, NULL, NULL, NULL, napi_default, NULL },
        { "rotateKey", NULL, WrapRotateKey, NULL, NULL, NULL, napi_default, NULL },
        { "deviceKey", NULL, WrapDeviceKey, NULL, NULL, NULL, napi_default, NULL },
        { "clearKey", NULL, WrapClearKey, NULL, NULL, NULL, napi_default, NULL },
        { "openUdp", NULL, WrapOpenUdp, NULL, NULL, NULL, napi_default, NULL },
        { "attachTun", NULL, WrapAttachTun, NULL, NULL, NULL, napi_default, NULL },
        { "openRelaySocket", NULL, WrapOpenRelaySocket, NULL, NULL, NULL, napi_default, NULL },
        { "stats", NULL, WrapStats, NULL, NULL, NULL, napi_default, NULL },
        { "stop", NULL, WrapStop, NULL, NULL, NULL, napi_default, NULL },
        { "setDirectAllowed", NULL, WrapSetDirectAllowed, NULL, NULL, NULL, napi_default, NULL },
        { "apiLogin", NULL, WrapApiLogin, NULL, NULL, NULL, napi_default, NULL },
        { "apiDevices", NULL, WrapApiDevices, NULL, NULL, NULL, napi_default, NULL },
        { "apiRemoveDevice", NULL, WrapApiRemoveDevice, NULL, NULL, NULL, napi_default, NULL },
        { "apiAccount", NULL, WrapApiAccount, NULL, NULL, NULL, napi_default, NULL },
        { "apiRelays", NULL, WrapApiRelays, NULL, NULL, NULL, napi_default, NULL },
        { "tunnelStart", NULL, WrapTunnelStart, NULL, NULL, NULL, napi_default, NULL },
        { "tunnelStatus", NULL, WrapTunnelStatus, NULL, NULL, NULL, napi_default, NULL },
        { "tunnelStop", NULL, WrapTunnelStop, NULL, NULL, NULL, napi_default, NULL },
        { "setDiagnostics", NULL, WrapSetDiagnostics, NULL, NULL, NULL, napi_default, NULL },
        { "setIpVersion", NULL, WrapSetIpVersion, NULL, NULL, NULL, napi_default, NULL },
        { "logMarker", NULL, WrapLogMarker, NULL, NULL, NULL, napi_default, NULL },
        { "logLine", NULL, WrapLogLine, NULL, NULL, NULL, napi_default, NULL },
    };

    napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties);
    return exports;
}
EXTERN_C_END

static napi_module yanshuModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = NULL,
    .nm_register_func = Init,
    .nm_modname = "yanshu",
    .nm_priv = NULL,
    .reserved = { 0 },
};

__attribute__((constructor)) static void RegisterYanshuModule(void)
{
    napi_module_register(&yanshuModule);
}
