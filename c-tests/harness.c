/* Link-time smoke test for libp2premote_punch.a (musl).
 * Verifies every exported symbol links and the JSON contract behaves. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern char* StartUdpTunnel(char*);
extern char* StopUdpTunnel(char*);
extern char* StartSubnetRouter(char*);
extern char* StopSubnetRouter(char*);
extern char* GetSubnetRouterStatus(char*);
extern char* GetWgCapabilities(char*);
extern char* GenerateWgKeypair(char*);
extern char* StartUserspaceWgPeer(char*);
extern char* StopUserspaceWgPeer(char*);
extern char* GetUserspaceWgPeerStatus(char*);
extern char* SetUserspaceWgPeerAllowed(char*);
extern char* StopUserspaceWgEngine(char*);
extern char* CleanupUserspaceWgPlatform(char*);
extern char* StartWindowsWgPeer(char*);
extern char* Exchange(char*);
extern void FreeCString(char*);
extern int P2PremotePunchRsAbiVersion(void);

static int failures = 0;

static void check(const char* name, const char* got, const char* needle) {
    int ok = strstr(got, needle) != NULL;
    printf("%-28s %s -> %s\n", name, ok ? "PASS" : "FAIL", got);
    if (!ok) failures++;
}

int main(void) {
    printf("abi_version=%d\n", P2PremotePunchRsAbiVersion());

    char* r;

    r = GetWgCapabilities(NULL);
    check("GetWgCapabilities", r, "\"abi_version\":2");
    FreeCString(r);

    r = StartUdpTunnel("{");
    check("StartUdpTunnel invalid json", r, "\"ok\":false");
    FreeCString(r);

    r = StartUdpTunnel("{\"network\":\"tcp4\",\"remote_target_port\":51820}");
    check("StartUdpTunnel no token", r, "\"ok\":false");
    FreeCString(r);

    r = StartUdpTunnel("{\"token\":\"t\",\"traversal_mode\":\"bogus\",\"remote_target_port\":51820}");
    check("StartUdpTunnel bad traversal", r, "traversal_mode");
    FreeCString(r);

    r = StopUdpTunnel("{\"handle_id\":\"missing\"}");
    check("StopUdpTunnel idempotent", r, "\"ok\":true");
    FreeCString(r);

    r = StartSubnetRouter("{\"session_id\":59,\"peer_device_id\":58,\"listen_port\":51820}");
    check("StartSubnetRouter no cidrs", r, "exposed_lan_cidrs");
    FreeCString(r);

    r = GetSubnetRouterStatus("{}");
    check("GetSubnetRouterStatus no handle", r, "handle_id");
    FreeCString(r);

    r = StopSubnetRouter("{\"handle_id\":\"missing\"}");
    check("StopSubnetRouter idempotent", r, "\"ok\":true");
    FreeCString(r);

    r = GenerateWgKeypair(NULL);
    check("GenerateWgKeypair stub", r, "\"ok\":false");
    FreeCString(r);

    r = StartUserspaceWgPeer("{\"handle_id\":\"h\",\"session_id\":1,\"peer_device_id\":1}");
    check("StartUserspaceWgPeer stub", r, "\"ok\":false");
    FreeCString(r);

    r = StartWindowsWgPeer("{\"handle_id\":\"h\",\"session_id\":1,\"peer_device_id\":1}");
    check("StartWindowsWgPeer alias", r, "\"ok\":false");
    FreeCString(r);

    r = Exchange("{\"send_data\":\"x\"}");
    check("Exchange no token", r, "token is required");
    FreeCString(r);

    r = Exchange(NULL);
    check("Exchange null", r, "input is null");
    FreeCString(r);

    printf(failures == 0 ? "ALL PASS\n" : "FAILURES: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
