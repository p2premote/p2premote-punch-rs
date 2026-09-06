/* Real iptables/sysctl round-trip test for the Linux subnet router. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern char* StartSubnetRouter(char*);
extern char* StopSubnetRouter(char*);
extern char* GetSubnetRouterStatus(char*);
extern void FreeCString(char*);

static int run(const char* cmd) { return system(cmd); }

int main(void) {
    run("iptables -t nat -F POSTROUTING >/dev/null 2>&1"); // start clean-ish
    run("iptables -F FORWARD >/dev/null 2>&1");

    char* r = StartSubnetRouter(
        "{\"session_id\":59,\"peer_device_id\":58,"
        "\"peer_tail_ip\":\"100.99.71.2\","
        "\"listen_ip\":\"127.0.0.1\",\"listen_port\":51820,"
        "\"exposed_lan_cidrs\":[\"192.168.10.0/24\"],"
        "\"snat\":true,\"allow_tcp\":true,\"allow_udp\":true,\"allow_icmp_echo\":true}");
    printf("START: %s\n", r);
    if (strstr(r, "\"ok\":true") == NULL) {
        FreeCString(r);
        return 1;
    }
    char handle[128];
    const char* h = strstr(r, "\"handle_id\":\"");
    sscanf(h + 13, "%[^\"]", handle);
    FreeCString(r);

    int chains = system("iptables -nL P2PREMOTE-FWD >/dev/null 2>&1") == 0
        && system("iptables -t nat -nL P2PREMOTE-NAT >/dev/null 2>&1") == 0;
    int masq = system("iptables -t nat -nL P2PREMOTE-NAT | grep -q MASQUERADE") == 0;
    int fwd = system("iptables -nL P2PREMOTE-FWD | grep -q 192.168.10.0/24") == 0;
    printf("chains=%d masquerade=%d forward_rules=%d\n", chains, masq, fwd);

    char status_input[256];
    snprintf(status_input, sizeof status_input, "{\"handle_id\":\"%s\"}", handle);
    char* s = GetSubnetRouterStatus(status_input);
    printf("STATUS: %s\n", s);
    FreeCString(s);

    char stop_input[256];
    snprintf(stop_input, sizeof stop_input, "{\"handle_id\":\"%s\"}", handle);
    char* st = StopSubnetRouter(stop_input);
    printf("STOP: %s\n", st);
    FreeCString(st);

    int gone = system("iptables -nL P2PREMOTE-FWD >/dev/null 2>&1") != 0
        && system("iptables -t nat -nL P2PREMOTE-NAT >/dev/null 2>&1") != 0;
    printf("chains_removed=%d\n", gone);

    int ok = chains && masq && fwd && gone;
    printf(ok ? "SUBNET ROUTER TEST PASS\n" : "SUBNET ROUTER TEST FAIL\n");
    return ok ? 0 : 1;
}
