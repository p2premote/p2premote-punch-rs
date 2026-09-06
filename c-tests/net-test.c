/* Network-stack smoke: Exchange in waitOnly mode must reach the public MQTT
 * brokers and time out waiting (proves DNS + TCP + MQTT + TLS-free path). */
#include <stdio.h>
#include <string.h>

extern char* Exchange(char*);
extern void FreeCString(char*);

int main(int argc, char** argv) {
    const char* token = argc > 1 ? argv[1] : "net-smoke-token";
    char input[512];
    snprintf(input, sizeof input,
             "{\"token\":\"%s\",\"exmode\":0,\"send_data\":\"x\",\"timeout_secs\":120}", token);
    char* r = Exchange(input);
    printf("RESULT: %s\n", r);
    /* Timeout (broker connected, no peer) is the expected success path. */
    int ok = strstr(r, "timeout waiting for remote data exchange") != NULL;
    FreeCString(r);
    printf(ok ? "NET TEST PASS\n" : "NET TEST FAIL\n");
    return ok ? 0 : 1;
}
