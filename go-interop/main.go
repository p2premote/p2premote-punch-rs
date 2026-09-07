// p2premote-punch-rs interop harness (temporary, not committed).
//
// Usage:
//
//	go run ./tmp-interop exchange <exmode> <token> <senddata>
//	go run ./tmp-interop tunnel <active|passive> <token> [wgPort]
//
// tunnel binds an ACK echo server on wgPort (default 53820/53821), starts
// easyp2p.StartUDPTunnel exactly like the desktop client, prints
// "RESULT <json>" and "RECV <data>" lines, and replies "ACK-<data>".
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/p2premote/p2premote-punch/easyp2p"
)

func main() {
	if len(os.Args) < 3 {
		die("usage: interop exchange|tunnel ...")
	}
	switch os.Args[1] {
	case "exchange":
		exchange(os.Args[2:])
	case "tunnel":
		tunnel(os.Args[2:])
	default:
		die("unknown mode " + os.Args[1])
	}
}

func die(msg string) {
	fmt.Fprintln(os.Stderr, "FATAL:", msg)
	os.Exit(1)
}

func exchange(args []string) {
	if len(args) < 3 {
		die("usage: exchange <exmode 0|1|2> <token> <senddata>")
	}
	exmode, _ := strconv.Atoi(args[0])
	token, data := args[1], args[2]
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	recv, err := easyp2p.MQTT_ExchangePayload(ctx, exmode, data, token, "wgvpn-kx/", "", 60*time.Second)
	if err != nil {
		die(err.Error())
	}
	out, _ := json.Marshal(map[string]string{"ok": "true", "recv_data": recv})
	fmt.Println("RESULT", string(out))
}

func tunnel(args []string) {
	if len(args) < 2 {
		die("usage: tunnel <active|passive> <token> [wgPort]")
	}
	role, token := args[0], args[1]
	wgPort := 0
	if role == "active" {
		wgPort = 53820
		if len(args) > 2 {
			wgPort, _ = strconv.Atoi(args[2])
		}
	} else {
		wgPort = 53821
		if len(args) > 2 {
			wgPort, _ = strconv.Atoi(args[2])
		}
	}

	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: wgPort})
	if err != nil {
		die("bind wg port: " + err.Error())
	}
	go echoLoop(echo)

	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	result, err := startTunnel(ctx, role, token, wgPort)
	if err != nil {
		out, _ := json.Marshal(map[string]string{"ok": "false", "error": err.Error()})
		fmt.Println("RESULT", string(out))
		time.Sleep(5 * time.Second)
		return
	}
	out, _ := json.Marshal(result)
	fmt.Println("RESULT", string(out))
	fmt.Println("FORWARD_PORT", strconv.Itoa(result.LocalForwardPort))

	// passive side drives pings after a short delay
	if role == "passive" {
		go func() {
			time.Sleep(3 * time.Second)
			sendPings(result.LocalForwardPort, wgPort)
		}()
	}
	time.Sleep(45 * time.Second)
}

func startTunnel(ctx context.Context, role, token string, wgPort int) (*easyp2p.UDPTunnelResult, error) {
	logs := os.Stderr
	if os.Getenv("GO_QUIET") != "" {
		logs = nil
	}
	tunnel, err := easyp2p.StartUDPTunnel(ctx, easyp2p.UDPTunnelRequest{
		Token:            token,
		RoleHint:         role,
		TraversalMode:    "auto",
		Network:          "udp4",
		TimeoutSecs:      60,
		RemoteTargetIP:   "127.0.0.1",
		RemoteTargetPort: wgPort,
		LocalListenIP:    "127.0.0.1",
	}, logs)
	if err != nil {
		if result, ok := easyp2p.UDPTunnelResultFromError(err); ok {
			return &result, nil
		}
		return nil, err
	}
	result := tunnel.Result()
	return &result, nil
}

func echoLoop(conn *net.UDPConn) {
	buf := make([]byte, 2048)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		data := string(buf[:n])
		fmt.Println("RECV", strconv.Quote(data))
		conn.WriteToUDP([]byte("ACK-"+data), addr)
	}
}

func sendPings(forwardPort, srcPort int) {
	local := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: srcPort}
	target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: forwardPort}
	conn, err := net.DialUDP("udp4", local, target)
	if err != nil {
		die("ping dial: " + err.Error())
	}
	defer conn.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			fmt.Println("PONG", strconv.Quote(string(buf[:n])))
		}
	}()
	for i := 0; i < 40; i++ {
		conn.Write([]byte("ping"))
		time.Sleep(1 * time.Second)
	}
}
