#!/usr/bin/env bash
# setup.sh — Create namespaces, veth pairs, and bridges.
# TAP interfaces (tap_devx, tap_devy) are created by server_tap / client_tap at runtime.

set -euo pipefail
MTU=1500

echo ""
echo "=== [1/5] Cleaning up any previous state ==="
ip netns del ns_devx  2>/dev/null && echo "  removed ns_devx"  || true
ip netns del ns_devy  2>/dev/null && echo "  removed ns_devy"  || true
ip link del br_client 2>/dev/null && echo "  removed br_client" || true
ip link del br_server 2>/dev/null && echo "  removed br_server" || true
ip link del veth_xh   2>/dev/null && echo "  removed veth_xh"  || true
ip link del veth_yh   2>/dev/null && echo "  removed veth_yh"  || true
ip link del tap_devx  2>/dev/null && echo "  removed tap_devx" || true
ip link del tap_devy  2>/dev/null && echo "  removed tap_devy" || true

echo ""
echo "=== [2/5] Creating network namespaces ==="
ip netns add ns_devx
ip netns add ns_devy
echo "  ✓ ns_devx"
echo "  ✓ ns_devy"

echo ""
echo "=== [3/5] Creating veth pairs ==="
ip link add veth_x type veth peer name veth_xh
ip link set veth_x netns ns_devx
echo "  ✓ veth_x (in ns_devx) <--> veth_xh (host)"

ip link add veth_y type veth peer name veth_yh
ip link set veth_y netns ns_devy
echo "  ✓ veth_y (in ns_devy) <--> veth_yh (host)"

echo ""
echo "=== [4/5] Creating L2 bridges ==="
ip link add name br_client type bridge
ip link set br_client mtu $MTU up
ip link set veth_xh   mtu $MTU up
ip link set veth_xh   master br_client
echo "  ✓ br_client  (veth_xh attached, tap_devx joins at runtime)"

ip link add name br_server type bridge
ip link set br_server mtu $MTU up
ip link set veth_yh   mtu $MTU up
ip link set veth_yh   master br_server
echo "  ✓ br_server  (veth_yh attached, tap_devy joins at runtime)"

echo ""
echo "=== [5/5] Configuring namespaces ==="
ip netns exec ns_devx ip link set lo     up
ip netns exec ns_devx ip link set veth_x mtu $MTU up
ip netns exec ns_devx ip addr add 10.0.0.10/24 dev veth_x
echo "  ✓ ns_devx: veth_x = 10.0.0.10/24"

ip netns exec ns_devy ip link set lo     up
ip netns exec ns_devy ip link set veth_y mtu $MTU up
ip netns exec ns_devy ip addr add 10.0.0.20/24 dev veth_y
echo "  ✓ ns_devy: veth_y = 10.0.0.20/24"

sysctl -qw net.ipv4.ip_forward=1

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  setup.sh done!  Now open 4 terminals:                      ║"
echo "║                                                              ║"
echo "║  Terminal 1:  sudo ./server_tap                              ║"
echo "║  Terminal 2:  sudo ./client_tap                              ║"
echo "║  Terminal 3:  sudo ip netns exec ns_devy ./device_y          ║"
echo "║  Terminal 4:  sudo ip netns exec ns_devx ./device_x          ║"
echo "╚══════════════════════════════════════════════════════════════╝"