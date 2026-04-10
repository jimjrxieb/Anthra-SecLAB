#!/usr/bin/env bash
set -euo pipefail

# Layer 2 — Attacker Container
#
# Launches a privileged container on the k3d-seclab Docker network
# with L2 attack and detection tools installed. This simulates an
# attacker who has gained access to the same network segment as
# the k3s cluster nodes.
#
# USAGE:
#   ./attacker-container.sh up      # Launch the attacker container
#   ./attacker-container.sh shell   # Attach to running container
#   ./attacker-container.sh down    # Remove the container
#
# Once inside:
#   arpspoof -i eth0 -t 172.19.0.3 172.19.0.5   # poison server → agent
#   tshark -i eth0 -f "arp" -a duration:60       # capture ARP traffic
#   arpwatch -d -i eth0                           # monitor ARP changes

CONTAINER_NAME="seclab-attacker"
NETWORK="k3d-seclab"

usage() {
    echo "Usage: $0 {up|shell|down}"
    echo ""
    echo "  up    — Launch attacker container on k3d-seclab network"
    echo "  shell — Attach to running attacker container"
    echo "  down  — Remove attacker container"
    exit 1
}

if [[ $# -ne 1 ]]; then
    usage
fi

case "$1" in
    up)
        # Check if already running
        if docker ps -q -f "name=$CONTAINER_NAME" | grep -q .; then
            echo "[*] Attacker container already running."
            echo "[*] Attach with: $0 shell"
            exit 0
        fi

        # Remove stale container if exists
        docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

        echo "============================================"
        echo "Layer 2 — Launching Attacker Container"
        echo "============================================"
        echo ""
        echo "[*] Network:   $NETWORK"
        echo "[*] Container: $CONTAINER_NAME"
        echo ""

        echo "[*] Building attacker image with L2 tools..."
        docker build -t seclab-attacker -f - . <<'DOCKERFILE'
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq \
    dsniff \
    arpwatch \
    tshark \
    arping \
    net-tools \
    tcpdump \
    iproute2 \
    iputils-ping \
    curl \
    nmap \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /evidence
CMD ["/bin/bash"]
DOCKERFILE

        echo ""
        echo "[*] Launching container on $NETWORK..."
        docker run -d \
            --name "$CONTAINER_NAME" \
            --network "$NETWORK" \
            --cap-add NET_RAW \
            --cap-add NET_ADMIN \
            -v /tmp/sc7-attacker-evidence:/evidence \
            seclab-attacker \
            sleep infinity

        # Get container IP
        ATTACKER_IP=$(docker inspect "$CONTAINER_NAME" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')

        echo ""
        echo "[+] Attacker container running."
        echo ""
        echo "[*] Attacker IP: $ATTACKER_IP"
        echo "[*] Targets on this network:"
        docker network inspect "$NETWORK" --format '{{range .Containers}}  {{.Name}}  {{.IPv4Address}}{{"\n"}}{{end}}'
        echo ""
        echo "[*] Attach with: $0 shell"
        echo ""
        echo "============================================"
        echo "Once inside, you are on the same L2 segment"
        echo "as the k3s nodes. Interface is eth0."
        echo ""
        echo "Quick start:"
        echo "  # 1. Check your position"
        echo "  arp -n"
        echo "  ip addr show eth0"
        echo ""
        echo "  # 2. Run detection in background"
        echo "  arpwatch -d -i eth0 &"
        echo ""
        echo "  # 3. Run the attack"
        echo "  echo 1 > /proc/sys/net/ipv4/ip_forward"
        echo "  arpspoof -i eth0 -t 172.19.0.3 172.19.0.5"
        echo "============================================"
        ;;

    shell)
        if ! docker ps -q -f "name=$CONTAINER_NAME" | grep -q .; then
            echo "[ERROR] Attacker container not running. Start with: $0 up"
            exit 1
        fi
        echo "[*] Attaching to $CONTAINER_NAME..."
        echo "[*] Type 'exit' to detach (container keeps running)"
        echo ""
        docker exec -it "$CONTAINER_NAME" /bin/bash
        ;;

    down)
        echo "[*] Removing attacker container..."
        docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
        echo "[+] Container removed."
        echo ""
        echo "[*] Evidence saved to: /tmp/sc7-attacker-evidence/"
        if [[ -d /tmp/sc7-attacker-evidence ]]; then
            ls -la /tmp/sc7-attacker-evidence/
        fi
        ;;

    *)
        usage
        ;;
esac
