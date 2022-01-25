#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cassert>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <signal.h>
#include <fcntl.h>

extern "C" {
#include "ncsi.h"
};

static uint16_t Ethertype(const uint8_t* pkt, size_t len) {
  assert(len >= 14);
  auto p = reinterpret_cast<const uint16_t*>(&pkt[12]);
  return ntohs(*p);
}

int main(int argc, char** argv) {
  if (argc < 2) {
    printf("Usage: %s <interface name>\n", argv[0]);
    return 1;
  }
  const char* ifname = argv[1];
  int ifindex = if_nametoindex(ifname);
  if (ifindex == 0) {
    perror("if_nametoindex");
    return 1;
  }

  int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (fd == -1) {
    perror("socket");
    return 1;
  }
  if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
    perror("fcntl");
    close(fd);
    return 1;
  }

  struct sockaddr_ll sll = {
    .sll_family = AF_PACKET,
    .sll_protocol = htons(ETH_P_ALL),
    .sll_ifindex = ifindex,
    .sll_pkttype = PACKET_BROADCAST,
  };
  if (bind(fd, reinterpret_cast<const sockaddr*>(&sll), sizeof(sll)) != 0) {
    perror("bind");
    return 1;
  }

  auto slirp = Slirp {
    .mfr_id = 0x8119,
    .ncsi_mac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
    .socket = fd,
  };

  for (;;) {
    uint8_t pkt[64];
    ssize_t r = recv(fd, &pkt, sizeof(pkt), 0);
    switch (r) {
      case -1:
      case 0:
        perror("recv");
        continue;
    }
    size_t len = size_t(r);
    if (len < ETH_HLEN) {
      printf("Packet is too small to have an ethernet header\n");
      continue;
    }
    if (Ethertype(pkt, len) != ETH_P_NCSI) {
      continue;
    }
    ncsi_input(&slirp, pkt, int(len));

    // if (send(fd, &response, sizeof(response), 0) != ssize_t(sizeof(response))) {
    //   perror("send");
    // }
  }
}
