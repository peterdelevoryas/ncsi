#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <signal.h>

int main(int argc, char** argv) {
  if (argc < 2) {
    printf("Usage: %s <interface name>\n", argv[0]);
    return 1;
  }
  const char *ifname = argv[1];
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

  struct sockaddr_ll sll = {
    .sll_family = AF_PACKET,
    .sll_protocol = htons(ETH_P_ALL),
    .sll_ifindex = ifindex,
    .sll_pkttype = PACKET_BROADCAST,
  };
  if (bind(fd, reinterpret_cast<const sockaddr*>(&sll), sizeof(sll)) != 0) {
    perror("bind");
    close(fd);
    return 1;
  }

  for (int i = 0; i < 3; i++) {
    static uint8_t buf[1500];
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    switch (n) {
      case -1:
        perror("recv");
        goto done;
      case 0:
        perror("recv 0");
        break;
      default:
        for (ssize_t j = 0; j < n; j++) {
          printf("%02x ", buf[j]);
        }
        printf("\n");
        break;
    }
  }

done:
  close(fd);
}
