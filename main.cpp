#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <signal.h>

static int SOCKET = -1;

static void handle_ctrl_c(int sig) {
  close(SOCKET);
  exit(0);
}

static void print_eth_addr(const uint8_t addr[ETH_ALEN]) {
  for (int i = 0; i < ETH_ALEN; i++) {
    if (i) {
      printf(":");
    }
    printf("%02x", addr[i]);
  }
}

struct NcsiHeader {
  uint8_t mc_id;
  uint8_t header_revision;
  uint8_t reserved0;
  uint8_t iid;
  uint8_t control_packet_type;
  uint8_t channel_id;
  uint8_t reserved1;
  uint8_t payload_length;
  uint32_t reserved2;
  uint32_t reserved3;
};

enum NcsiCommand {
  CLEAR_INITIAL_STATE = 0x00,
  SELECT_PACKAGE = 0x01,
  DESELECT_PACKAGE = 0x02,
  ENABLE_CHANNEL = 0x03,
  DISABLE_CHANNEL = 0x04,
  RESET_CHANNEL = 0x05,
  ENABLE_CHANNEL_NETWORK_TX = 0x06,
  DISABLE_CHANNEL_NETWORK_TX = 0x07,
  AEN_ENABLE = 0x08,
  SET_LINK = 0x09,
  GET_LINK_STATUS = 0x0A,
  SET_VLAN_FILTER = 0x0B,
  ENABLE_VLAN = 0x0C,
  DISABLE_VLAN = 0x0D,
  SET_MAC_ADDRESS = 0x0E,
  ENABLE_BROADCAST_FILTERING = 0x10,
  DISABLE_BROADCAST_FILTERING = 0x11,
  ENABLE_GLOBAL_MULTICAST_FILTERING = 0x12,
  DISABLE_GLOBAL_MULTICAST_FILTERING = 0x13,
  SET_NCSI_FLOW_CONTROL = 0x14,
  GET_VERSION_ID = 0x15,
  GET_CAPABILITIES = 0x16,
  GET_PARAMETERS = 0x17,
  GET_CONTROLLER_PACKET_STATISTICS = 0x18,
  GET_NCSI_STATISTICS = 0x19,
  GET_NCSI_PASSTHROUGH_STATISTICS = 0x1A,
  OEM_COMMAND = 0x50,
};

static const char* ncsi_type_to_string(uint8_t type) {
  type &= 0x80 - 1;
  switch (type) {
    case 0x00:
      return "Clear Initial State";
    case 0x01:
      return "Select Package";
    case 0x02:
      return "Deselect Package";
    case 0x03:
      return "Enable Channel";
    case 0x04:
      return "Disable Channel";
    case 0x05:
      return "Reset Channel";
    case 0x06:
      return "Enable Channel Network TX";
    case 0x07:
      return "Disable Channel Network TX";
    case 0x08:
      return "AEN Enable";
    case 0x09:
      return "Set Link";
    case 0x0A:
      return "Get Link Status";
    case 0x0B:
      return "Set VLAN Filter";
    case 0x0C:
      return "Enable VLAN";
    case 0x0D:
      return "Disable VLAN";
    case 0x0E:
      return "Set MAC Address";
    case 0x10:
      return "Enable Broadcast Filtering";
    case 0x11:
      return "Disable Broadcast Filtering";
    case 0x12:
      return "Enable Global Multicast Filtering";
    case 0x13:
      return "Disable Global Multicast Filtering";
    case 0x14:
      return "Set NC-SI Flow Control";
    case 0x15:
      return "Get Version ID";
    case 0x16:
      return "Get Capabilities";
    case 0x17:
      return "Get Parameters";
    case 0x18:
      return "Get Controller Packet Statistics";
    case 0x19:
      return "Get NC-SI Statistics";
    case 0x1A:
      return "Get NC-SI Pass-through Statistics";
    case 0x50:
      return "OEM Command";
    default:
      return nullptr;
  }
}

static void print_packet(const uint8_t* pkt, int len) {
  auto eth = reinterpret_cast<const ether_header&>(*pkt);
  print_eth_addr(eth.ether_shost);
  printf(" ");
  print_eth_addr(eth.ether_dhost);

  auto ethertype = ntohs(eth.ether_type);
  printf(" %04x", ethertype);

  if (ethertype != 0x88f8) {
    printf("\n");
    return;
  }
  if (uint32_t(len) < ETH_HLEN + sizeof(NcsiHeader)) {
    printf(": len is too small for NCSI header: %d\n", len);
    return;
  }
  auto ncsi = reinterpret_cast<const NcsiHeader&>(*&pkt[ETH_HLEN]);
  printf(" %02x %s\n", ncsi.control_packet_type,
         ncsi_type_to_string(ncsi.control_packet_type));
}

constexpr auto NCSI_MAX_PAYLOAD = 172;
constexpr auto NCSI_MAX_LEN = sizeof(NcsiHeader) + NCSI_MAX_PAYLOAD + 4;

static void deselect_package(const NcsiHeader& command) {
  uint8_t response[ETH_HLEN + NCSI_MAX_LEN];
  //uint32_t len = ETH_HLEN;
  memset(response, 0xFF, ETH_ALEN * 2);
}

static void handle_ncsi_command(const NcsiHeader& command) {
  switch (command.control_packet_type) {
    case DESELECT_PACKAGE:
      deselect_package(command);
      break;
    default:
      printf("Unimplemented NCSI command: %02x %s\n",
             command.control_packet_type,
             ncsi_type_to_string(command.control_packet_type));
      break;
  }
}

static void handle_packet(const uint8_t* pkt, int len) {
  print_packet(pkt, len);

  auto eth = reinterpret_cast<const ether_header&>(*pkt);
  if (ntohs(eth.ether_type) != 0x88f8) {
    return;
  }
  if (uint32_t(len) < ETH_HLEN + sizeof(NcsiHeader)) {
    printf(": len is too small for NCSI header: %d\n", len);
    return;
  }
  auto command = reinterpret_cast<const NcsiHeader&>(*&pkt[ETH_HLEN]);
  handle_ncsi_command(command);
}

int main(int argc, char** argv) {
  signal(SIGINT, handle_ctrl_c);

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
  SOCKET = fd;

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

  for (;;) {
    static uint8_t buf[1500];
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    switch (n) {
      case -1:
        perror("recv");
        return 1;
      case 0:
        perror("recv 0");
        break;
      default:
        handle_packet(buf, static_cast<int>(n));
        break;
    }
  }
}
