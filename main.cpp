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
#include <fcntl.h>

template<typename T>
T max(T a, T b) {
  return a >= b ? a : b;
}

constexpr uint16_t NCSI_ETHERTYPE = 0x88f8;
constexpr size_t ETHERNET_MIN_FRAME_SIZE = 64;

struct EthernetHeader {
  uint8_t src[6];
  uint8_t dst[6];
  __be16 type;
};

struct NcsiHeader {
  uint8_t mc_id;
  uint8_t header_revision;
  uint8_t reserved0;
  uint8_t iid;
  uint8_t type;
  uint8_t channel_id;
  __be16 payload_length;
  uint32_t reserved2;
  uint32_t reserved3;
};

struct __attribute__((packed)) NcsiCommandPacket {
  EthernetHeader eth;
  NcsiHeader ncsi;
  __be32 checksum;
  uint8_t min_size_padding[
    ETHERNET_MIN_FRAME_SIZE
    - sizeof(EthernetHeader)
    - sizeof(NcsiHeader)
    - sizeof(__be32)
  ];
};

struct __attribute__((packed)) NcsiResponsePacket {
  EthernetHeader eth;
  NcsiHeader ncsi;
  __be16 code;
  __be16 reason;
  __be32 checksum;
  uint8_t min_size_padding[
    ETHERNET_MIN_FRAME_SIZE
    - sizeof(EthernetHeader)
    - sizeof(NcsiHeader)
    - sizeof(__be16) * 2
    - sizeof(__be32)
  ];
};

static_assert(sizeof(NcsiCommandPacket) == ETHERNET_MIN_FRAME_SIZE, "");
static_assert(sizeof(NcsiResponsePacket) == ETHERNET_MIN_FRAME_SIZE, "");

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

enum NcsiCode {
  COMMAND_COMPLETED = 0x000,
  COMMAND_FAILED = 0x0001,
  COMMAND_UNAVAILABLE = 0x0002,
  COMMAND_UNSUPPORTED = 0x0003,
};

enum NcsiReason {
  NO_ERROR_REASON = 0x000,
  INTERFACE_INITIALIZATION_REQUIRED = 0x0001,
  PARAMETER_IS_INVALID = 0x0002,
  CHANNEL_NOT_READY = 0x0003,
  PACKAGE_NOT_READY = 0x0004,
  INVALID_PAYLOAD_LENGTH = 0x0005,
  UNSUPPORTED_COMMAND_TYPE = 0x7FFF,
};

// static const char* NcsiTypeToString(uint8_t type) {
//   type &= 0x80 - 1;
//   switch (type) {
//     case 0x00:
//       return "Clear Initial State";
//     case 0x01:
//       return "Select Package";
//     case 0x02:
//       return "Deselect Package";
//     case 0x03:
//       return "Enable Channel";
//     case 0x04:
//       return "Disable Channel";
//     case 0x05:
//       return "Reset Channel";
//     case 0x06:
//       return "Enable Channel Network TX";
//     case 0x07:
//       return "Disable Channel Network TX";
//     case 0x08:
//       return "AEN Enable";
//     case 0x09:
//       return "Set Link";
//     case 0x0A:
//       return "Get Link Status";
//     case 0x0B:
//       return "Set VLAN Filter";
//     case 0x0C:
//       return "Enable VLAN";
//     case 0x0D:
//       return "Disable VLAN";
//     case 0x0E:
//       return "Set MAC Address";
//     case 0x10:
//       return "Enable Broadcast Filtering";
//     case 0x11:
//       return "Disable Broadcast Filtering";
//     case 0x12:
//       return "Enable Global Multicast Filtering";
//     case 0x13:
//       return "Disable Global Multicast Filtering";
//     case 0x14:
//       return "Set NC-SI Flow Control";
//     case 0x15:
//       return "Get Version ID";
//     case 0x16:
//       return "Get Capabilities";
//     case 0x17:
//       return "Get Parameters";
//     case 0x18:
//       return "Get Controller Packet Statistics";
//     case 0x19:
//       return "Get NC-SI Statistics";
//     case 0x1A:
//       return "Get NC-SI Pass-through Statistics";
//     case 0x50:
//       return "OEM Command";
//     default:
//       return nullptr;
//   }
// }

// static void PrintPacket(const uint8_t* pkt, int len) {
//   auto eth = reinterpret_cast<const ether_header&>(*pkt);
//   PrintEthAddr(eth.ether_shost);
//   printf(" ");
//   PrintEthAddr(eth.ether_dhost);
// 
//   auto ethertype = ntohs(eth.ether_type);
//   printf(" %04x", ethertype);
// 
//   if (ethertype != 0x88f8) {
//     printf("\n");
//     return;
//   }
//   if (uint32_t(len) < ETH_HLEN + sizeof(NcsiHeader)) {
//     printf(": len is too small for NCSI header: %d\n", len);
//     return;
//   }
//   auto ncsi = reinterpret_cast<const NcsiHeader&>(*&pkt[ETH_HLEN]);
//   printf(" %02x %s\n", ncsi.control_packet_type,
//          NcsiTypeToString(ncsi.control_packet_type));
// }
// 
// constexpr auto NCSI_MAX_PAYLOAD = 172;
// constexpr auto NCSI_MAX_LEN = sizeof(NcsiHeader)
//                             + NCSI_MAX_PAYLOAD + 4;
// 
// static void DeselectPackage(const NcsiHeader& command) {
//   uint8_t pkt[ETH_HLEN + NCSI_MAX_LEN];
//   memset(pkt, 0, sizeof(pkt));
// 
//   auto eth = reinterpret_cast<ether_header&>(*&pkt[0]);
//   memset(&eth.ether_dhost, 0xFF, ETH_ALEN);
//   memset(&eth.ether_shost, 0xFF, ETH_ALEN);
//   eth.ether_type = htons(0x88f8);
// 
//   auto response = reinterpret_cast<NcsiHeader&>(*&pkt[ETH_HLEN]);
//   response.mc_id = 0x00; // Should be copied from command for AEN.
//   response.header_revision = 0x01;
//   response.iid = command.iid;
//   response.control_packet_type = 0x80 + command.control_packet_type;
//   response.channel_id = command.channel_id;
//   response.payload_length = htons(4);
//   response.code = htons(COMMAND_COMPLETED);
//   response.reason = htons(NO_ERROR_REASON);
// }
// 
// static void HandleNcsiCommand(const NcsiHeader& command) {
//   switch (command.control_packet_type) {
//     case DESELECT_PACKAGE:
//       DeselectPackage(command);
//       break;
//     default:
//       printf("Unimplemented NCSI command: %02x %s\n",
//              command.control_packet_type,
//              NcsiTypeToString(command.control_packet_type));
//       break;
//   }
// }
// 
// static void HandlePacket(const uint8_t* pkt, int len) {
//   PrintPacket(pkt, len);
// 
//   auto eth = reinterpret_cast<const ether_header&>(*pkt);
//   if (ntohs(eth.ether_type) != 0x88f8) {
//     return;
//   }
//   if (uint32_t(len) < ETH_HLEN + sizeof(NcsiHeader)) {
//     printf(": len is too small for NCSI header: %d\n", len);
//     return;
//   }
//   auto command = reinterpret_cast<const NcsiHeader&>(*&pkt[ETH_HLEN]);
//   HandleNcsiCommand(command);
// }

static void PrintNcsiHeader(const NcsiHeader& h) {
  printf("mc_id=0x%02x rev=0x%02x iid=%d type=0x%02x chan=0x%02x len=0x%02x", h.mc_id, h.header_revision, h.iid, h.type, h.channel_id, ntohs(h.payload_length));
}

static uint32_t Checksum(const uint16_t* p, size_t n) {
  uint32_t checksum = 0;
  for (size_t i = 0; i < n; i++) {
    checksum += htons(p[i]);
  }
  return ~checksum + 1;
}

static NcsiResponsePacket GenerateResponse(const NcsiCommandPacket& command) {
  printf("NcsiCommandPacket  ");
  PrintNcsiHeader(command.ncsi);
  printf("\n");

  NcsiResponsePacket response;
  memset(response.eth.src, 0xFF, sizeof(response.eth.src));
  memset(response.eth.dst, 0xFF, sizeof(response.eth.dst));
  response.eth.type             = htons(NCSI_ETHERTYPE);
  response.ncsi.mc_id           = command.ncsi.mc_id;
  response.ncsi.header_revision = 0x01;
  response.ncsi.iid             = command.ncsi.iid;
  response.ncsi.type            = 0x80 + command.ncsi.type;
  response.ncsi.channel_id      = command.ncsi.channel_id;
  response.ncsi.payload_length  = htons(4);
  response.code                 = htons(COMMAND_COMPLETED);
  response.reason               = htons(NO_ERROR_REASON);

  switch (command.ncsi.type) {
    case DESELECT_PACKAGE:
      response.ncsi.channel_id = 0x00;
      break;
    case CLEAR_INITIAL_STATE:
    case SELECT_PACKAGE:
      break;
    default:
      printf("Unsupported command type: 0x%02x\n", command.ncsi.type);
      response.code   = htons(COMMAND_UNSUPPORTED);
      response.reason = htons(UNSUPPORTED_COMMAND_TYPE);
      break;
  }

  uint32_t checksum = Checksum(reinterpret_cast<const uint16_t*>(&response.ncsi), (sizeof(response.ncsi) + 4) / 2);
  response.checksum = htonl(checksum);

  printf("NcsiResponsePacket ");
  PrintNcsiHeader(response.ncsi);
  printf(" checksum=0x%08x\n", checksum);

  return response;
}

// static size_t GenerateResponse(const EthernetPacket& command, EthernetPacket& response) {
//   printf("Generating response for command type 0x%02x\n", command.type);
// 
//   memset(&response, 0, sizeof(response));
// 
//   memset(response.eth.src, 0xFF, sizeof(response.eth.src));
//   memset(response.eth.dst, 0xFF, sizeof(response.eth.dst));
//   response.eth.type = htons(NCSI_ETHERTYPE);
// 
//   response.ncsi.mc_id           = command.ncsi.mc_id;
//   response.ncsi.header_revision = 0x01;
//   response.ncsi.iid             = command.ncsi.iid;
//   response.ncsi.type            = 0x80 + command.ncsi.type;
//   response.ncsi.channel_id      = command.ncsi.channel_id;
//   response.ncsi.payload_length  = htons(4);
// 
//   response.code   = htons(COMMAND_COMPLETED);
//   response.reason = htons(NO_ERROR_REASON);
// 
//   switch (command.ncsi.type) {
//     case CLEAR_INITIAL_STATE:
//     case SELECT_PACKAGE:
//     case ENABLE_CHANNEL:
//     case DISABLE_CHANNEL:
//     case RESET_CHANNEL:
//     case GET_LINK_STATUS:
//       break;
//     case DESELECT_PACKAGE:
//       response.ncsi.channel_id = 0x00;
//       break;
//     default:
//       printf("Unimplemented NCSI type: 0x%02x\n", command.ncsi.type);
//       response.code = htons(COMMAND_UNSUPPORTED);
//       response.reason = htons(UNSUPPORTED_COMMAND_TYPE);
//       break;
//   }
// 
//   return sizeof(NcsiResponsePacket);
// }

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

  for (;;) {
    NcsiCommandPacket command;
    ssize_t r = recv(fd, &command, sizeof(command), 0);
    switch (r) {
      case -1:
      case 0:
        perror("recv");
        continue;
    }
    size_t n = size_t(r);
    if (n < sizeof(EthernetHeader)) {
      printf("Packet is smaller than minimum ethernet frame size: %zu\n", n);
      continue;
    }
    if (command.eth.type != htons(NCSI_ETHERTYPE)) {
      continue;
    }
    if (n < sizeof(EthernetHeader) + sizeof(NcsiHeader)) {
      printf("Packet isn't long enough to have NCSI header: %zu\n", n);
      continue;
    }
    NcsiResponsePacket response = GenerateResponse(command);

    if (send(fd, &response, sizeof(response), 0) != ssize_t(sizeof(response))) {
      perror("send");
    }
  }
}
