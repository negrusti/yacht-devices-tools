#include <errno.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

namespace {

constexpr uint32_t kPgnAddressClaim = 60928;     // 0xEE00
constexpr uint32_t kPgnIsoRequest = 59904;       // 0xEA00
constexpr uint32_t kPgnGroupFunction = 126208;   // 0x1ED00
constexpr uint32_t kPgnProductInfo = 126996;     // 0x1F014
constexpr uint32_t kPgnConfigInfo = 126998;      // 0x1F016
constexpr uint8_t kDefaultPriority = 6;
constexpr uint8_t kConfigPriority = 3;
constexpr uint8_t kGlobalAddress = 0xFF;
constexpr uint8_t kNullAddress = 0xFE;
constexpr uint16_t kYachtDevicesManufacturerCode = 717;

struct Options {
  std::string iface = "can0";
  uint8_t preferred_source = 0x23;
  uint8_t source = 0x23;
  uint8_t destination = 0xFF;
  int timeout_ms = 3000;
  bool verbose = false;
  bool list_only = false;
  std::string command;

  uint32_t unique_number = 0x12345;
  uint16_t manufacturer_code = 2046;
  uint8_t device_instance_lower = 0;
  uint8_t device_instance_upper = 0;
  uint8_t device_function = 130;
  uint8_t device_class = 25;
  uint8_t system_instance = 0;
  uint8_t industry_group = 4;
  bool arbitrary_address_capable = true;
};

struct CanMeta {
  uint32_t pgn = 0;
  uint8_t source = 0;
  uint8_t destination = kGlobalAddress;
  uint8_t priority = 0;
};

struct FastPacketState {
  uint8_t next_frame = 1;
  uint8_t total_len = 0;
  std::vector<uint8_t> data;
};

struct ConfigInfo {
  uint8_t block1_len = 0;
  uint8_t block1_encoding = 0;
  std::string installation_desc1;
  uint8_t block2_len = 0;
  uint8_t block2_encoding = 0;
  std::string installation_desc2;
};

struct ProductInfo {
  std::string model_id;
  std::string software_version;
  std::string serial_code;
};

[[noreturn]] void Die(const std::string &message) {
  throw std::runtime_error(message);
}

uint32_t BuildCanId(uint32_t pgn, uint8_t priority, uint8_t destination, uint8_t source) {
  const uint8_t pf = static_cast<uint8_t>((pgn >> 8) & 0xFF);
  const uint8_t ps = static_cast<uint8_t>(pgn & 0xFF);
  uint32_t id = (static_cast<uint32_t>(priority & 0x7) << 26);
  if (pf < 240) {
    id |= (pgn & 0x3FF00u) << 8;
    id |= static_cast<uint32_t>(destination) << 8;
    id |= source;
  } else {
    id |= (pgn & 0x3FFFFu) << 8;
    id |= source;
    (void)ps;
  }
  return id | CAN_EFF_FLAG;
}

CanMeta ParseCanId(uint32_t can_id) {
  const uint32_t raw = can_id & CAN_EFF_MASK;
  CanMeta meta;
  meta.priority = static_cast<uint8_t>((raw >> 26) & 0x7);
  const uint8_t dp = static_cast<uint8_t>((raw >> 24) & 0x1);
  const uint8_t pf = static_cast<uint8_t>((raw >> 16) & 0xFF);
  const uint8_t ps = static_cast<uint8_t>((raw >> 8) & 0xFF);
  meta.source = static_cast<uint8_t>(raw & 0xFF);
  if (pf < 240) {
    meta.destination = ps;
    meta.pgn = (static_cast<uint32_t>(dp) << 16) | (static_cast<uint32_t>(pf) << 8);
  } else {
    meta.destination = kGlobalAddress;
    meta.pgn = (static_cast<uint32_t>(dp) << 16) | (static_cast<uint32_t>(pf) << 8) | ps;
  }
  return meta;
}

uint8_t ParseByte(const std::string &value) {
  size_t idx = 0;
  const unsigned long parsed = std::stoul(value, &idx, 0);
  if (idx != value.size() || parsed > 0xFF) {
    Die("invalid byte value: " + value);
  }
  return static_cast<uint8_t>(parsed);
}

uint16_t ParseWord(const std::string &value, uint16_t max_value) {
  size_t idx = 0;
  const unsigned long parsed = std::stoul(value, &idx, 0);
  if (idx != value.size() || parsed > max_value) {
    Die("invalid value: " + value);
  }
  return static_cast<uint16_t>(parsed);
}

uint32_t ParseDword(const std::string &value, uint32_t max_value) {
  size_t idx = 0;
  const unsigned long parsed = std::stoul(value, &idx, 0);
  if (idx != value.size() || parsed > max_value) {
    Die("invalid value: " + value);
  }
  return static_cast<uint32_t>(parsed);
}

int ParseInt(const std::string &value) {
  size_t idx = 0;
  const long parsed = std::stol(value, &idx, 0);
  if (idx != value.size()) {
    Die("invalid integer value: " + value);
  }
  return static_cast<int>(parsed);
}

void PrintUsage(const char *argv0) {
  std::cerr
      << "Usage: " << argv0 << " --dest <addr> --command <text> [options]\n"
      << "Options:\n"
      << "  --iface <ifname>          SocketCAN interface, default can0\n"
      << "  --src <addr>              Preferred source address, default 0x23\n"
      << "  --dest <addr>             Destination device address\n"
      << "  --command <text>          Value to write into Installation Description 2\n"
      << "  --list                    List Yacht Devices nodes and their addresses\n"
      << "  --timeout-ms <ms>         Reply wait timeout, default 3000\n"
      << "  --unique-number <n>       NAME unique number, default 0x12345\n"
      << "  --manufacturer-code <n>   NAME manufacturer code, default 2046\n"
      << "  --device-function <n>     NAME device function, default 130\n"
      << "  --device-class <n>        NAME device class, default 25\n"
      << "  --system-instance <n>     NAME system instance, default 0\n"
      << "  --device-instance-lower <n> NAME lower device instance, default 0\n"
      << "  --device-instance-upper <n> NAME upper device instance, default 0\n"
      << "  --industry-group <n>      NAME industry group, default 4 (Marine)\n"
      << "  --single-address          Disable arbitrary address capable bit\n"
      << "  --verbose                 Print CAN and parser details\n"
      << "  --help                    Show this message\n\n"
      << "Example:\n"
      << "  " << argv0 << " --iface can0 --dest 0x34 --command \"YD:DEV 1\"\n"
      << "  " << argv0 << " --iface can0 --list\n";
}

Options ParseArgs(int argc, char **argv) {
  Options opts;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    auto require_value = [&](const char *name) -> std::string {
      if (i + 1 >= argc) {
        Die(std::string("missing value for ") + name);
      }
      return argv[++i];
    };

    if (arg == "--iface") {
      opts.iface = require_value("--iface");
    } else if (arg == "--src") {
      opts.preferred_source = ParseByte(require_value("--src"));
    } else if (arg == "--dest") {
      opts.destination = ParseByte(require_value("--dest"));
    } else if (arg == "--command") {
      opts.command = require_value("--command");
    } else if (arg == "--list") {
      opts.list_only = true;
    } else if (arg == "--timeout-ms") {
      opts.timeout_ms = ParseInt(require_value("--timeout-ms"));
    } else if (arg == "--unique-number") {
      opts.unique_number = ParseDword(require_value("--unique-number"), 0x1FFFFF);
    } else if (arg == "--manufacturer-code") {
      opts.manufacturer_code = ParseWord(require_value("--manufacturer-code"), 0x7FF);
    } else if (arg == "--device-function") {
      opts.device_function = ParseByte(require_value("--device-function"));
    } else if (arg == "--device-class") {
      opts.device_class = ParseByte(require_value("--device-class"));
    } else if (arg == "--system-instance") {
      opts.system_instance = ParseByte(require_value("--system-instance"));
    } else if (arg == "--device-instance-lower") {
      opts.device_instance_lower = ParseByte(require_value("--device-instance-lower"));
    } else if (arg == "--device-instance-upper") {
      opts.device_instance_upper = ParseByte(require_value("--device-instance-upper"));
    } else if (arg == "--industry-group") {
      opts.industry_group = ParseByte(require_value("--industry-group"));
    } else if (arg == "--single-address") {
      opts.arbitrary_address_capable = false;
    } else if (arg == "--verbose") {
      opts.verbose = true;
    } else if (arg == "--help" || arg == "-h") {
      PrintUsage(argv[0]);
      std::exit(0);
    } else {
      Die("unknown argument: " + arg);
    }
  }

  if (!opts.list_only && opts.destination == 0xFF) {
    Die("--dest is required unless --list is used");
  }
  if (!opts.list_only && opts.command.empty()) {
    Die("--command is required unless --list is used");
  }
  if (!opts.command.empty() && opts.command.size() > 223) {
    Die("--command is too long for a single fast-packet payload");
  }
  if (opts.preferred_source >= kNullAddress) {
    Die("--src must be a usable source address (0x00..0xFD)");
  }
  if (opts.device_instance_lower > 0x7 || opts.device_instance_upper > 0x1F) {
    Die("device instance fields exceed NAME bit widths");
  }
  if (opts.system_instance > 0xF || opts.device_class > 0x7F || opts.industry_group > 0x7) {
    Die("one or more NAME fields exceed NMEA 2000 bit widths");
  }
  opts.source = opts.preferred_source;
  return opts;
}

std::string HexBytes(const std::vector<uint8_t> &bytes) {
  std::ostringstream os;
  os << std::hex << std::setfill('0');
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (i) {
      os << ' ';
    }
    os << std::setw(2) << static_cast<unsigned>(bytes[i]);
  }
  return os.str();
}

uint64_t BuildName(const Options &opts) {
  uint64_t name = 0;
  name |= static_cast<uint64_t>(opts.unique_number & 0x1FFFFF);
  name |= static_cast<uint64_t>(opts.manufacturer_code & 0x7FF) << 21;
  name |= static_cast<uint64_t>(opts.device_instance_lower & 0x7) << 32;
  name |= static_cast<uint64_t>(opts.device_instance_upper & 0x1F) << 35;
  name |= static_cast<uint64_t>(opts.device_function) << 40;
  name |= static_cast<uint64_t>(opts.device_class & 0x7F) << 49;
  name |= static_cast<uint64_t>(opts.system_instance & 0xF) << 56;
  name |= static_cast<uint64_t>(opts.industry_group & 0x7) << 60;
  name |= static_cast<uint64_t>(opts.arbitrary_address_capable ? 1ULL : 0ULL) << 63;
  return name;
}

std::vector<uint8_t> EncodeName(uint64_t name) {
  std::vector<uint8_t> bytes(8, 0);
  for (size_t i = 0; i < bytes.size(); ++i) {
    bytes[i] = static_cast<uint8_t>((name >> (8 * i)) & 0xFF);
  }
  return bytes;
}

uint64_t DecodeName(const can_frame &frame) {
  if (frame.can_dlc < 8) {
    return 0;
  }
  uint64_t name = 0;
  for (size_t i = 0; i < 8; ++i) {
    name |= static_cast<uint64_t>(frame.data[i]) << (8 * i);
  }
  return name;
}

uint16_t ManufacturerCodeFromName(uint64_t name) {
  return static_cast<uint16_t>((name >> 21) & 0x7FF);
}

class CanSocket {
 public:
  explicit CanSocket(const std::string &iface) {
    fd_ = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (fd_ < 0) {
      Die("socket(PF_CAN) failed: " + std::string(std::strerror(errno)));
    }

    struct ifreq ifr {};
    std::snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface.c_str());
    if (ioctl(fd_, SIOCGIFINDEX, &ifr) < 0) {
      Die("ioctl(SIOCGIFINDEX) failed for " + iface + ": " + std::string(std::strerror(errno)));
    }

    struct sockaddr_can addr {};
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (bind(fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
      Die("bind(AF_CAN) failed: " + std::string(std::strerror(errno)));
    }
  }

  ~CanSocket() {
    if (fd_ >= 0) {
      close(fd_);
    }
  }

  void Send(const can_frame &frame) const {
    const ssize_t written = write(fd_, &frame, sizeof(frame));
    if (written != static_cast<ssize_t>(sizeof(frame))) {
      Die("CAN write failed: " + std::string(std::strerror(errno)));
    }
  }

  bool Receive(can_frame &frame, int timeout_ms) const {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fd_, &readfds);

    struct timeval tv {};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    const int rc = select(fd_ + 1, &readfds, nullptr, nullptr, &tv);
    if (rc < 0) {
      Die("select() failed: " + std::string(std::strerror(errno)));
    }
    if (rc == 0) {
      return false;
    }

    const ssize_t rd = read(fd_, &frame, sizeof(frame));
    if (rd < 0) {
      Die("CAN read failed: " + std::string(std::strerror(errno)));
    }
    if (rd != static_cast<ssize_t>(sizeof(frame))) {
      Die("short CAN read");
    }
    return true;
  }

 private:
  int fd_ = -1;
};

void LogFrame(const char *prefix, const can_frame &frame, bool verbose) {
  if (!verbose) {
    return;
  }
  const CanMeta meta = ParseCanId(frame.can_id);
  std::vector<uint8_t> bytes(frame.data, frame.data + frame.can_dlc);
  std::cerr << prefix << " pgn=" << meta.pgn << " src=0x" << std::hex
            << static_cast<unsigned>(meta.source) << " dst=0x"
            << static_cast<unsigned>(meta.destination) << std::dec
            << " data=" << HexBytes(bytes) << "\n";
}

void SendAddressClaim(const CanSocket &sock, uint8_t source, uint64_t name, bool verbose) {
  can_frame frame {};
  frame.can_id = BuildCanId(kPgnAddressClaim, kDefaultPriority, kGlobalAddress, source);
  frame.can_dlc = 8;
  const std::vector<uint8_t> name_bytes = EncodeName(name);
  std::memcpy(frame.data, name_bytes.data(), 8);
  LogFrame("TX", frame, verbose);
  sock.Send(frame);
}

void SendIsoRequest(const CanSocket &sock, uint8_t source, uint8_t destination, uint32_t requested_pgn, bool verbose) {
  can_frame frame {};
  frame.can_id = BuildCanId(kPgnIsoRequest, kDefaultPriority, destination, source);
  frame.can_dlc = 3;
  frame.data[0] = static_cast<uint8_t>(requested_pgn & 0xFF);
  frame.data[1] = static_cast<uint8_t>((requested_pgn >> 8) & 0xFF);
  frame.data[2] = static_cast<uint8_t>((requested_pgn >> 16) & 0xFF);
  LogFrame("TX", frame, verbose);
  sock.Send(frame);
}

uint8_t ClaimAddress(const CanSocket &sock, const Options &opts, uint64_t name) {
  for (uint16_t candidate = opts.preferred_source; candidate < kNullAddress; ++candidate) {
    uint8_t address = static_cast<uint8_t>(candidate);
    bool restart = false;

    for (int attempt = 0; attempt < 3 && !restart; ++attempt) {
      SendAddressClaim(sock, address, name, opts.verbose);
      const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(250);

      while (std::chrono::steady_clock::now() < deadline) {
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) {
          break;
        }

        can_frame frame {};
        if (!sock.Receive(frame, static_cast<int>(remaining))) {
          break;
        }
        if (!(frame.can_id & CAN_EFF_FLAG)) {
          continue;
        }
        const CanMeta meta = ParseCanId(frame.can_id);
        LogFrame("RX", frame, opts.verbose);
        if (meta.pgn != kPgnAddressClaim || meta.source != address) {
          continue;
        }

        const uint64_t other_name = DecodeName(frame);
        if (other_name == 0 || other_name == name) {
          continue;
        }

        if (other_name < name) {
          restart = true;
          break;
        }

        SendAddressClaim(sock, address, name, opts.verbose);
      }
    }

    if (!restart) {
      return address;
    }
  }

  Die("failed to claim a usable NMEA 2000 address");
}

std::vector<std::pair<uint8_t, uint64_t>> DiscoverYachtDevices(
    const CanSocket &sock,
    uint8_t source,
    int timeout_ms,
    bool verbose) {
  SendIsoRequest(sock, source, kGlobalAddress, kPgnAddressClaim, verbose);

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  std::map<uint8_t, uint64_t> found;

  while (std::chrono::steady_clock::now() < deadline) {
    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
    if (remaining <= 0) {
      break;
    }

    can_frame frame {};
    if (!sock.Receive(frame, static_cast<int>(remaining))) {
      break;
    }
    if (!(frame.can_id & CAN_EFF_FLAG)) {
      continue;
    }

    const CanMeta meta = ParseCanId(frame.can_id);
    LogFrame("RX", frame, verbose);
    if (meta.pgn != kPgnAddressClaim || meta.source >= kNullAddress || frame.can_dlc < 8) {
      continue;
    }

    const uint64_t name = DecodeName(frame);
    if (ManufacturerCodeFromName(name) != kYachtDevicesManufacturerCode) {
      continue;
    }

    found[meta.source] = name;
  }

  std::vector<std::pair<uint8_t, uint64_t>> nodes(found.begin(), found.end());
  std::sort(nodes.begin(), nodes.end(), [](const auto &lhs, const auto &rhs) {
    return lhs.first < rhs.first;
  });
  return nodes;
}

std::string TrimFixedString(const uint8_t *data, size_t size) {
  size_t end = 0;
  while (end < size && data[end] != 0x00 && data[end] != 0xFF) {
    ++end;
  }
  while (end > 0 && data[end - 1] == ' ') {
    --end;
  }
  return std::string(reinterpret_cast<const char *>(data), end);
}

std::vector<uint8_t> BuildGroupFunctionWritePayload(const std::string &text) {
  std::vector<uint8_t> payload;
  payload.reserve(text.size() + 9);
  payload.push_back(0x01);
  payload.push_back(0x16);
  payload.push_back(0xF0);
  payload.push_back(0x01);
  payload.push_back(0xF8);
  payload.push_back(0x01);
  payload.push_back(0x02);
  payload.push_back(static_cast<uint8_t>(text.size() + 2));
  payload.push_back(0x01);
  payload.insert(payload.end(), text.begin(), text.end());
  return payload;
}

void SendFastPacket(const CanSocket &sock, uint32_t can_id, const std::vector<uint8_t> &payload, bool verbose) {
  static uint8_t sequence_id = 0;
  const uint8_t seq = sequence_id++ & 0x7;

  size_t offset = 0;
  uint8_t frame_index = 0;
  while (offset < payload.size()) {
    can_frame frame {};
    frame.can_id = can_id;
    frame.can_dlc = 8;
    std::memset(frame.data, 0xFF, sizeof(frame.data));

    frame.data[0] = static_cast<uint8_t>((seq << 5) | frame_index);
    if (frame_index == 0) {
      frame.data[1] = static_cast<uint8_t>(payload.size());
      const size_t chunk = std::min<size_t>(6, payload.size() - offset);
      std::memcpy(&frame.data[2], payload.data() + offset, chunk);
      offset += chunk;
    } else {
      const size_t chunk = std::min<size_t>(7, payload.size() - offset);
      std::memcpy(&frame.data[1], payload.data() + offset, chunk);
      offset += chunk;
    }

    LogFrame("TX", frame, verbose);
    sock.Send(frame);
    ++frame_index;
    usleep(2000);
  }
}

std::optional<ConfigInfo> ParseConfigInfo126998(const std::vector<uint8_t> &payload) {
  if (payload.size() < 4) {
    return std::nullopt;
  }

  ConfigInfo info;
  const size_t first_len = payload[0];
  if (first_len < 2 || first_len > payload.size()) {
    return std::nullopt;
  }
  info.block1_len = payload[0];
  info.block1_encoding = payload[1];
  info.installation_desc1.assign(reinterpret_cast<const char *>(&payload[2]), first_len - 2);

  const size_t second_offset = first_len;
  if (second_offset >= payload.size()) {
    return std::nullopt;
  }
  const size_t second_len = payload[second_offset];
  if (second_len < 2 || second_offset + second_len > payload.size()) {
    return std::nullopt;
  }
  info.block2_len = payload[second_offset];
  info.block2_encoding = payload[second_offset + 1];
  info.installation_desc2.assign(reinterpret_cast<const char *>(&payload[second_offset + 2]), second_len - 2);
  return info;
}

std::optional<ProductInfo> ParseProductInfo126996(const std::vector<uint8_t> &payload) {
  constexpr size_t kExpectedMin = 2 + 2 + 32 + 32 + 32 + 32 + 1 + 1;
  if (payload.size() < kExpectedMin) {
    return std::nullopt;
  }

  ProductInfo info;
  info.model_id = TrimFixedString(&payload[4], 32);
  info.software_version = TrimFixedString(&payload[68], 32);
  info.serial_code = TrimFixedString(&payload[100], 32);
  if (info.model_id.empty()) {
    return std::nullopt;
  }
  return info;
}

std::optional<std::vector<uint8_t>> TryReassembleFastPacket(
    const can_frame &frame,
    std::map<std::tuple<uint8_t, uint32_t, uint8_t>, FastPacketState> &states) {
  if (!(frame.can_id & CAN_EFF_FLAG) || frame.can_dlc < 2) {
    return std::nullopt;
  }

  const CanMeta meta = ParseCanId(frame.can_id);
  const uint8_t header = frame.data[0];
  const uint8_t sequence = header >> 5;
  const uint8_t frame_index = header & 0x1F;
  const auto key = std::make_tuple(meta.source, meta.pgn, sequence);

  if (frame_index == 0) {
    FastPacketState state;
    state.total_len = frame.data[1];
    const size_t chunk = std::min<size_t>(6, state.total_len);
    state.data.insert(state.data.end(), &frame.data[2], &frame.data[2] + chunk);
    states[key] = std::move(state);
  } else {
    auto it = states.find(key);
    if (it == states.end() || it->second.next_frame != frame_index) {
      return std::nullopt;
    }
    FastPacketState &state = it->second;
    const size_t remaining = state.total_len > state.data.size() ? state.total_len - state.data.size() : 0;
    const size_t chunk = std::min<size_t>(7, remaining);
    state.data.insert(state.data.end(), &frame.data[1], &frame.data[1] + chunk);
    ++state.next_frame;
    if (state.data.size() >= state.total_len) {
      std::vector<uint8_t> result(state.data.begin(), state.data.begin() + state.total_len);
      states.erase(it);
      return result;
    }
    return std::nullopt;
  }

  FastPacketState &state = states[key];
  state.next_frame = 1;
  if (state.data.size() >= state.total_len) {
    std::vector<uint8_t> result(state.data.begin(), state.data.begin() + state.total_len);
    states.erase(key);
    return result;
  }
  return std::nullopt;
}

std::optional<ProductInfo> QueryProductInfo(
    const CanSocket &sock,
    uint8_t source,
    uint8_t destination,
    int timeout_ms,
    bool verbose) {
  SendIsoRequest(sock, source, destination, kPgnProductInfo, verbose);
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  std::map<std::tuple<uint8_t, uint32_t, uint8_t>, FastPacketState> states;

  while (std::chrono::steady_clock::now() < deadline) {
    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
    if (remaining <= 0) {
      break;
    }

    can_frame frame {};
    if (!sock.Receive(frame, static_cast<int>(remaining))) {
      break;
    }
    if (!(frame.can_id & CAN_EFF_FLAG)) {
      continue;
    }

    const CanMeta meta = ParseCanId(frame.can_id);
    LogFrame("RX", frame, verbose);
    if (meta.pgn != kPgnProductInfo || meta.source != destination) {
      continue;
    }

    const auto assembled = TryReassembleFastPacket(frame, states);
    if (!assembled.has_value()) {
      continue;
    }
    return ParseProductInfo126996(*assembled);
  }

  return std::nullopt;
}

}  // namespace

int main(int argc, char **argv) {
  try {
    Options opts = ParseArgs(argc, argv);
    const CanSocket sock(opts.iface);
    const uint64_t name = BuildName(opts);

    std::cout << "Claiming NMEA 2000 source address...\n";
    opts.source = ClaimAddress(sock, opts, name);
    usleep(250000);

    if (opts.list_only) {
      const auto nodes = DiscoverYachtDevices(sock, opts.source, opts.timeout_ms, opts.verbose);
      if (nodes.empty()) {
        std::cout << "No Yacht Devices nodes found.\n";
        return 0;
      }

      for (const auto &[address, node_name] : nodes) {
        const auto product = QueryProductInfo(sock, opts.source, address, std::min(opts.timeout_ms, 1000), opts.verbose);
        const std::string display_name =
            product.has_value() && !product->model_id.empty() ? product->model_id : "Unknown Yacht Devices";
        std::cout << display_name;
        if (product.has_value()) {
          if (!product->software_version.empty()) {
            std::cout << " SW:" << product->software_version;
          }
          if (!product->serial_code.empty()) {
            std::cout << " SN:" << product->serial_code;
          }
        }
        std::cout << " - CAN Address: " << static_cast<unsigned>(address) << "\n";
        if (opts.verbose) {
          std::cout << "  NAME=0x" << std::hex << std::setw(16) << std::setfill('0')
                    << node_name << std::dec << "\n";
        }
      }
      return 0;
    }

    const std::vector<uint8_t> payload = BuildGroupFunctionWritePayload(opts.command);
    const uint32_t can_id = BuildCanId(kPgnGroupFunction, kConfigPriority, opts.destination, opts.source);

    std::cout << "Claimed source address: 0x" << std::hex << static_cast<unsigned>(opts.source) << std::dec << "\n";
    std::cout << "Sending PGN 126208 write request to PGN 126998 field 2\n";
    std::cout << "Interface: " << opts.iface
              << "  dest=0x" << std::hex << static_cast<unsigned>(opts.destination) << std::dec << "\n";
    std::cout << "Command: " << opts.command << "\n";
    if (opts.verbose) {
      std::cout << "NAME: 0x" << std::hex << std::setw(16) << std::setfill('0') << name << std::dec << "\n";
      std::cout << "Payload: " << HexBytes(payload) << "\n";
    }

    SendFastPacket(sock, can_id, payload, opts.verbose);

    std::cout << "Waiting for PGN 126998 reply...\n";

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(opts.timeout_ms);
    std::map<std::tuple<uint8_t, uint32_t, uint8_t>, FastPacketState> states;

    while (std::chrono::steady_clock::now() < deadline) {
      const auto now = std::chrono::steady_clock::now();
      const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
      can_frame frame {};
      if (!sock.Receive(frame, static_cast<int>(remaining))) {
        break;
      }

      if (!(frame.can_id & CAN_EFF_FLAG)) {
        continue;
      }

      const CanMeta meta = ParseCanId(frame.can_id);
      LogFrame("RX", frame, opts.verbose);

      if (meta.pgn != kPgnConfigInfo || meta.source != opts.destination) {
        continue;
      }

      const auto assembled = TryReassembleFastPacket(frame, states);
      if (!assembled.has_value()) {
        continue;
      }

      if (opts.verbose) {
        std::cerr << "PGN 126998 payload: " << HexBytes(*assembled) << "\n";
      }

      const auto parsed = ParseConfigInfo126998(*assembled);
      if (!parsed.has_value()) {
        std::cout << "Received PGN 126998 from 0x" << std::hex
                  << static_cast<unsigned>(meta.source) << std::dec
                  << " but could not parse Installation Description strings.\n";
        return 2;
      }

      std::cout << "Installation Description 1: " << parsed->installation_desc1 << "\n";
      std::cout << "Installation Description 2: " << parsed->installation_desc2 << "\n";

      if (parsed->installation_desc2.find("DONE") != std::string::npos) {
        std::cout << "Result: device accepted the command.\n";
        return 0;
      }
      if (parsed->installation_desc2.find("FAIL") != std::string::npos) {
        std::cout << "Result: device rejected the command.\n";
        return 3;
      }

      std::cout << "Result: reply received, but no DONE/FAIL marker was found.\n";
      return 0;
    }

    std::cerr << "Timed out waiting for PGN 126998 from device 0x"
              << std::hex << static_cast<unsigned>(opts.destination) << std::dec << "\n";
    return 1;
  } catch (const std::exception &ex) {
    std::cerr << "error: " << ex.what() << "\n";
    return 1;
  }
}
