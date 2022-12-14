/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::processPacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN

  /*// If ethernet packet less than minimum size, discard
  if (packet.size() < 64)
    return;*/


  Buffer new_packet(packet); // Create duplicate packet
  ethernet_hdr* eth_hdr = (ethernet_hdr *)new_packet.data();

  bool to_broadcast = true;
  bool to_me = true;

  for (int i = 0; i < ETHER_ADDR_LEN; i++) {
    if (!eth_hdr->ether_dhost[i])
      to_broadcast = false;
    if (eth_hdr->ether_dhost[i] != iface->addr[i])
      to_me = false;
  }

  if (!to_broadcast && !to_me)
    return;

  // Handle ARP packets
  if (eth_hdr->ether_type == htons(ethertype_arp)) {
    
    arp_hdr* a_hdr = (arp_hdr *)(new_packet.data() + sizeof(ethernet_hdr));

    // Handle ARP request
    if (a_hdr->arp_op == htons(arp_op_request)) {
      std::cerr << "Received ARP request for " << a_hdr->arp_tip << std::endl;
      
      const Interface* dest_int = findIfaceByIp(a_hdr->arp_tip);
      if (dest_int) {
        memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, dest_int->addr.data(), ETHER_ADDR_LEN);

        a_hdr->arp_op = htons(arp_op_reply);
        a_hdr->arp_tip = a_hdr->arp_sip;
        memcpy(a_hdr->arp_tha, a_hdr->arp_sha, ETHER_ADDR_LEN);
        a_hdr->arp_sip = dest_int->ip;
        memcpy(a_hdr->arp_sha, dest_int->addr.data(), ETHER_ADDR_LEN);

        std::cerr << "Sent ARP reply to " << dest_int->name << std::endl;
        print_hdrs(new_packet);

        sendPacket(new_packet, dest_int->name);
      }
    }

    // Handle ARP reply
    else if (a_hdr->arp_op == htons(arp_op_reply)) {
      std::cerr << "Received ARP reply from " << a_hdr->arp_tip << std::endl;
      Buffer source_mac(ETHER_ADDR_LEN);
      memcpy(source_mac.data(), a_hdr->arp_sha, ETHER_ADDR_LEN);
      std::shared_ptr<ArpRequest> request = m_arp.insertArpEntry(source_mac, a_hdr->arp_sip);
      if (request) {
        Buffer mac = (m_arp.lookup(a_hdr->arp_sip))->mac;
        for (auto pending : request->packets) {
          memcpy(pending.packet.data(), mac.data(), ETHER_ADDR_LEN);
          sendPacket(pending.packet, pending.iface);
        }
      }
    }
  }

  // Handle IP packets
  else if (eth_hdr->ether_type == htons(ethertype_ip)) {

    std::cerr << "Received IPv4 packet" << std::endl;

    ip_hdr* i_hdr = (ip_hdr *)(new_packet.data() + sizeof(ethernet_hdr));

    const Interface* dest_int = findIfaceByIp(i_hdr->ip_dst);

    // If header is too short or invalid checksum or datagram is destined to current router, discard
    if (i_hdr->ip_hl < 5) {
      std::cerr << "Invalid IP header length" << std::endl;
      return;
    }
    if (cksum(i_hdr, sizeof(ip_hdr)) != 0xffff) {
      std::cerr << "Bad checksum" << std::endl;
      return;
    }
    if (dest_int) {
      std::cerr << "IP packet destined to router" << std::endl;
      return;
    }

    i_hdr->ip_ttl--;
    if (i_hdr->ip_ttl < 0)
      return;
    i_hdr->ip_sum = 0;
    i_hdr->ip_sum = cksum(i_hdr, sizeof(ip_hdr));

    /*// If source IP not already in ARP cache, record it
    if (!m_arp.lookup(i_hdr->ip_src)) {
      std::cerr << "Recording source in ARP cache" << std::endl;
      Buffer source_mac(sizeof(ETHER_ADDR_LEN));
      memcpy(source_mac.data(), eth_hdr->ether_shost, ETHER_ADDR_LEN);
      m_arp.insertArpEntry(source_mac, i_hdr->ip_src);
    }*/

    // Find next hop IP in routing table using longest matching prefix
    RoutingTableEntry next_hop;
    try {
      RoutingTable rt = getRoutingTable();
      next_hop = rt.lookup(i_hdr->ip_dst);
    }
    catch (std::runtime_error& e) {
      std::cerr << "Could not find next hop in routing table" << std::endl;
      return;
    }

    dest_int = findIfaceByName(next_hop.ifName);
    std::cerr << "Next hop interface is " << dest_int->name << std::endl;
    memcpy(eth_hdr->ether_shost, dest_int->addr.data(), ETHER_ADDR_LEN);

    std::shared_ptr<ArpEntry> cache_entry = m_arp.lookup(i_hdr->ip_dst);
    // If destination IP is already in ARP cache
    if (cache_entry) {
      //if (ipToString(next_hop.dest) == "0.0.0.0") // Packet addressed to endnode on current router
      //  memcpy(eth_hdr->ether_dhost, (cache_entry->mac).data(), ETHER_ADDR_LEN);
      //else {
        memcpy(eth_hdr->ether_dhost, (m_arp.lookup(next_hop.dest)->mac).data(), ETHER_ADDR_LEN);
      //}

      sendPacket(new_packet, next_hop.ifName);
    }

    else {
      m_arp.queueArpRequest(next_hop.dest, new_packet, next_hop.ifName);
    }

  }

}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
  m_aclLogFile.open("router-acl.log");
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

bool
SimpleRouter::loadACLTable(const std::string& aclConfig)
{
  return m_aclTable.load(aclConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

} // namespace simple_router {
