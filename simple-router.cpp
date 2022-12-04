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

  struct ethernet_hdr eth_hdr;
  memcpy(&eth_hdr, &packet[0], sizeof(eth_hdr));

  if (eth_hdr.ether_type == ntohs(ethertype_ip)) {
    if (packet.size() - 14 < sizeof(ip_hdr))
      return;
    struct ip_hdr i_hdr;
    memcpy(&i_hdr, &packet[14], sizeof(i_hdr));

    Interface dest_int = findIfaceByIp(i_hdr.ip_dst);

    if (dest_int || cksum(&i_hdr, sizeof(i_hdr)) != 0xffff)
      return;

    i_hdr.ip_ttl--;
    if (i_hdr.ip_ttl < 0)
      return;
    i_hdr.ip_sum = 0;
    i_hdr.ip_sum = cksum(&i_hdr, sizeof(i_hdr));
    ArpCache arp = getArp();

    if (!arp.lookup(i_hdr.ip_src))
      arp.insertArpEntry(eth_hdr.ether_shost, i_hdr.ip_src);

    if (arp.lookup(i_hdr.ip_dst)) {
      try {
        RoutingTable rt = getRoutingTable();
        RoutingTableEntry match = rt.lookup(i_hdr.ip_dst);

        if (ipToString(match.dest) == "0.0.0.0")
          memcpy(eth_hdr.ether_dhost, &(arp.lookup(i_hdr.ip_dst)->mac)[0], sizeof(eth_hdr.ether_dhost));
        else
          memcpy(eth_hdr.ether_dhost, &(arp.lookup(match.dest)->mac)[0], sizeof(eth_hdr.ether_dhost))

        dest_int = *findIfaceByName(match.ifName);
        memcpy(eth_hdr.ether_shost, &dest_int.addr, sizeof(eth_hdr.ether_shost));
        memcpy(&packet[0], &eth_hdr, sizeof(eth_hdr));
        memcpy(&packet[14], &i_hdr, sizeof(i_hdr));
        sendPacket(packet, match.ifName);
      }
      catch (std::runtime_error &error);
    }
    else {
      
    }

  }

  else if (eth_hdr.ether_type == ntohs(ethertype_arp)) {

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
