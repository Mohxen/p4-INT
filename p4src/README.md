
# P4 Ingress Pipeline Overview

This P4 program defines several tables in the ingress pipeline, each designed to handle different aspects of packet processing, such as Layer 2 forwarding, multicast, firewall functionality, routing (for both IPv4 and IPv6), Segment Routing (SRv6), and ACL (Access Control List). Here's a breakdown of each table in the ingress pipeline:

## 1. unicast Table
- **Purpose**: Handles unicast forwarding by looking up the destination MAC address in the Ethernet header.
- **Key**: 
  - `hdr.ethernet.dst_addr`: The destination MAC address.
- **Actions**: 
  - `set_output_port`: Sets the egress port for forwarding the packet.
  - `drop`: Drops the packet.
  - `NoAction`: No action is taken, the packet is forwarded as is.
- **Counters**: `unicast_counter` counts packets and bytes processed by this table.
- **Default Action**: `NoAction`, meaning if no match is found, the packet proceeds without changes.

## 2. multicast Table
- **Purpose**: Handles multicast forwarding based on the destination MAC address.
- **Key**: 
  - `hdr.ethernet.dst_addr`: The destination MAC address, matched with ternary (mask-based) matching.
- **Actions**: 
  - `set_multicast_group`: Sets the multicast group ID for forwarding the packet to multiple destinations.
  - `drop`: Drops the packet.
- **Counters**: `multicast_counter` tracks the packets and bytes processed by this table.
- **Default Action**: `drop`, meaning if no match is found, the packet is dropped.

## 3. l2_firewall Table
- **Purpose**: Implements Layer 2 firewall functionality by checking the destination MAC address and determining whether the packet should be forwarded or dropped.
- **Key**: 
  - `hdr.ethernet.dst_addr`: The destination MAC address.
- **Actions**: 
  - `NoAction`: No explicit forwarding or dropping action is taken, allowing the packet to pass through.
- **Counters**: `l2_firewall_counter` counts packets and bytes passing through this table.
- **Default Action**: `NoAction`.

## 4. routing_v6 Table
- **Purpose**: Performs IPv6 Layer 3 routing by looking up the destination IPv6 address and flow label to set the next hop.
- **Key**: 
  - `hdr.ipv6.dst_addr`: The destination IPv6 address, matched using longest prefix match (LPM).
  - `hdr.ipv6.flow_label`: Used for advanced routing decisions, such as Equal-Cost Multi-Path (ECMP) routing (though ECMP is not fully implemented).
  - `hdr.ipv6.src_addr`: Source IPv6 address for advanced routing decisions (selector-based match).
- **Actions**: 
  - `set_next_hop`: Sets the next hop's MAC address and decrements the IPv6 hop limit.
- **Counters**: `routing_v6_counter` counts the packets and bytes processed by this table.
- **Default Action**: No default action specified, meaning packets that do not match any entry won’t be processed further by this table.

## 5. routing_v4 Table
- **Purpose**: Performs IPv4 Layer 3 routing by looking up the destination IPv4 address to set the next hop.
- **Key**: 
  - `hdr.ipv4.dst_addr`: The destination IPv4 address, matched using longest prefix match (LPM).
- **Actions**: 
  - `set_next_hop_v4`: Sets the next hop's MAC address and decrements the IPv4 Time-to-Live (TTL).
- **Counters**: `routing_v4_counter` counts the packets and bytes processed by this table.
- **Default Action**: No default action specified, meaning packets that do not match any entry won’t be processed further by this table.

## 6. ndp_reply_table Table
- **Purpose**: Handles Neighbor Discovery Protocol (NDP) reply messages for IPv6 by converting Neighbor Solicitation (NS) messages into Neighbor Advertisement (NA) replies.
- **Key**: 
  - `hdr.ndp.target_addr`: The target IPv6 address in the NDP message, matched exactly.
- **Actions**: 
  - `ndp_ns_to_na`: Converts an NDP Neighbor Solicitation message into a Neighbor Advertisement by setting relevant fields (like Ethernet source/destination MAC, ICMPv6 type, NDP flags, etc.).
- **Counters**: `ndp_reply_table_counter` counts packets and bytes processed by this table.
- **Default Action**: No default action specified.

## 7. srv6_localsid_table Table
- **Purpose**: Handles SRv6 Local SID (Segment Identifier) processing. It matches the destination IPv6 address in the SRv6 segment header and performs segment routing functions such as SRv6 encapsulation or endpoint behavior.
- **Key**: 
  - `hdr.ipv6.dst_addr`: The destination IPv6 address, matched using longest prefix match (LPM).
- **Actions**: 
  - `srv6_end`: Marks the end of SRv6 processing.
  - `srv6_end_x`: Handles cross-connect routing based on SRv6 segment information.
  - `srv6_end_dx6`: Handles SRv6 decapsulation for IPv6 packets.
  - `srv6_end_dx4`: Handles SRv6 decapsulation for IPv4 packets.
  - `srv6_usid_un`: Encapsulates using uSID (Unstructured Segment Routing Identifier).
  - `srv6_usid_ua`: Encapsulates using a different uSID mechanism.
- **Counters**: `srv6_localsid_table_counter` counts packets and bytes processed by this table.
- **Default Action**: `NoAction`.

## 8. xconnect_table Table
- **Purpose**: Handles cross-connect functionality, which directly forwards packets between ports based on specific conditions (such as in SRv6 or other scenarios).
- **Key**: 
  - `local_metadata.ua_next_hop`: The next hop for SRv6 cross-connect, matched using longest prefix match (LPM).
- **Actions**: 
  - `xconnect_act`: Sets the next hop MAC address and prepares the packet for direct forwarding.
- **Counters**: `xconnect_table_counter` counts packets and bytes processed by this table.
- **Default Action**: `NoAction`.

## 9. srv6_encap and srv6_encap_v4 Tables
- **Purpose**: These tables handle SRv6 encapsulation for both IPv4 and IPv6 packets.
  - `srv6_encap`: Handles SRv6 encapsulation for IPv6 packets.
  - `srv6_encap_v4`: Handles SRv6 encapsulation for IPv4 packets.
- **Key**:
  - For IPv6 (`srv6_encap`):
    - `hdr.ipv6.dst_addr`: The destination IPv6 address, matched using LPM.
  - For IPv4 (`srv6_encap_v4`):
    - `hdr.ipv4.dscp`: Differentiated Services Code Point (DSCP) value, matched exactly.
    - `hdr.ipv4.dst_addr`: The destination IPv4 address, matched using LPM.
    - Additional fields like source/destination addresses and Layer 4 ports are used as selectors for Equal-Cost Multi-Path (ECMP) routing.
- **Actions**: 
  - `usid_encap_1`: Encapsulates the packet using one SRv6 segment.
  - `usid_encap_2`: Encapsulates the packet using two SRv6 segments.
- **Counters**: `srv6_encap_table_counter` and `srv6_encap_v4_table_counter` count packets and bytes processed by these tables.
- **Default Action**: `NoAction`.

## 10. acl Table
- **Purpose**: Implements an Access Control List (ACL) for filtering packets based on multiple fields, including ingress port, MAC addresses, EtherType, IP protocol, ICMP type, and Layer 4 ports.
- **Key**: 
  - `standard_metadata.ingress_port`: Ingress port number, matched using ternary (mask-based) matching.
  - `hdr.ethernet.dst_addr`: Destination MAC address, matched using ternary matching.
  - `hdr.ethernet.src_addr`: Source MAC address, matched using ternary matching.
  - `hdr.ethernet.ether_type`: EtherType field to distinguish between IPv4, IPv6, ARP, etc.
  - `local_metadata.ip_proto`: IP protocol number (TCP, UDP, etc.), matched using ternary matching.
  - `local_metadata.icmp_type`: ICMP type for ICMP packets.
  - `local_metadata.l4_src_port`: Layer 4 source port (for TCP/UDP), matched using ternary matching.
  - `local_metadata.l4_dst_port`: Layer 4 destination port (for TCP/UDP), matched using ternary matching.
- **Actions**: 
  - `clone_to_cpu`: Clones packets to the CPU for further inspection.
  - `drop`: Drops the packet.
- **Counters**: `acl_counter` tracks packets and bytes processed by this table.
- **Default Action**: No default action specified.
