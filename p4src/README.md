
# P4 Ingress Pipeline Overview

Several tables and actions are used to handle different aspects of the packet's path, including basic forwarding, INT (In-band Network Telemetry) operations, and configuring packet processing behavior for INT reports. Let’s break down each table in the ingress pipeline:

## 1. `tb_forward` Table (Forward Control Block)
- **Purpose**: This table is used to forward packets based on their destination MAC address.
- **Key**: 
  - `hdr.ethernet.dstAddr`: The destination MAC address is matched using ternary matching (which allows for exact, wildcard, or range matches).
- **Actions**: 
  - `send_to_cpu`: Sends the packet to the CPU.
  - `send_to_port`: Specifies the egress port to which the packet will be forwarded.
- **Size**: This table can hold up to 31 entries.
- **Behavior**: This table applies forwarding rules based on the destination MAC address. Depending on the match, the packet is either forwarded to a specific port or sent to the CPU.

## 2. `tb_int_reporting` Table (INT Reporting)
- **Purpose**: Handles the generation of INT (In-band Network Telemetry) reports. When packets are identified as INT packets, this table is used to prepare and send INT reports to a specified collector.
- **Actions**: 
  - `send_report`: This action generates an INT report, populates it with telemetry data, and sends it to the INT collector (using the collector’s MAC address, IP address, and port).
- **Size**: This table can hold up to 512 entries.
- **Behavior**: The table ensures that packets containing INT headers are processed correctly and that INT reports are generated and sent to the appropriate INT collector.

## 3. `tb_int_sink` Table (INT Sink Configuration)
- **Purpose**: Configures the switch as an INT sink, which is responsible for terminating INT flows and generating INT reports. This table activates the INT sink for particular egress ports.
- **Key**: 
  - `standard_metadata.egress_spec`: The egress port is matched exactly to determine whether INT sink functionality should be applied.
- **Actions**: 
  - `configure_sink`: This action activates the INT sink by setting a flag (`remove_int`) that instructs the egress pipeline to remove all INT headers before the packet leaves the switch. It also clones the packet to the CPU for INT reporting purposes.
- **Size**: The table can hold up to 255 entries.
- **Behavior**: If the packet is destined for an egress port where INT sink functionality is active, this table will apply the `configure_sink` action, enabling INT termination and INT report generation for that packet.

## 4. `tb_int_transit` Table (INT Transit Configuration)
- **Purpose**: Configures the switch as an INT transit node. Transit nodes insert metadata into the packet as it traverses the network. This table is responsible for applying the necessary INT transit logic.
- **Actions**: 
  - `configure_transit`: Configures the switch as an INT transit node by setting the switch ID and initializing the metadata counters for tracking the number of INT words and bytes added to packets.
- **Behavior**: This table is used to set up the switch as an INT transit node, allowing it to insert metadata into packets that contain INT headers.

## 5. `tb_int_inst_0003` Table (INT Metadata Insertion for Instructions 0-3)
- **Purpose**: Inserts metadata based on the instructions encoded in the `instruction_mask` field of the INT header. This table handles instructions for inserting metadata related to the first four fields.
- **Key**: 
  - `hdr.int_header.instruction_mask`: The instruction mask from the INT header is used for ternary matching. It determines which metadata fields should be inserted into the packet at this INT node.
- **Actions**: 
  - This table has multiple actions, each of which inserts specific metadata fields. For example:
    - `int_set_header_0003_i0`: Inserts metadata for switch ID.
    - `int_set_header_0003_i1`: Inserts metadata for port IDs.
    - Other actions insert metadata for hop latency, queue occupancy, etc.
- **Behavior**: This table ensures that the correct INT metadata is added to the packet based on the instructions in the INT header. It focuses on the first four fields of metadata.

## 6. `tb_int_inst_0407` Table (INT Metadata Insertion for Instructions 4-7)
- **Purpose**: Similar to the `tb_int_inst_0003` table, this table is responsible for inserting metadata for instructions 4 through 7. It handles additional fields for telemetry data.
- **Key**: 
  - `hdr.int_header.instruction_mask`: The instruction mask from the INT header is matched to determine which metadata fields should be added.
- **Actions**: 
  - Like the `tb_int_inst_0003` table, this table has actions that insert different types of metadata. For example:
    - `int_set_header_0407_i0`: Could insert egress timestamps.
    - Other actions insert egress port utilization and other telemetry data.
- **Behavior**: This table adds INT metadata fields as per the instructions in the INT header for the second set of telemetry fields.

## 7. `tb_port_forward` Table (Port Forwarding)
- **Purpose**: This table performs basic port forwarding by setting the egress port based on the ingress port or other metadata.
- **Key**: 
  - `standard_metadata.egress_port`: The egress port is matched exactly.
- **Actions**: 
  - `send`: Sets the egress port for the packet.
- **Size**: This table can hold up to 31 entries.
- **Behavior**: This table determines the outgoing port for the packet. If no forwarding decision has been made yet, this table will ensure that the packet is sent to the correct egress port.
