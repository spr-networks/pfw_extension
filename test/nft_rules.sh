#!/bin/bash
# Test fixture: the tables, maps, and chains pfw operates on, with definitions
# matching the SPR base configuration.

nft -f - << 'EOF'
table inet filter {
  set outbound_sites {
    type ifname;
  }

  map site_forward {
    type ipv4_addr . ipv4_addr . ifname : verdict;
    flags interval, timeout;
  }

  map site_forward_tcp_port {
    type ipv4_addr . ipv4_addr . inet_service . ifname: verdict;
    flags interval, timeout;
  }

  map site_forward_udp_port {
    type ipv4_addr . ipv4_addr . inet_service . ifname: verdict;
    flags interval, timeout;
  }

  map fwd_block {
    type ipv4_addr . ipv4_addr . inet_proto . inet_service : verdict;
    flags interval, timeout;
  }

  chain PFWDROPLOG {
    counter log prefix "drop:pfw " group 1
    counter drop
  }
}

table inet mangle {
  map site_forward_mangle {
    type ipv4_addr . ipv4_addr : verdict;
    flags interval, timeout;
  }

  map site_forward_tcp_port_mangle {
    type ipv4_addr . ipv4_addr . inet_service: verdict;
    flags interval, timeout;
  }

  map site_forward_udp_port_mangle {
    type ipv4_addr . ipv4_addr . inet_service: verdict;
    flags interval, timeout;
  }

  set supernetworks {
    type ipv4_addr;
    flags interval;
    elements = { 192.168.2.0/24 }
  }
}

table inet nat {
  map dnat_tcp_ipmap {
    type ipv4_addr . ipv4_addr . inet_service : ipv4_addr;
    flags interval, timeout;
  }

  map dnat_tcp_portmap {
    type ipv4_addr . ipv4_addr . inet_service : inet_service;
    flags interval, timeout;
  }

  map dnat_tcp_anymap {
    type ipv4_addr . ipv4_addr : ipv4_addr;
    flags interval, timeout;
  }

  map dnat_udp_ipmap {
    type ipv4_addr . ipv4_addr . inet_service : ipv4_addr;
    flags interval, timeout;
  }

  map dnat_udp_portmap {
    type ipv4_addr . ipv4_addr . inet_service : inet_service;
    flags interval, timeout;
  }

  map dnat_udp_anymap {
    type ipv4_addr . ipv4_addr : ipv4_addr;
    flags interval, timeout;
  }
}
EOF
