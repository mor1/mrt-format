(*
 * Copyright (c) 2012 Richard Mortier <mort@cantab.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

open Printf
open Operators

type tc =        
  | PEER_INDEX_TABLE | RIB_IPV4_UNICAST | RIB_IPV4_MULTICAST
  | RIB_IPV6_UNICAST | RIB_IPV6_MULTICAST | RIB_GENERIC

let tc_to_int = function
  | PEER_INDEX_TABLE -> 1
  | RIB_IPV4_UNICAST -> 2
  | RIB_IPV4_MULTICAST -> 3
  | RIB_IPV6_UNICAST -> 4
  | RIB_IPV6_MULTICAST -> 5
  | RIB_GENERIC -> 6
and int_to_tc = function
  | 1 -> PEER_INDEX_TABLE
  | 2 -> RIB_IPV4_UNICAST
  | 3 -> RIB_IPV4_MULTICAST
  | 4 -> RIB_IPV6_UNICAST
  | 5 -> RIB_IPV6_MULTICAST
  | 6 -> RIB_GENERIC
and tc_to_string = function
  | PEER_INDEX_TABLE -> "PEER_INDEX_TABLE"
  | RIB_IPV4_UNICAST -> "RIB_IPV4_UNICAST"
  | RIB_IPV4_MULTICAST -> "RIB_IPV4_MULTICAST"
  | RIB_IPV6_UNICAST -> "RIB_IPV6_UNICAST"
  | RIB_IPV6_MULTICAST -> "RIB_IPV6_MULTICAST"
  | RIB_GENERIC -> "RIB_GENERIC"

cstruct index_table {
  uint32_t bgpid
} as big_endian

cstruct viewname {
  uint16_t len
} as big_endian

cstruct peers {
  uint16_t count
} as big_endian

cstruct peer {
  uint8_t typ;
  uint32_t bgpid
} as big_endian

cstruct peer_ip4 {
  uint32_t ip
} as big_endian

cstruct peer_ip6 {
  uint64_t hi;
  uint64_t lo
} as big_endian

cstruct peer_as {
  uint16_t asn
} as big_endian

cstruct peer_as4 {
  uint32_t asn4
} as big_endian

type peer = {
  id: int32;
  ip: Afi.ip;
  asn: Bgp4mp.asn;
}

let peer_to_string p = 
  sprintf "id:0x%08lx, ip:%s, asn:%s" 
    p.id (Afi.ip_to_string p.ip) (Bgp4mp.asn_to_string p.asn)

type header = unit

type payload = 
  | Index_table of int32 * string * peer list
(*
  | Ip4_uni of
  | Ip4_multi of
  | Ip6_uni of
  | Ip6_multi of
  | Generic of
*)

let payload_to_string = function
  | Index_table (id, n, peers) ->
      sprintf "bgpid:0x%08lx, name:\"%s\", peers:[%s]" 
        id n (peers ||> peer_to_string |> String.concat "; ")

type t = header * payload

let parse subtype buf = 
  let payload, bs = match subtype with
    | PEER_INDEX_TABLE ->
        let it,bs = Cstruct.split buf sizeof_index_table in
        let vl,bs = Cstruct.split bs sizeof_viewname in
        let viewname,bs = Cstruct.split bs (get_viewname_len vl) in
        let viewname = Cstruct.to_string viewname in
        let pc,bs = Cstruct.split bs sizeof_peers in
        let peer_count = get_peers_count pc in

        let peer_entries buf = 
          let rec aux rem acc bs =
            if rem = 0 then acc, bs
            else (
              let entry,bs = Cstruct.split bs sizeof_peer in
              let typ = get_peer_typ entry in
              let id = get_peer_bgpid entry in
              let ip,bs = match is_bit typ 7 with
                | false -> 
                    let ip,bs = Cstruct.split bs sizeof_peer_ip4 in
                    Afi.IPv4 (get_peer_ip4_ip ip), bs
                | true -> 
                    let ip,bs = Cstruct.split bs sizeof_peer_ip6 in
                    Afi.IPv6 ((get_peer_ip6_hi ip),(get_peer_ip6_lo ip)), bs
              in
              let asn,bs = match is_bit typ 6 with
                | false -> 
                    let asn,bs = Cstruct.split bs sizeof_peer_as in
                    Bgp4mp.Asn (get_peer_as_asn asn), bs
                | true -> 
                    let asn,bs = Cstruct.split bs sizeof_peer_as4 in
                    Bgp4mp.Asn4 (get_peer_as4_asn4 asn), bs
              in
              let peer_entry = { id; ip; asn } in
              aux (rem-1) (peer_entry :: acc) bs
            )
          in
          aux peer_count [] buf
        in
        let entries,rest = peer_entries bs in
        Index_table ((get_index_table_bgpid it), viewname, entries), rest
  in
  ((), payload)

let to_string (h,p) = 
  sprintf "TABLE2()|%s" (payload_to_string p)
