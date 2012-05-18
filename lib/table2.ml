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

cenum tc {
  PEER_INDEX_TABLE   = 1;
  RIB_IPV4_UNICAST   = 2;
  RIB_IPV4_MULTICAST = 3;
  RIB_IPV6_UNICAST   = 4;
  RIB_IPV6_MULTICAST = 5
(*
  ;
  RIB_GENERIC        = 6
*)
} as uint8_t

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

cstruct peer_as {
  uint16_t asn
} as big_endian

cstruct peer_as4 {
  uint32_t asn4
} as big_endian

type peer = {
  id: int32;
  ip: Afi.ip;
  asn: Bgp.asn;
}

let peer_to_string p = 
  sprintf "id:0x%08lx, ip:%s, asn:%s" 
    p.id (Afi.ip_to_string p.ip) (Bgp.asn_to_string p.asn)

let peers_to_string ps = 
  let rec aux acc ps = match ps () with
    | None -> acc
    | Some p -> sprintf "%s; %s" acc (peer_to_string p)
  in 
  aux "" ps

cstruct rib_h4 {
  uint32_t seqno;
  uint8_t pfxlen;
  uint32_t prefix;
  uint16_t count
} as big_endian

cstruct rib_h6 {
  uint32_t seqno;
  uint8_t pfxlen;
  uint64_t prefix_hi;
  uint64_t prefix_lo;
  uint16_t count
} as big_endian
    
cstruct rib_entry {
  uint16_t peer;
  uint32_t otime;
  uint16_t alen
} as big_endian

type rib = {
  peer_index: int; (* 16 bit, index into peer_table *)
  otime: int32;
  attrs: Bgp.path_attr list;
}

let rib_to_string r = 
  sprintf "peer:%d, otime:%lu, attrs:[]" r.peer_index r.otime 

let ribs_to_string rs = 
  let rec aux acc rs = match rs () with
    | None -> acc
    | Some r -> sprintf "%s; %s" acc (rib_to_string r)
  in
  aux "" rs
  
type t =
  | Index_table of int32 * string * peer Cstruct.iter
  | Ip4_uni of int32 * Afi.prefix * rib Cstruct.iter
  | Ip4_multi of int32 * Afi.prefix * rib Cstruct.iter
  | Ip6_uni of int32 * Afi.prefix * rib Cstruct.iter
  | Ip6_multi of int32 * Afi.prefix * rib Cstruct.iter

let to_string p =
  let payload_to_string = function
    | Index_table (id, n, peers) ->
        sprintf "INDEX_TABLE(bgpid:0x%08lx, name:\"%s\", peers:[%s])" 
          id n (peers_to_string peers)

    | Ip4_uni (seqno, prefix, ribs) ->
        sprintf "IPV4_UNICAST(seqno:%ld, prefix:%s, ribs:[%s])"
          seqno (Afi.prefix_to_string prefix) (ribs_to_string ribs)

    | Ip4_multi (seqno, prefix, ribs) ->
        sprintf "IPV4_MULTICAST(seqno:%ld, prefix:%s, ribs:[%s])"
          seqno (Afi.prefix_to_string prefix) (ribs_to_string ribs)

    | Ip6_uni (seqno, prefix, ribs) ->
        sprintf "IPV6_UNICAST(seqno:%ld, prefix:%s, ribs:[%s])"
          seqno (Afi.prefix_to_string prefix) (ribs_to_string ribs) 

    | Ip6_multi (seqno, prefix, ribs) ->
        sprintf "IPV6_MULTICAST(seqno:%ld, prefix:%s, ribs:[%s])"
          seqno (Afi.prefix_to_string prefix) (ribs_to_string ribs) 
  in
  sprintf "TABLE2()|%s" (payload_to_string p)

let parse subtype buf =
(*
    let ribs,rest = 
      Cstruct.getn nribs (fun buf ->
        let rib,bs = Cstruct.split buf sizeof_rib_entry in
        let attrs,bs = Cstruct.split bs (get_rib_entry_alen rib) in
        { peer_index = get_rib_entry_peer rib;
          otime = get_rib_entry_otime rib;
          attrs = [];
        }, bs
      ) bs
    in
    rib_h, pfx, ribs, rest
  in
*)
  let lenf buf = 
    let hlen = match int_to_tc subtype with
      | None -> failwith "lenf: bad TABLE2 header"
      | Some PEER_INDEX_TABLE -> 0
      | Some (RIB_IPV4_UNICAST|RIB_IPV4_MULTICAST) -> sizeof_rib_h4
      | Some (RIB_IPV6_UNICAST|RIB_IPV6_MULTICAST) -> sizeof_rib_h6
    in hlen, Cstruct.len buf - hlen
  in
  let pf hlen buf = (), (match int_to_tc subtype with
    | Some RIB_IPV4_UNICAST ->
        let pfx = get_rib_h4_pfxlen buf |> Bgp.pfxlen_to_bytes in
        let ribs = x in
        Ip4_uni (
          (get_rib_h4_seqno buf), 
          (Afi.(IPv4 (Bgp.get_partial_ip4 pfx)), get_rib_h4_pfxlen buf), 
          ribs
        )
          
    | Some RIB_IPV4_MULTICAST ->
        let pfx = get_rib_h4_pfxlen buf |> Bgp.pfxlen_to_bytes in
        let ribs = x in
        Ip4_multi (
          (get_rib_h4_seqno buf), 
          (Afi.(IPv4 (Bgp.get_partial_ip4 pfx)), get_rib_h4_pfxlen buf), 
          ribs
        )

    | Some RIB_IPV6_UNICAST ->
        let pfx = get_rib_h6_pfxlen buf |> Bgp.pfxlen_to_bytes in
        let ribs = x in
        Ip6_uni (
          (get_rib_h6_seqno buf), 
          (Afi.(IPv6 (Bgp.get_partial_ip6 pfx)), get_rib_h6_pfxlen buf), 
          ribs
        )
          
    | Some RIB_IPV6_MULTICAST ->
        let pfx = get_rib_h6_pfxlen buf |> Bgp.pfxlen_to_bytes in
        let ribs = x in
        Ip6_multi (
          (get_rib_h6_seqno buf), 
          (Afi.(IPv6 (Bgp.get_partial_ip6 pfx)), get_rib_h6_pfxlen buf), 
          ribs
        )
    | Some PEER_INDEX_TABLE ->
        let it,bs = Cstruct.split buf sizeof_index_table in
        let vl,bs = Cstruct.split bs sizeof_viewname in
        let viewname,bs = 
          let v,bs = Cstruct.split bs (get_viewname_len vl) in
          Cstruct.to_string v, bs
        in
        let npeer_entries,bs = 
          let v,bs = Cstruct.split bs sizeof_peers in
          get_peers_count v, bs
        in
        let peer_entries,rest = Cstruct.getn npeer_entries (fun buf ->
          let entry,bs = Cstruct.split buf sizeof_peer in
          let typ = get_peer_typ entry in
          let id = get_peer_bgpid entry in
          let ip,bs = match is_bit 0 (* 7 *) typ with
            | false -> 
                let ip,bs = Cstruct.split bs Afi.sizeof_ip4 in
                Afi.(IPv4 (get_ip4_ip ip)), bs
            | true -> 
                let ip,bs = Cstruct.split bs Afi.sizeof_ip6 in
                Afi.(IPv6 ((get_ip6_hi ip),(get_ip6_lo ip))), bs
          in
          let asn,bs = match is_bit 1 (* 6 *) typ with
            | false -> 
                let asn,bs = Cstruct.split bs sizeof_peer_as in
                Bgp.Asn (get_peer_as_asn asn), bs
            | true -> 
                let asn,bs = Cstruct.split bs sizeof_peer_as4 in
                Bgp.Asn4 (get_peer_as4_asn4 asn), bs
          in
          { id; ip; asn }, bs
        ) bs
        in
        Index_table ((get_index_table_bgpid it), viewname, peer_entries), rest
          
  )
  in
  Cstruct.iter lenf pf buf
