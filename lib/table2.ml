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
(* RIB_GENERIC        = 6 *)
} as uint8_t

cstruct index_table {
  uint32_t bgpid
} as big_endian

let get_name8 ?(off=0) buf = Cstruct.(
  let len = get_uint8 buf off in
  let name = sub buf 1 len in
  if not (shift_left buf (len+1)) then
    failwith "get_name8: shiftleft"
  else
    to_string name, buf
)

let get_name16 ?(off=0) buf = Cstruct.(
  let len = BE.get_uint16 buf off in
  let name = sub buf 2 len in
  if not (shift_left buf (len+2)) then
    failwith "get_name16: shiftleft"
  else 
    to_string name, buf
)

cstruct peer {
  uint8_t typ;
  uint32_t bgpid
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

cstruct rib_h {
  uint32_t seqno
} as big_endian

cstruct rib {
  uint16_t peer;
  uint32_t otime;
  uint16_t alen
} as big_endian

type rib = {
  peer_index: int; (* 16 bit, index into peer_table *)
  otime: int32;
  attrs: Cstruct.buf; (* Bgp.path_attr Cstruct.iter; *)
}

let rib_to_string r = 
  sprintf "peer:%d, otime:%lu, attrs:[]" r.peer_index r.otime 

let ribs_to_string rs = 
  let rec aux acc rs = match rs () with
    | None -> acc
    | Some r -> sprintf "%s; %s" acc (rib_to_string r)
  in
  aux "" rs
  
type header = unit

type payload = 
  | Index_table of int32 * string * peer Cstruct.iter
  | Ip4_unicast of int32 * Afi.prefix * rib Cstruct.iter
  | Ip4_multicast of int32 * Afi.prefix * rib Cstruct.iter
  | Ip6_unicast of int32 * Afi.prefix * rib Cstruct.iter
  | Ip6_multicast of int32 * Afi.prefix * rib Cstruct.iter

type t = header * payload

let to_string (_,p) =
  let payload_to_string = function
    | Index_table (id, n, peers) ->
        sprintf "INDEX_TABLE(bgpid:0x%08lx, name:\"%s\", peers:[%s])" 
          id n (peers_to_string peers)

    | Ip4_unicast (seqno, prefix, ribs) ->
        sprintf "IPV4_UNICAST(seqno:%ld, prefix:%s, ribs:[%s])"
          seqno (Afi.prefix_to_string prefix) (ribs_to_string ribs)

    | Ip4_multicast (seqno, prefix, ribs) ->
        sprintf "IPV4_MULTICAST(seqno:%ld, prefix:%s, ribs:[%s])"
          seqno (Afi.prefix_to_string prefix) (ribs_to_string ribs)

    | Ip6_unicast (seqno, prefix, ribs) ->
        sprintf "IPV6_UNICAST(seqno:%ld, prefix:%s, ribs:[%s])"
          seqno (Afi.prefix_to_string prefix) (ribs_to_string ribs) 

    | Ip6_multicast (seqno, prefix, ribs) ->
        sprintf "IPV6_MULTICAST(seqno:%ld, prefix:%s, ribs:[%s])"
          seqno (Afi.prefix_to_string prefix) (ribs_to_string ribs) 
  in
  sprintf "TABLE2()|%s" (payload_to_string p)

let parse subtype buf =
  let lenf buf = 
    let hlen = match int_to_tc subtype with
      | None -> failwith "lenf: bad TABLE2 header"
      | Some PEER_INDEX_TABLE -> 0
      | Some (RIB_IPV4_UNICAST|RIB_IPV4_MULTICAST) -> sizeof_rib_h
      | Some (RIB_IPV6_UNICAST|RIB_IPV6_MULTICAST) -> sizeof_rib_h
    in hlen, Cstruct.len buf - hlen
  in
  let parse_ribs hlen buf = 
    if not (Cstruct.shift_left buf sizeof_rib_h) then
      failwith "bad ip4_uni rib"
    else (
      Cstruct.iter
        (fun buf -> sizeof_rib, get_rib_alen buf)
        (fun hlen buf -> 
          let h,p = Cstruct.split buf hlen in
          let peer_index = get_rib_peer h in
          let otime = get_rib_otime h in
          { peer_index; otime; attrs=p }
        )
        buf
    )
  in
  let pf hlen buf = (), (match int_to_tc subtype with
    | Some PEER_INDEX_TABLE ->
        let itid = get_index_table_bgpid buf in
        if not (Cstruct.shift_left buf sizeof_index_table) then
          failwith "bad peer_index_table";
        let viewname, buf = get_name16 buf in
        let parse_peer_entries = Cstruct.(
          iter
            (fun buf -> 
              let pt = get_peer_typ buf in 
              let plen = (if is_bit 0 (* 7 *) pt then 16 else 4)
                + (if is_bit 1 (* 6 *) pt then 4 else 2)
              in
              (sizeof_peer, plen)
            )
            (fun hlen buf -> 
              let h,p = Cstruct.split buf hlen in
              let pt = get_peer_typ h in
              let id = get_peer_bgpid h in
              let ip, sz = Afi.(match is_bit 0 (* 7 *) pt with
                | false -> IPv4 (get_ip4_ip p), sizeof_ip4
                | true -> IPv6 (get_ip6_hi p, get_ip6_lo p), sizeof_ip6
              ) in
              if not (Cstruct.shift_left p sz) then
                failwith "peer_entry";
              let asn = Bgp.(match is_bit 1 (* 6 *) pt with
                | false -> Asn (Bgp.get_asn_v p) 
                | true -> Asn4 (Bgp.get_asn4_v p)
              ) in
              { id; ip; asn }
            )
            buf
        )
        in
        Index_table (itid, viewname, parse_peer_entries)

    | Some RIB_IPV4_UNICAST ->
        let seqno = get_rib_h_seqno buf in
        let prefix = Bgp.get_nlri4 buf sizeof_rib_h in
        Ip4_unicast (seqno, prefix, parse_ribs hlen buf)

    | Some RIB_IPV4_MULTICAST ->
        let seqno = get_rib_h_seqno buf in
        let prefix = Bgp.get_nlri4 buf sizeof_rib_h in
        Ip4_multicast (seqno, prefix, parse_ribs hlen buf)

    | Some RIB_IPV6_UNICAST ->
        let seqno = get_rib_h_seqno buf in
        let prefix = Bgp.get_nlri6 buf sizeof_rib_h in
        Ip6_unicast (seqno, prefix, parse_ribs hlen buf)
          
    | Some RIB_IPV6_MULTICAST ->
        let seqno = get_rib_h_seqno buf in
        let prefix = Bgp.get_nlri6 buf sizeof_rib_h in
        Ip6_multicast (seqno, prefix, parse_ribs hlen buf)
  )
  in
  Cstruct.iter lenf pf buf
