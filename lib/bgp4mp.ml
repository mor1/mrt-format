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
  STATE       = 0;
  MESSAGE     = 1;
  MESSAGE_AS4 = 4;
  STATE_AS4   = 5;
  LOCAL       = 6;
  LOCAL_AS4   = 7
} as uint8_t

cstruct h {
  uint16_t peer_as;
  uint16_t local_as;
  uint16_t ifc;
  uint16_t afi
} as big_endian

cstruct h_as4 {
  uint32_t peer_as;
  uint32_t local_as;
  uint16_t ifc;
  uint16_t afi
} as big_endian

cstruct h4 {
  uint32_t peer_ip;
  uint32_t local_ip
} as big_endian

cstruct h6 {
  uint64_t peer_ip_hi;
  uint64_t peer_ip_lo;
  uint64_t local_ip_hi;
  uint64_t local_ip_lo
} as big_endian

cstruct state_change {
  uint16_t oldstate;
  uint16_t newstate
} as big_endian

cenum state {
  Idle        = 1;
  Connect     = 2;
  Active      = 3;
  OpenSent    = 4;
  OpenConfirm = 5;
  Established = 6
} as uint8_t

type header = {
  peer_as: Bgp.asn;
  local_as: Bgp.asn;
  ifc: int;
  peer_ip: Afi.ip;
  local_ip: Afi.ip;
} 

let header_to_string h = 
  sprintf "peer_as:%s, local_as:%s, ifc:%d, peer_ip:%s, local_ip:%s"
    (Bgp.asn_to_string h.peer_as) (Bgp.asn_to_string h.local_as) h.ifc
    (Afi.ip_to_string h.peer_ip) (Afi.ip_to_string h.local_ip)

type payload = 
  | State of state option * state option
  | State_as4 of state option * state option
  | Message of Bgp.t option
  | Message_as4 of Bgp.t option
  | Local of Bgp.t option
  | Local_as4 of Bgp.t option

let payload_to_string = function
  | State (o,n) | State_as4 (o,n) ->
      let os = match o with None -> "BAD" | Some s -> state_to_string s in
      let ns = match n with None -> "BAD" | Some s -> state_to_string s in
      sprintf "STATE_CHANGE(%s -> %s)" os ns
  | Message p | Message_as4 p -> (match p with
      | None -> failwith "bad BGP message"
      | Some p -> sprintf "MESSAGE(%s)" (Bgp.to_string p)
  )
  | Local _ | Local_as4 _ -> "...local message..."

type t = header * payload

let to_string (h,p) = 
  sprintf "BGP4MP(%s)|%s" (header_to_string h) (payload_to_string p)

let parse subtype buf = 
  let get_ips bs = 
    Afi.(function
      | IP4 -> 
          IPv4 (get_h4_peer_ip bs), IPv4 (get_h4_local_ip bs)
      | IP6 ->
          (IPv6 ((get_h6_peer_ip_hi bs), (get_h6_peer_ip_lo bs)), 
           IPv6 ((get_h6_local_ip_hi bs), (get_h6_local_ip_lo bs)))
    )
  in
  let lenf buf = 
    let hlen, afi = match int_to_tc subtype with 
      | Some (MESSAGE|LOCAL|STATE) -> sizeof_h, get_h_afi buf
      | Some (MESSAGE_AS4|LOCAL_AS4|STATE_AS4)
        -> sizeof_h_as4, get_h_as4_afi buf
      | None -> failwith "lenf: bad BGP4MP header"
    in
    let ipslen = Afi.(match int_to_tc afi with
      | IP4 -> sizeof_h4
      | IP6 -> sizeof_h6
    )
    in
    hlen+ipslen, Cstruct.len buf - hlen-ipslen
  in
  let pf hlen buf = 
    let h,p = Cstruct.split buf hlen in
    let header = match int_to_tc subtype with 
      | Some (MESSAGE|LOCAL|STATE) ->
          let peer_as = Bgp.Asn (get_h_peer_as h) in
          let local_as = Bgp.Asn (get_h_local_as h) in
          let ifc = get_h_ifc h in
          let afi = get_h_afi h |> Afi.int_to_tc in
          let peer_ip, local_ip = 
            let h = Cstruct.shift h sizeof_h in
            get_ips h afi 
          in
          { peer_as; local_as; ifc; peer_ip; local_ip }

      | Some(MESSAGE_AS4|LOCAL_AS4|STATE_AS4) ->
          let peer_as = Bgp.Asn4 (get_h_as4_peer_as h) in
          let local_as = Bgp.Asn4 (get_h_as4_local_as h) in
          let ifc = get_h_as4_ifc h in
          let afi = get_h_as4_afi h |> Afi.int_to_tc in
          let peer_ip, local_ip = 
            let h = Cstruct.shift h sizeof_h_as4 in
            get_ips h afi 
          in
          { peer_as; local_as; ifc; peer_ip; local_ip }

      | None -> failwith "pf: bad BGP4MP header"
    in
    let payload = match int_to_tc subtype with 
      | Some (STATE|STATE_AS4) ->
          State ((p |> get_state_change_oldstate |> int_to_state),
                 (p |> get_state_change_newstate |> int_to_state))
      | Some MESSAGE -> Message (Bgp.parse p ())
      | Some MESSAGE_AS4 
        -> Message_as4 (Bgp.parse ~caller:Bgp.Bgp4mp_as4 p ())
      | Some LOCAL -> Local (Bgp.parse p ())
      | Some LOCAL_AS4 -> Local_as4 (Bgp.parse ~caller:Bgp.Bgp4mp_as4 p ())
      | None -> failwith "pf: bad BGP4MP payload"
    in
    (header, payload)
  in
  Cstruct.iter lenf pf buf
