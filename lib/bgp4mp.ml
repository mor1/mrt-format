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
  | STATE | MESSAGE | MESSAGE_AS4 | STATE_AS4 | LOCAL | LOCAL_AS4 | ETC of int
let tc_to_int = function
  | STATE       -> 0
  | MESSAGE     -> 1
  | MESSAGE_AS4 -> 4
  | STATE_AS4   -> 5
  | LOCAL       -> 6
  | LOCAL_AS4   -> 7
  | ETC n       -> n
and int_to_tc = function
  | 0 -> STATE
  | 1 -> MESSAGE
  | 4 -> MESSAGE_AS4
  | 5 -> STATE_AS4
  | 6 -> LOCAL
  | 7 -> LOCAL_AS4
  | n -> ETC n
and tc_to_string = function
  | STATE       -> "STATE_CHANGE"
  | MESSAGE     -> "MESSAGE"
  | MESSAGE_AS4 -> "MESSAGE_AS4"
  | STATE_AS4   -> "STATE_CHANGE_AS4"
  | LOCAL       -> "MESSAGE_LOCAL"
  | LOCAL_AS4   -> "MESSAGE_AS4_LOCAL"
  | ETC n       -> sprintf "ETC %d" n

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

type state = 
  | Idle | Connect | Active | OpenSent | OpenConfirm | Established 
  | ESTATE of int
let state_to_int = function
  | Idle        -> 1
  | Connect     -> 2
  | Active      -> 3
  | OpenSent    -> 4
  | OpenConfirm -> 5
  | Established -> 6
  | ESTATE n    -> n
and int_to_state = function
  | 1 -> Idle
  | 2 -> Connect
  | 3 -> Active
  | 4 -> OpenSent
  | 5 -> OpenConfirm
  | 6 -> Established
  | n -> ESTATE n
and state_to_string = function
  | Idle        -> "Idle"
  | Connect     -> "Connect"
  | Active      -> "Active"
  | OpenSent    -> "OpenSent"
  | OpenConfirm -> "OpenConfirm"
  | Established -> "Established"
  | ESTATE n    -> sprintf "ESTATE %d" n

type header = {
  peer_as: Bgp.asn;
  local_as: Bgp.asn;
  ifc: int;
  peer_ip: Afi.ip;
  local_ip: Afi.ip;
} 

let header_to_string h = 
  sprintf  "peer_as:%s, local_as:%s, ifc:%d, peer_ip:%s, local_ip:%s"
    (Bgp.asn_to_string h.peer_as) (Bgp.asn_to_string h.local_as) h.ifc
    (Afi.ip_to_string h.peer_ip) (Afi.ip_to_string h.local_ip)

type payload = 
  | State of state * state
  | State_as4 of state * state
  | Message of Bgp.t
  | Message_as4 of Bgp.t
  | Local of Bgp.t
  | Local_as4 of Bgp.t

let payload_to_string = function
  | State (o,n) | State_as4 (o,n) ->
      sprintf "STATE_CHANGE(old:%s, new:%s)" 
        (state_to_string o) (state_to_string n)
  | Message _ | Message_as4 _ -> "...message..."
  | Local _ | Local_as4 _ -> "...local message..."

type t = header * payload

let parse subtype buf = 
  let get_ips buf = Afi.(function
    | IP4 -> 
        let h,bs = Cstruct.split buf sizeof_h4 in 
        IPv4 (get_h4_peer_ip h), IPv4 (get_h4_local_ip h), bs
    | IP6 ->
        let h,bs = Cstruct.split buf sizeof_h6 in 
        IPv6 ((get_h6_peer_ip_hi h), (get_h6_peer_ip_lo h)), 
        IPv6 ((get_h6_local_ip_hi h), (get_h6_local_ip_lo h)),
        bs
  ) in
  let header, bs = match subtype with 
    | MESSAGE | LOCAL | STATE ->
        let h,bs = Cstruct.split buf sizeof_h in 
        let afi = h |> get_h_afi |> Afi.int_to_tc in
        let peer_ip, local_ip, bs = get_ips bs afi in
        { peer_as = Bgp.Asn (get_h_peer_as h);
          local_as = Bgp.Asn (get_h_local_as h);
          ifc = get_h_ifc h;
          peer_ip; 
          local_ip;
        }, bs

    | MESSAGE_AS4 | LOCAL_AS4 | STATE_AS4 ->
        let h,bs = Cstruct.split buf sizeof_h_as4 in
        let afi = h |> get_h_as4_afi |> Afi.int_to_tc in
        let peer_ip, local_ip, bs = get_ips bs afi in
        { peer_as = Bgp.Asn4 (get_h_as4_peer_as h);
          local_as = Bgp.Asn4 (get_h_as4_local_as h);
          ifc = get_h_as4_ifc h;
          peer_ip; 
          local_ip;
        }, bs
  in
  let payload = match subtype with 
    | STATE | STATE_AS4 ->
        let state_change, bs = Cstruct.split bs sizeof_state_change in
        State ((state_change |> get_state_change_oldstate |> int_to_state),
               (state_change |> get_state_change_newstate |> int_to_state))
    | MESSAGE -> Message (Bgp.parse bs)
    | MESSAGE_AS4 -> Message_as4 (Bgp.parse bs)
    | LOCAL -> Local (Bgp.parse bs)
    | LOCAL_AS4 -> Local_as4 (Bgp.parse bs)
  in
  (header, payload)
                         
let to_string (h,p) = 
  sprintf "BGP4MP(%s)|%s" (header_to_string h) (payload_to_string p)

