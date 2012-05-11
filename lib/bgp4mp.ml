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
    
type t = State | Message | Message_as4 | State_as4 | Local | Local_as4
let t_to_int = function
  | State -> 0
  | Message -> 1
  | Message_as4 -> 4
  | State_as4 -> 5
  | Local -> 6
  | Local_as4 -> 7
and int_to_t = function
  | 0 -> State
  | 1 -> Message
  | 4 -> Message_as4
  | 5 -> State_as4
  | 6 -> Local
  | 7 -> Local_as4
  | _ -> invalid_arg "int_to_t"
and t_to_string = function
  | State -> "STATE_CHANGE"
  | Message -> "MESSAGE"
  | Message_as4 -> "MESSAGE_AS4"
  | State_as4 -> "STATE_CHANGE_AS4"
  | Local -> "MESSAGE_LOCAL"
  | Local_as4 -> "MESSAGE_AS4_LOCAL"

type asn = Asn of int | Asn4 of int32
let asn_to_string = function
  | Asn a -> sprintf "%d" a
  | Asn4 a -> sprintf "%ld" a

cstruct h {
  uint16_t peer_as;
  uint16_t local_as;
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

type state = Idle | Connect | Active | OpenSent | OpenConfirm | Established
let state_to_int = function
  | Idle -> 1
  | Connect -> 2
  | Active -> 3
  | OpenSent -> 4
  | OpenConfirm -> 5
  | Established -> 6
and int_to_state = function
  | 1 -> Idle
  | 2 -> Connect
  | 3 -> Active
  | 4 -> OpenSent
  | 5 -> OpenConfirm
  | 6 -> Established
  | n -> invalid_arg (sprintf "int_to_state (%d)" n)
and state_to_string = function
  | Idle -> "Idle"
  | Connect -> "Connect"
  | Active -> "Active"
  | OpenSent -> "OpenSent"
  | OpenConfirm -> "OpenConfirm"
  | Established -> "Established"

cstruct h_as4 {
  uint32_t peer_as;
  uint32_t local_as;
  uint16_t ifc;
  uint16_t afi
} as big_endian


