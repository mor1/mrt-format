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
    
cstruct h4 {
  uint16_t peer_as;
  uint16_t local_as;
  uint16_t ifc;
  uint16_t afi;
  uint32_t peer_ip;
  uint32_t local_ip
} as big_endian

cstruct h6 {
  uint16_t peer_as;
  uint16_t local_as;
  uint16_t ifc;
  uint16_t afi;
  uint64_t peer_ip_hi;
  uint64_t peer_ip_lo;
  uint64_t local_ip_hi;
  uint64_t local_ip_lo
} as big_endian

type t = IP4 | IP6
let t_to_int = function
  | IP4 -> 1
  | IP6 -> 2
and int_to_t = function
  | 1 -> IP4
  | 2 -> IP6
  | _ -> invalid_arg "int_to_t"      
and t_to_string = function
  | IP4 -> "IPv4"
  | IP6 -> "IPv6"      

cstruct state_change {
  uint16_t oldstate;
  uint16_t newstate
} as big_endian

cstruct h4_as4 {
  uint32_t peer_as;
  uint32_t local_as;
  uint16_t ifc;
  uint16_t afi;
  uint32_t peer_ip;
  uint32_t local_ip
} as big_endian

cstruct h6_as4 {
  uint32_t peer_as;
  uint32_t local_as;
  uint16_t ifc;
  uint16_t afi;
  uint64_t peer_ip_hi;
  uint64_t peer_ip_lo;
  uint64_t local_ip_hi;
  uint64_t local_ip_lo
} as big_endian

