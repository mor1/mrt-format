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
    
cstruct h4 {
  uint16_t viewno;
  uint16_t seqno;
  uint32_t prefix;
  uint8_t pfxlen;
  uint8_t status;
  uint32_t otime;
  uint32_t peer_ip;
  uint16_t peer_as;
  uint16_t attrlen
} as big_endian

cstruct h6 {
  uint16_t viewno;
  uint16_t seqno;
  uint64_t prefix_hi;
  uint64_t prefix_lo;
  uint8_t pfxlen;
  uint8_t status;
  uint32_t otime;
  uint64_t peer_ip_hi;
  uint64_t peer_ip_lo;
  uint16_t peer_as;
  uint16_t attrlen
} as big_endian

type header = {
  viewno: int;
  seqno: int;
  prefix: Afi.ip;
  pfxlen: int;
  status: int;
  otime: int32;
  peer_ip: Afi.ip;
  peer_as: Bgp.asn;
}

let header_to_string h = 
  sprintf "viewno:%d, seqno:%d, status:%d, otime:%ld, peer_ip:%s, peer_as:%s, prefix:%s/%d"
    h.viewno h.seqno h.status h.otime 
    (Afi.ip_to_string h.peer_ip) (Bgp.asn_to_string h.peer_as)
    (Afi.ip_to_string h.prefix) h.pfxlen

type payload = Not_implemented

let payload_to_string = function
  | Not_implemented -> "Not_implemented"

type t = header * payload

let parse subtype buf = 
  let header,bs = Afi.(match subtype with
    | IP4 -> let buf, rest = Cstruct.split buf sizeof_h4 in
             { viewno=get_h4_viewno buf;
               seqno=get_h4_seqno buf;
               prefix=IPv4 (get_h4_prefix buf);
               pfxlen=get_h4_pfxlen buf;
               status=get_h4_status buf;
               otime=get_h4_otime buf;
               peer_ip=IPv4 (get_h4_peer_ip buf);
               peer_as=Bgp.Asn (get_h4_peer_as buf);
             }, rest
    | IP6 -> let buf, rest = Cstruct.split buf sizeof_h6 in
             { viewno=get_h6_viewno buf;
               seqno=get_h6_seqno buf;
               prefix=IPv6 ((get_h6_prefix_hi buf), (get_h6_prefix_lo buf));
               pfxlen=get_h6_pfxlen buf;
               status=get_h6_status buf;
               otime=get_h6_otime buf;
               peer_ip=IPv6 ((get_h6_peer_ip_hi buf), (get_h6_peer_ip_lo buf));
               peer_as=Bgp.Asn (get_h6_peer_as buf);
             }, rest
  )
  in
  let payload = Not_implemented in
  (header, payload)

let to_string (h,p) = 
  sprintf "TABLE(%s)|%s" (header_to_string h) (payload_to_string p)
