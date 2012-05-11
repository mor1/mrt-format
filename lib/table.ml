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
