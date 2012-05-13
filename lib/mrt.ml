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
  | OSPF2 | TABLE | TABLE2 | BGP4MP | BGP4MP_ET | ISIS | ISIS_ET 
  | OSPF3 | OSPF3_ET | ETC of int
let tc_to_int = function
  | OSPF2     -> 11
  | TABLE     -> 12
  | TABLE2    -> 13
  | BGP4MP    -> 16
  | BGP4MP_ET -> 17
  | ISIS      -> 32
  | ISIS_ET   -> 33
  | OSPF3     -> 48
  | OSPF3_ET  -> 49
  | ETC t     -> t
and int_to_tc = function
  | 11 -> OSPF2
  | 12 -> TABLE
  | 13 -> TABLE2
  | 16 -> BGP4MP
  | 17 -> BGP4MP_ET
  | 32 -> ISIS
  | 33 -> ISIS_ET
  | 48 -> OSPF3
  | 49 -> OSPF3_ET
  | t  -> ETC t
and tc_to_string = function
  | OSPF2     -> "OPSFv2"
  | TABLE     -> "TABLE_DUMP"
  | TABLE2    -> "TABLE_DUMP_V2"
  | BGP4MP    -> "BGP4MP"
  | BGP4MP_ET -> "BGP4MP_ET"
  | ISIS      -> "ISIS"
  | ISIS_ET   -> "ISIS_ET"
  | OSPF3     -> "OSPFv3"
  | OSPF3_ET  -> "OSPFv3_ET"
  | ETC t     -> sprintf "ETC %d" t

cstruct h {
  uint32_t ts_sec;
  uint16_t mrttype;
  uint16_t subtype;
  uint32_t length
} as big_endian

let h_to_string h =
  let mrttype = get_h_mrttype h |> int_to_tc in
  let subtype =
    let st = (get_h_subtype h) in match mrttype with
      | BGP4MP -> Bgp4mp.(st |> int_to_tc |> tc_to_string)
      | TABLE  -> Afi.(st |> int_to_tc |> tc_to_string)
      | t      -> sprintf "h_to_string (%s)" (tc_to_string t)
  in          
  sprintf "%ld %s/%s %ld"
    (get_h_ts_sec h) (tc_to_string mrttype) subtype (get_h_length h)

cstruct et {
  uint32_t ts_usec
} as big_endian
    
type header = {
  ts_sec: int32;
}

let header_to_string h = sprintf "%ld" h.ts_sec

let h_to_header h = 
  { ts_sec = get_h_ts_sec h;
  }

type payload = 
  | Bgp4mp of Bgp4mp.t
  | Table of Table.t
  | Table2 of Table2.t
  | Unknown of Cstruct.buf

let payload_to_string p = 
  sprintf "%s" (match p with 
    | Bgp4mp p  -> Bgp4mp.to_string p
    | Table p   -> Table.to_string p
    | Table2 p  -> Table2.to_string p
    | Unknown p -> "UNKNOWN()"
  )

type t = header * payload

let parse buf = 
  let h,bs = Cstruct.split buf sizeof_h in
  let p,rest = 
    let plen = Int32.to_int (get_h_length h) in
    Cstruct.split bs plen 
  in
  let payload = 
    let subtype = get_h_subtype h in
    match h |> get_h_mrttype |> int_to_tc with
      | BGP4MP -> Bgp4mp Bgp4mp.(parse (int_to_tc subtype) p)
      | TABLE  -> Table Table.(parse (Afi.int_to_tc subtype) p) 
      | TABLE2 -> Table2 Table2.(parse (int_to_tc subtype) p)
      | _      -> printf "%d\n%!" (get_h_mrttype h); Unknown p
  in
  (h_to_header h, payload), rest

let to_string (h,p) =
  sprintf "%s|%s" (header_to_string h) (payload_to_string p)
