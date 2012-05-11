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

type t = 
  | Ospf2 | Table | Table2 | Bgp4mp | Bgp4mp_et | Isis | Isis_et 
  | Ospf3 | Ospf3_et
let t_to_int = function
  | Ospf2     -> 11
  | Table     -> 12
  | Table2    -> 13
  | Bgp4mp    -> 16
  | Bgp4mp_et -> 17
  | Isis      -> 32
  | Isis_et   -> 33
  | Ospf3     -> 48
  | Ospf3_et  -> 49
and int_to_t = function
  | 11 -> Ospf2
  | 12 -> Table
  | 13 -> Table2
  | 16 -> Bgp4mp
  | 17 -> Bgp4mp_et
  | 32 -> Isis
  | 33 -> Isis_et
  | 48 -> Ospf3
  | 49 -> Ospf3_et
  | _  -> invalid_arg "int_to_t"
and t_to_string = function
  | Ospf2     -> "OPSFv2"
  | Table     -> "TABLE_DUMP"
  | Table2    -> "TABLE_DUMP_V2"
  | Bgp4mp    -> "BGP4MP"
  | Bgp4mp_et -> "BGP4MP_ET"
  | Isis      -> "ISIS"
  | Isis_et   -> "ISIS_ET"
  | Ospf3     -> "OSPFv3"
  | Ospf3_et  -> "OSPFv3_ET"

cstruct h {
  uint32_t ts_sec;
  uint16_t mrttype;
  uint16_t subtype;
  uint32_t length
} as big_endian

let h_to_string h = 
  sprintf "%ld %s/%d %ld"
    (get_h_ts_sec h) (get_h_mrttype h |> int_to_t |> t_to_string) 
    (get_h_subtype h) (get_h_length h);

cstruct et {
  uint32_t ts_usec
} as big_endian

