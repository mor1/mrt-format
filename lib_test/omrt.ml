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

open Mrt
open Printf
open Operators

let npackets = ref 0

let parse_bgp4mp h bs = 
  printf 
                    
let rec parse_packets buf = 
  incr npackets;
  
  let h,bs = Cstruct.split buf Mrt.sizeof_h in
  let plen = Int32.to_int (get_h_length h) in
  let p,bs = Cstruct.split bs plen in

  printf "[%d] %s\n%!" !npackets (h_to_string h);
  (match (get_h_mrttype h |> int_to_t) with
    | Bgp4mp -> parse_bgp4mp (h |> get_h_subtype |> Bgp4mp.int_to_t) bs
    | _      -> invalid_arg "mrttype"
  );
  if Cstruct.len bs > 0 then parse_packets bs

let parse fn =
  let fd = Unix.(openfile fn [O_RDONLY] 0) in

  let buf = Bigarray.(Array1.map_file fd Bigarray.char c_layout false (-1)) in
  Printf.printf "file length %d\n" (Cstruct.len buf);

  parse_packets buf;
  Printf.printf "num packets %d\n%!" !npackets

let _ = 
  parse Sys.argv.(1)







