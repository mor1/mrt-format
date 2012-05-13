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

let npackets = ref 0

let rec print_packets buf = 
  incr npackets;
  let packet, rest = Mrt.parse buf in
  printf "#%d|%s\n%!" !npackets (Mrt.to_string packet);
  if Cstruct.len rest > 0 then print_packets rest

let fn_to_buf fn =
  let fd = Unix.(openfile fn [O_RDONLY] 0) in
  Bigarray.(Array1.map_file fd Bigarray.char c_layout false (-1))

let _ = 
  let buf = fn_to_buf Sys.argv.(1) in
  printf "file length %d\n" (Cstruct.len buf);
  print_packets buf;
  printf "num packets %d\n%!" !npackets
