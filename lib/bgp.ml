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

open Operators

let pfxlen_to_bytes l = ((l+7) / 8)

let get_partial_ip4 buf = 
  Cstruct.( 
    let v = ref 0l in
    for i = 0 to (min 3 ((len buf)-1)) do
      v := (!v <<< 8) +++ (Int32.of_int (BE.get_uint8 buf i))
    done;
    !v <<< (8*(4 - len buf))
  )

let get_partial_ip6 buf = 
  Cstruct.(   
    let hi = 
      let v = ref 0L in
      let n = min 7 ((len buf)-1) in
      for i = 0 to n do
        v := (!v <<<< 8) ++++ (Int64.of_int (BE.get_uint8 buf i))
      done;
      !v <<<< (8*(8 - n))
    in
    let lo = 
      let v = ref 0L in
      let n = min 15 ((len buf)-1) in
      for i = 8 to n do
        v := (!v <<<< 8) ++++ (Int64.of_int (BE.get_uint8 buf i))
      done;
      !v <<<< (8*(8 - n))
    in 
    hi, lo
  )

type attr
