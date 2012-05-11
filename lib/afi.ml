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
open Printf 

type t = IP4 | IP6
let t_to_int = function
  | IP4 -> 1
  | IP6 -> 2
and int_to_t = function
  | 1 -> IP4
  | 2 -> IP6
  | n -> invalid_arg (sprintf "Afi.int_to_t (%d)" n)
and t_to_string = function
  | IP4 -> "IPv4"
  | IP6 -> "IPv6"      

type ip = IPv4 of int32 | IPv6 of int64 * int64
let ip_to_string = function
  | IPv4 ip -> 
      sprintf "%ld.%ld.%ld.%ld" 
        (ip >>> 24 &&& 0xff_l) (ip >>> 16 &&& 0xff_l) (ip >>> 8 &&& 0xff_l) (ip &&& 0xff_l)
  | IPv6 (hi,lo) -> 
      sprintf "%04Lx:%04Lx:%04Lx:%04Lx:%04Lx:%04Lx:%04Lx:%04Lx"
        (hi >>>> 48 &&&& 0xffff_L) (hi >>>> 32 &&&& 0xffff_L)
        (hi >>>> 16 &&&& 0xffff_L) (hi         &&&& 0xffff_L)
        (lo >>>> 48 &&&& 0xffff_L) (lo >>>> 32 &&&& 0xffff_L)
        (lo >>>> 16 &&&& 0xffff_L) (lo         &&&& 0xffff_L)
