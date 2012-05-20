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

type asn = Asn of int | Asn4 of int32
val asn_to_string: asn -> string

val pfxlen_to_bytes : int -> int
val get_nlri4 : Cstruct.buf -> int -> Afi.prefix
val get_nlri6 : Cstruct.buf -> int -> Afi.prefix

type caller = Normal | Table2 | Bgp4mp_as4
type path_attrs
val path_attrs_to_string : path_attrs -> string
val parse_path_attrs : ?caller:caller -> Cstruct.buf -> path_attrs

type t
val to_string : t -> string
val parse : ?caller:caller -> Cstruct.buf -> t Cstruct.iter
