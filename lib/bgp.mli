(*
 * Copyright (c) 2012-2015 Richard Mortier <mort@cantab.net>
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

type asn = 
| Asn of int 
| Asn4 of int32

type capability =
| Mp_ext of Afi.tc * Safi.tc
| Ecapability of Cstruct.t

type opt_param =
| Reserved (* wtf? *)
| Authentication (* deprecated, rfc 4271 *)
| Capability of capability

type opent = {
  version: int;
  my_as: asn;
  hold_time: int;
  bgp_id: int32;
  options: opt_param list;
}

type origin = IGP | EGP | INCOMPLETE

type asp_segment = 
| Set of int32 list 
| Seq of int32 list


type path_attr_flags = {
  optional: bool;
  transitive: bool;
  partial: bool;
  extlen: bool;
};;

type path_attr =
  | Origin of origin
  | As_path of asp_segment list
  | Next_hop of Afi.ip4
  | Community of int32
  | Ext_communities
  | Med of int32
  | Atomic_aggr
  | Aggregator
  | Mp_reach_nlri
  | Mp_unreach_nlri
  | As4_path of asp_segment list
  | Local_pref of int
  | Unknown of int
;;

type path_attrs = (path_attr_flags * path_attr) list

type update = {
  withdrawn: Afi.prefix list;
  path_attrs: path_attrs;
  nlri: Afi.prefix list;
}

type message_header_error =
  | Connection_not_synchroniszed
  | Bad_message_length of Cstruct.uint16
  | Bad_message_type of Cstruct.uint8


type open_message_error =
  | Unspecific
  | Unsupported_version_number of Cstruct.uint16
  | Bad_peer_as 
  | Bad_bgp_identifier
  | Unsupported_optional_parameter
  | Unacceptable_hold_time


type update_message_error =
| Malformed_attribute_list 
| Unrecognized_wellknown_attribute of Cstruct.t 
| Missing_wellknown_attribute of Cstruct.uint8
| Attribute_flags_error of Cstruct.t
| Attribute_length_error of Cstruct.t
| Invalid_origin_attribute of Cstruct.t
| Invalid_next_hop_attribute of Cstruct.t
| Optional_attribute_error of Cstruct.t
| Invalid_network_field
| Malformed_as_path


type msg_fmt_error = 
| Message_header_error of message_header_error
| Open_message_error of open_message_error
| Update_message_error of update_message_error
| Hold_timer_expired
| Finite_state_machine_error
| Cease


type notif_fmt_error =
| Invalid_error_code
| Invalid_sub_error_code
| Bad_message_length_n
| Connection_not_synchroniszed_n


type t =
| Open of opent
| Update of update
| Notification of msg_fmt_error
| Keepalive


type error =
| Parsing_error
| Msg_fmt_error of msg_fmt_error
| Notif_fmt_error of notif_fmt_error

val asn_to_string: asn -> string

val get_h_len: Cstruct.t -> int

val pfxlen_to_bytes : int -> int
val get_nlri4 : Cstruct.t -> int -> Afi.prefix
val get_nlri6 : Cstruct.t -> int -> Afi.prefix

type caller = Normal | Table2 | Bgp4mp_as4

val path_attrs_to_string : path_attrs -> string
val parse_path_attrs : ?caller:caller -> Cstruct.t -> path_attrs

val opent_to_string : opent -> string
val update_to_string : update -> string

val to_string : t -> string
val parse : ?caller:caller -> Cstruct.t -> t Cstruct.iter
val parse_buffer_to_t : Cstruct.t -> (t, error) Result.result

val gen_open : opent -> Cstruct.t
val gen_update : update -> Cstruct.t
val gen_keepalive : unit -> Cstruct.t
val gen_notification : msg_fmt_error -> Cstruct.t
val gen_msg : ?test:bool -> t -> Cstruct.t

val len_pfxs_buffer : Afi.prefix list -> int
val len_path_attrs_buffer : path_attrs -> int
val len_update_buffer : update -> int

