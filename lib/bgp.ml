(*
 * Copyright (c) 2012-2017 Richard Mortier <mort@cantab.net>
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

(* Lame, lame, lame. RFC6396, sec. 4.3.4 says that AS_PATHs MUST be encoded as
   4 bytes in a TABLE_DUMP_V2 RIB_ENTRY, no matter what. Similarly in BGP4MP
   MESSAGE_AS4 and LOCAL_AS4 message types (4.4.3 and 4.4.6). The first
   section (4.3.4) then says, in the same section, that MP_REACH_NLRI
   attributes contain only the nexthop address length and address, not the
   AFI, SAFI and NLRI fields as these are encoded in the RIB entry header.

   We hack around this via the `caller` parameter, typed appropriately; and by
   forcing aspath to always contain `int32`.

   MRT remains IMO, in random ways, a half-witted format. *)

type caller = Normal | Table2 | Bgp4mp_as4

let rec cstruct_iter_to_list iter =
  match iter () with
  | Some v -> v :: (cstruct_iter_to_list iter)
  | None -> []
;;

type asn = Asn of int | Asn4 of int32

let asn_to_int = function
  | Asn a -> a
  | Asn4 a -> Int32.to_int a

let asn_to_string = function
  | Asn a -> sprintf "%d" a
  | Asn4 a ->
    if a < 65536_l then sprintf "%ld" a
    else
      sprintf "%ld.%ld" (a >>> 16) (a &&& 0xFFFF_l)

let pfxlen_to_bytes l = (l+7) / 8

let get_nlri4 buf off =
  Cstruct.(
    let v = ref 0l in
    let pl = get_uint8 buf off in
    let bl = pfxlen_to_bytes pl in
    for i = 0 to bl-1 do
      v := (!v <<< 8) +++ (Int32.of_int (get_uint8 buf (off+i+1)))
    done;
    Afi.IPv4 (!v <<< (8*(4 - bl))), pl
  )

let get_nlri6 buf off =
  Cstruct.(
    let pl = get_uint8 buf off in
    let bl = pfxlen_to_bytes pl in
    let hi =
      let v = ref 0L in
      let n = min 7 (bl-1) in
      for i = 0 to n do
        v := (!v <<<< 8) ++++ (Int64.of_int (get_uint8 buf off+i+1))
      done;
      !v <<<< (8*(8 - n))
    in
    let lo =
      let v = ref 0L in
      let n = min 15 (bl-1) in
      for i = 8 to n do
        v := (!v <<<< 8) ++++ (Int64.of_int (get_uint8 buf off+i+1))
      done;
      !v <<<< (8*(8 - n))
    in
    Afi.IPv6 (hi, lo), pl
  )

let get_partial buf =
  let get_partial_ip4 buf =
    Cstruct.(
      let v = ref 0l in
      for i = 0 to (min 3 ((len buf)-1)) do
        v := (!v <<< 8) +++ (Int32.of_int (get_uint8 buf i))
      done;
      !v <<< (8*(4 - len buf))
    )
  in
  let get_partial_ip6 buf =
    Cstruct.(
      let hi =
        let v = ref 0L in
        let n = min 7 ((len buf)-1) in
        for i = 0 to n do
          v := (!v <<<< 8) ++++ (Int64.of_int (get_uint8 buf i))
        done;
        !v <<<< (8*(8 - n))
      in
      let lo =
        let v = ref 0L in
        let n = min 15 ((len buf)-1) in
        for i = 8 to n do
          v := (!v <<<< 8) ++++ (Int64.of_int (get_uint8 buf i))
        done;
        !v <<<< (8*(8 - n))
      in
      hi, lo
    )
  in
  let l = Cstruct.get_uint8 buf 0 in
  let bl = pfxlen_to_bytes l in
  let ip,bs = Cstruct.split ~start:1 buf bl in
  let ip =
    if bl > 4 then
      let (hi,lo) = get_partial_ip6 ip in Afi.IPv6 (hi,lo)
    else
      Afi.IPv4 (get_partial_ip4 ip)
  in (ip,l)

let parse_nlris buf =
  let lenf buf = Some (1 + (pfxlen_to_bytes (Cstruct.get_uint8 buf 0))) in
  let pf buf =
    if pfxlen_to_bytes (Cstruct.get_uint8 buf 0) <= 4 then
      get_nlri4 buf 0
    else
      get_nlri6 buf 0
  in
  cstruct_iter_to_list (Cstruct.iter lenf pf buf)

[%%cstruct
  type h = {
     marker: uint8_t; [@len 16]
     len: uint16_t;
     typ: uint8_t;
   }
  [@@big_endian]
]

[%%cenum
  type tc =
    | OPEN [@id 1]
    | UPDATE
    | NOTIFICATION
    | KEEPALIVE
  [@@uint8_t]
]

[%%cenum
  type cc =
    | MP_EXT                      [@id 1]
    | ROUTE_REFRESH
    | OUTBOUND_ROUTE_FILTERING
    | MULTIPLE_ROUTES_DESTINATION
    | EXT_HEXTHOP_ENC
    | GRACEFUL_RESTART            [@id 64]
    | AS4_SUPPORT
    | ENHANCED_REFRESH            [@id 70]
  [@@uint8_t]
]

[%%cstruct
  type mp_ext = {
    afi: uint16_t;
    safi: uint16_t;
  }
  [@@big_endian]
]

type capability =
  | Mp_ext of Afi.tc * Safi.tc
  | Ecapability of Cstruct.t

let capability_to_string = function
  | Mp_ext (a,s) ->
    sprintf "MP_EXT(%s,%s)" (Afi.tc_to_string a) (Safi.tc_to_string s)
  | Ecapability _ -> "UNKNOWN_CAPABILITY"

let parse_capability buf = function
  | Some MP_EXT -> Mp_ext (
    get_mp_ext_afi buf |> Afi.int_to_tc,
    get_mp_ext_safi buf |> Safi.int_to_tc)
  | Some ROUTE_REFRESH
  | Some OUTBOUND_ROUTE_FILTERING
  | Some MULTIPLE_ROUTES_DESTINATION
  | Some EXT_HEXTHOP_ENC
  | Some GRACEFUL_RESTART
  | Some AS4_SUPPORT
  | Some ENHANCED_REFRESH
  | None
    -> Ecapability buf

[%%cenum
  type oc =
    | RESERVED [@id 0]
    | AUTHENTICATION
    | CAPABILITY
  [@@uint8_t]
]

type opt_param =
  | Reserved (* wtf? *)
  | Authentication (* deprecated, rfc 4271 *)
  | Capability of capability
;;

let opt_param_to_string = function
  | Reserved -> "RESERVED"
  | Authentication -> "AUTH"
  | Capability c -> sprintf "CAP(%s)" (capability_to_string c)
;;

[%%cstruct
  type opent = {
    version: uint8_t;
    my_as: uint16_t;
    hold_time: uint16_t;
    bgp_id: uint32_t;
    opt_len: uint8_t;
  }
  [@@big_endian]
]

type opent = {
  version: int;
  my_as: asn;
  hold_time: int;
  bgp_id: int32;
  options: opt_param list;
}

let opent_to_string o =
  sprintf "version:%d, my_as:%s, hold_time:%d, bgp_id:0x%08lx, options:[%s]"
    o.version (asn_to_string o.my_as) o.hold_time o.bgp_id
    (o.options ||> opt_param_to_string |> String.concat "; ")

[%%cenum
  type attr_t =
    | ORIGIN [@id 1]
    | AS_PATH
    | NEXT_HOP
    | MED
    | LOCAL_PREF
    | ATOMIC_AGGR
    | AGGREGATOR
    | COMMUNITY
    | MP_REACH_NLRI [@id 14]
    | MP_UNREACH_NLRI
    | EXT_COMMUNITIES
    | AS4_PATH
  [@@uint8_t]
]

[%%cenum
  type origin =
    | IGP
    | EGP
    | INCOMPLETE
  [@@uint8_t]
]

[%%cstruct
  type ft = {
    flags: uint8_t;
    tc: uint8_t;
    len: uint8_t;
  }
  [@@big_endian]
]

[%%cstruct
  type fte = {
    flags: uint8_t;
    tc: uint8_t;
    len: uint16_t
  }
  [@@big_endian]
]

let is_optional f = is_bit 7 f
let is_transitive f = is_bit 6 f
let is_partial f = is_bit 5 f
let is_extlen f = is_bit 4 f

[%%cenum
  type aspt =
    | AS_SET [@id 1]
    | AS_SEQ
  [@@uint8_t]
]

[%%cstruct
  type asp = {
    t: uint8_t;
    n: uint8_t;
  }
  [@@big_endian]
]

type message_header_error =
  | Connection_not_synchroniszed
  | Bad_message_length of Cstruct.uint16
  | Bad_message_type of Cstruct.uint8
;;

type open_message_error =
  | Unspecific
  | Unsupported_version_number of Cstruct.uint16
  | Bad_peer_as 
  | Bad_bgp_identifier
  | Unsupported_optional_parameter
  | Unacceptable_hold_time
;;

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
;;

type error = 
  | Message_header_error of message_header_error
  | Open_message_error of open_message_error
  | Update_message_error of update_message_error
  | Hold_timer_expired
  | Finite_state_machine_error
  | Cease
;;

type notification_error =
  | Invalid_error_code
  | Invalid_sub_error_code

exception Parse_error of error
exception Notification_error of notification_error


type asp = Set of int32 list | Seq of int32 list
let parse_as4path buf =
  let lenf buf = Some (sizeof_asp + get_asp_n buf*4) in
  let pf buf =
    let t = get_asp_t buf in
    let buf = Cstruct.shift buf sizeof_asp in
    let vs = Cstruct.iter
        (fun buf -> Some 4)
        (fun buf -> Cstruct.BE.get_uint32 buf 0)
        buf
    in
    match int_to_aspt t with
    | None -> 
      raise (Parse_error (Update_message_error Malformed_as_path))
    | Some AS_SET -> Set (cstruct_iter_to_list vs)
    | Some AS_SEQ -> Seq (cstruct_iter_to_list vs)
  in
  cstruct_iter_to_list (Cstruct.iter lenf pf buf)

let aspath_to_string l_asp =
  let f asp acc =
    let rec asps_to_string asn_list = 
      let f v acc = sprintf "%ld <- %s" v acc in
      List.fold_right f asn_list ""
    in 
    let s = 
      match asp with 
      | Set asn_list -> sprintf "set(%s)" (asps_to_string asn_list)
      | Seq asn_list -> sprintf "seq(%s)" (asps_to_string asn_list)
    in
    sprintf "%s;%s" s acc
  in
  List.fold_right f l_asp ""
;;

let parse_aspath buf =
  let lenf buf = Some (sizeof_asp + get_asp_n buf * 2) in
  let pf buf =
    let t = get_asp_t buf in
    let buf = Cstruct.shift buf sizeof_asp in
    let vs = Cstruct.iter
        (fun buf -> Some 2)
        (fun buf -> Cstruct.BE.get_uint16 buf 0 |> Int32.of_int)
        buf
    in
    match int_to_aspt t with
    | None -> 
      raise (Parse_error (Update_message_error Malformed_as_path))
    | Some AS_SET -> Set (cstruct_iter_to_list vs)
    | Some AS_SEQ -> Seq (cstruct_iter_to_list vs)
  in
  cstruct_iter_to_list (Cstruct.iter lenf pf buf)
;;

type path_attr_flags = {
  optional: bool;
  transitive: bool;
  partial: bool;
  extlen: bool;
};;

let set_bit n pos b =
  if (n > 255) then raise (Failure "Invalid argument: n is too large.")
  else if (pos > 7) then raise (Failure "Invalid argument: pos is too large.")
  else
    let n_32 = Int32.of_int n in 
    let res_32 = 
      match b with
      | 0 -> (n_32 ^^^ (1_l <<< pos))
      | 1 -> (n_32 ||| (1_l <<< pos))
      | _ -> raise (Failure "Invalid argument: b should be either 0 or 1.")
    in
      Int32.to_int res_32
;;

let attr_flags_to_int {optional; transitive; partial; extlen} =
  let n_ref = ref 0 in
  if (optional) then n_ref := set_bit (!n_ref) 7 1;
  if (transitive) then n_ref := set_bit (!n_ref) 6 1;
  if (partial) then n_ref := set_bit (!n_ref) 5 1;
  if (extlen) then n_ref := set_bit (!n_ref) 4 1;
  !n_ref
;;

let int_to_attr_flags n = {
  optional = is_optional n;
  transitive = is_transitive n;
  partial = is_partial n;
  extlen = is_extlen n;
};;

  
type path_attr =
  | Origin of origin
  | As_path of asp list
  | Next_hop of Afi.ip4
  | Community of int32
  | Ext_communities
  | Med of int32
  | Atomic_aggr
  | Aggregator
  | Mp_reach_nlri
  | Mp_unreach_nlri
  | As4_path of asp list
;;

type path_attrs = (path_attr_flags * path_attr) list;;

let parse_path_attrs ?(caller=Normal) buf =
  let lenf buf =
    let f = get_ft_flags buf in
    Some (
      if is_extlen f then sizeof_fte + get_fte_len buf
      else sizeof_ft + get_ft_len buf
    )
  in
  let pf buf =
    let flags = int_to_attr_flags (get_ft_flags buf) in
    let hlen =
      if flags.extlen then sizeof_fte else sizeof_ft
    in
    let h, p = Cstruct.split buf hlen in
    let path_attr = match h |> get_ft_tc |> int_to_attr_t with
    | Some ORIGIN -> 
      (match Cstruct.get_uint8 p 0 |> int_to_origin with
      | Some v -> Origin v 
      | None -> 
        let b = Cstruct.shift buf 1 in
        raise (Parse_error (Update_message_error (Invalid_origin_attribute b)))
      )
    | Some AS_PATH -> (match caller with
        | Normal -> As_path (parse_aspath p)
        | Table2 | Bgp4mp_as4 -> As4_path (parse_as4path p)
      )
    | Some AS4_PATH -> As4_path (parse_as4path p)
    | Some NEXT_HOP -> Next_hop (Cstruct.BE.get_uint32 p 0)
    | Some COMMUNITY -> Community (Cstruct.BE.get_uint32 p 0)
    | Some EXT_COMMUNITIES -> Ext_communities
    | Some MED -> Med (Cstruct.BE.get_uint32 p 0)
    | Some ATOMIC_AGGR -> Atomic_aggr
    | Some AGGREGATOR -> Aggregator
    | Some MP_REACH_NLRI -> Mp_reach_nlri
    | Some MP_UNREACH_NLRI -> Mp_unreach_nlri
    | Some LOCAL_PREF
    | None ->
      printf "U %d %d\n%!" (get_ft_tc h) (Cstruct.len p);
      Cstruct.hexdump p; failwith "unknown path attr"
    in (flags, path_attr)
  in
  cstruct_iter_to_list (Cstruct.iter lenf pf buf)
;;

type update = {
  withdrawn: Afi.prefix list;
  path_attrs: path_attrs;
  nlri: Afi.prefix list;
};;

let rec path_attrs_to_string path_attrs = 
  let f (_, path_attr) acc =
    match path_attr with 
    | Origin v ->
      sprintf "ORIGIN(%s); %s" (origin_to_string v) acc
    | As_path v ->
      sprintf "AS_PATH(%s); %s"
        (aspath_to_string v) acc
    | As4_path v ->
      sprintf "AS4_PATH(%s); %s"
        (aspath_to_string v) acc
    | Next_hop v ->
      sprintf "NEXT_HOP(%s); %s"
        (Afi.ip4_to_string v) acc
    | Community v ->
      sprintf "COMMUNITY(%ld:%ld); %s"
        (v >>> 16 &&& 0xffff_l) (v &&& 0xffff_l) acc
    | Ext_communities -> "EXT_COMMUNITIES; " ^ acc
    | Med v -> sprintf "MED(%ld); %s" v acc
    | Atomic_aggr -> "ATOMIC_AGGR; " ^ acc
    | Aggregator -> "AGGREGATOR; " ^ acc
    | Mp_reach_nlri -> "MP_REACH_NLRI; " ^ acc
    | Mp_unreach_nlri -> "MP_UNREACH_NLRI; " ^ acc
  in
  List.fold_right f path_attrs ""
;;

(* let rec nlris_to_string iter = match iter () with
  | None -> ""
  | Some p -> (Afi.prefix_to_string p) ^ "; " ^ (nlris_to_string iter) *)

let rec nlris_to_string l_pfx = 
  let f pfx acc =
    (Afi.prefix_to_string pfx) ^ "; " ^ acc
  in
  List.fold_right f l_pfx ""
;;


let update_to_string u =
  sprintf "withdrawn:[%s], path_attrs:[%s], nlri:[%s]"
    (nlris_to_string u.withdrawn)
    (path_attrs_to_string u.path_attrs)
    (nlris_to_string u.nlri)
;;

[%%cenum
  type message_header_error_t =
    | CONNECTION_NOT_SYNCHRONIZED [@id 1]
    | BAD_MESSAGE_LENGTH
    | BAD_MESSAGE_TYPE
  [@@uint8_t]
]

[%%cenum
  type open_message_error_t =
    | UNSPECIFIC [@id 0]
    | UNSUPPORTED_VERSION_NUMBER
    | BAD_PEER_AS 
    | BAD_BGP_IDENTIFIER
    | UNSUPPORTED_OPTIONAL_PARAMETER
    | UNACCEPTABLE_HOLD_TIME
  [@@uint8_t]
]

[%%cenum
  type update_message_error_t =
    | MALFORMED_ATTRIBUTE_LIST [@id 1]
    | UNRECOGNIZED_WELLKNOWN_ATTRIBUTE
    | MISSING_WELLKNOWN_ATTRIBUTE
    | ATTRIBUTE_FLAGS_ERROR
    | ATTRIBUTE_LENGTH_ERROR
    | INVALID_ORIGIN_ATTRIBUTE
    | INVALID_NEXT_HOP_ATTRIBUTE [@id 8]
    | OPTIONAL_ATTRIBUTE_ERROR
    | INVALID_NETWORK_FIELD
    | MALFORMED_AS_PATH
  [@@uint8_t]
]

[%%cenum
  type error_t =
    | MESSAGE_HEADER_ERROR [@id 1]
    | OPEN_MESSAGE_ERROR
    | UPDATE_MESSAGE_ERROR
    | HOLD_TIMER_EXPIRED
    | FINITE_STATE_MACHINE_ERROR
    | CEASE
  [@@uint8_t]
]

[%%cstruct
  type err = {
    ec: uint8_t;
    sec: uint8_t;
  }
  [@@big_endian]
]

let parse_error p =
  match get_err_ec p |> int_to_error_t with
  | Some MESSAGE_HEADER_ERROR -> 
    let suberror = match get_err_sec p |> int_to_message_header_error_t with
    | Some CONNECTION_NOT_SYNCHRONIZED -> Connection_not_synchroniszed
    | Some BAD_MESSAGE_LENGTH -> 
      let bad_len = Cstruct.BE.get_uint16 p 2 in
      Bad_message_length bad_len
    | Some BAD_MESSAGE_TYPE ->
      let bad_type = Cstruct.get_uint8 p 2 in
      Bad_message_type bad_type
    | None -> raise (Notification_error Invalid_sub_error_code)
    in Message_header_error suberror
  | Some OPEN_MESSAGE_ERROR ->
    let suberror = match get_err_sec p |> int_to_open_message_error_t with
    | Some UNSPECIFIC -> Unspecific
    | Some UNSUPPORTED_VERSION_NUMBER ->
      let vn = Cstruct.BE.get_uint16 p 2 in
      Unsupported_version_number vn
    | Some BAD_PEER_AS ->
      Bad_peer_as
    | Some BAD_BGP_IDENTIFIER ->
      Bad_bgp_identifier
    | Some UNSUPPORTED_OPTIONAL_PARAMETER ->
      Unsupported_optional_parameter
    | Some UNACCEPTABLE_HOLD_TIME ->
      Unacceptable_hold_time
    | None -> raise (Notification_error Invalid_sub_error_code)
    in Open_message_error suberror
  | Some UPDATE_MESSAGE_ERROR ->
    let suberror = match get_err_sec p |> int_to_update_message_error_t with
    | Some MALFORMED_ATTRIBUTE_LIST -> Malformed_attribute_list
    | Some UNRECOGNIZED_WELLKNOWN_ATTRIBUTE ->
      let attr = Cstruct.shift p 2 in
      Unrecognized_wellknown_attribute attr
    | Some MISSING_WELLKNOWN_ATTRIBUTE -> 
      let attr = Cstruct.get_uint8 p 2 in
      Missing_wellknown_attribute attr
    | Some ATTRIBUTE_FLAGS_ERROR -> 
      let attr = Cstruct.shift p 2 in
      Attribute_flags_error attr
    | Some ATTRIBUTE_LENGTH_ERROR ->
      let attr = Cstruct.shift p 2 in
      Attribute_length_error attr
    | Some INVALID_ORIGIN_ATTRIBUTE ->
      let attr = Cstruct.shift p 2 in
      Invalid_origin_attribute attr
    | Some INVALID_NEXT_HOP_ATTRIBUTE ->
      let attr = Cstruct.shift p 2 in
      Invalid_next_hop_attribute attr
    | Some OPTIONAL_ATTRIBUTE_ERROR ->
      let attr = Cstruct.shift p 2 in
      Optional_attribute_error attr
    | Some INVALID_NETWORK_FIELD ->
      Invalid_network_field
    | Some MALFORMED_AS_PATH ->
      Malformed_as_path
    | None -> raise (Notification_error Invalid_sub_error_code)
    in Update_message_error suberror
  | Some HOLD_TIMER_EXPIRED ->
    Hold_timer_expired
  | Some FINITE_STATE_MACHINE_ERROR ->
    Finite_state_machine_error
  | Some CEASE ->
    Cease
  | None -> raise (Notification_error Invalid_error_code)
;;

let error_to_string err =
  match err with
  | Message_header_error sub ->
    let error = "Message header error" in
    let suberror = (match sub with 
    | Connection_not_synchroniszed ->
      "Connection not synchronized"
    | Bad_message_length bad_len ->
      "Bad message length"
    | Bad_message_type bad_type ->
      "Bad message type"
    ) in sprintf "%s : %s" error suberror
  | Open_message_error sub ->
    let error = "Open message error" in
    let suberror = (match sub with
    | Unspecific -> "Unspecific"
    | Unsupported_version_number vn ->
      "Unsupported version number"
    | Bad_peer_as -> 
      "Bad peer as"
    | Bad_bgp_identifier ->
      "Bad bgp identifier"
    | Unsupported_optional_parameter ->
      "Unsupported optional parameter"
    | Unacceptable_hold_time ->
      "Unacceptable hold time"
    ) in sprintf "%s : %s" error suberror
  | Update_message_error sub ->
    let error = "Update message error" in
    let suberror = (match sub with
    | Malformed_attribute_list ->
      "Malformed attribute list"
    | Unrecognized_wellknown_attribute buf_attr ->
      "Unrecognized wellknown attribute"
    | Missing_wellknown_attribute attr ->
      "Missing wellknown attribute"
    | Attribute_flags_error buf_attr ->
      "Attribute flags error"
    | Attribute_length_error buf_attr ->
      "Attribute length error"
    | Invalid_origin_attribute buf_attr ->
      "Invalid origin attribute"
    | Invalid_next_hop_attribute buf_attr ->
      "Invalid next hop attribute"
    | Optional_attribute_error buf_attr ->
      "Optioanl attribute error"
    | Invalid_network_field ->
      "Invalid network field"
    | Malformed_as_path ->
      "Malformed as path"
    ) in sprintf "%s : %s" error suberror
  | Hold_timer_expired ->
    "Hold timer expired"
  | Finite_state_machine_error ->
    "Finite state machine error"
  | Cease ->
    "Cease"
;;

type t =
  | Open of opent
  | Update of update
  | Notification of error
  | Keepalive
;;

let to_string = function
  | Open o -> sprintf "OPEN(%s)" (opent_to_string o)
  | Update u -> sprintf "UPDATE(%s)" (update_to_string u)
  | Notification e -> sprintf "NOTIFICATION(%s)" (error_to_string e)
  | Keepalive -> "KEEPALIVE"
;;

let parse ?(caller=Normal) buf =
  let lenf buf = Some (get_h_len buf) in
  let pf buf =
    let hlen = sizeof_h in
    let h, p = Cstruct.split buf hlen in
    match get_h_typ h |> int_to_tc with
    | None -> 
      raise (Parse_error (Message_header_error (Bad_message_type (get_h_typ h))))
    | Some OPEN ->
      let m,opts = Cstruct.split p (Cstruct.len p - get_opent_opt_len p) in
      let opts =
        let rec aux acc bs =
          if Cstruct.len bs = 0 then acc else (
            let t, opt, bs = Tlv.get_tlv bs in
            let opt = match int_to_oc t with
              | None -> failwith "bad option"
              | Some RESERVED -> Reserved
              | Some AUTHENTICATION -> Authentication
              | Some CAPABILITY ->
                let t,c, _ = Tlv.get_tlv bs in
                Capability (parse_capability c (int_to_cc t))
            in aux (opt :: acc) bs
          )
        in aux [] opts
      in
      Open { version = get_opent_version m;
             my_as = Asn (get_opent_my_as m);
             hold_time = get_opent_hold_time m;
             bgp_id = get_opent_bgp_id m;
             options = opts;
           }
    | Some UPDATE ->
      let withdrawn, bs =
        let wl = Cstruct.BE.get_uint16 p 0 in
        Cstruct.split ~start:2 p wl
      in
      let path_attrs, nlri =
        let pl = Cstruct.BE.get_uint16 bs 0 in
        Cstruct.split ~start:2 bs pl
      in
      Update {
        withdrawn = parse_nlris withdrawn;
        path_attrs = parse_path_attrs ~caller path_attrs;
        nlri = parse_nlris nlri;
      }
    | Some NOTIFICATION -> 
      let error = parse_error p in
      Notification error
    | Some KEEPALIVE -> Keepalive
  in
  Cstruct.iter lenf pf buf
;;

let parse_buffer_to_t buf =
  match parse buf () with
  | None -> None
  | Some it -> Some it
;;


let fill_header_buffer buf len typ = 
  let marker, _ = Cstruct.split buf 16 in
  Cstruct.memset marker 0x00ff; 
  set_h_len buf len;
  set_h_typ buf (tc_to_int typ);
  sizeof_h
;;


let fill_open_buffer buf (o: opent) =
  let buf_h, buf_p = Cstruct.split buf sizeof_h in
  let buf_opent, buf_opt = Cstruct.split buf_p sizeof_opent in
  let _  = fill_header_buffer buf_h (sizeof_h + sizeof_opent) OPEN in
  set_opent_version buf_opent o.version;
  set_opent_my_as buf_opent (asn_to_int o.my_as);
  set_opent_hold_time buf_opent o.hold_time;
  set_opent_bgp_id buf_opent o.bgp_id;
  set_opent_opt_len buf_opent 0;
  sizeof_h + sizeof_opent
;;
  
  
(* TODO: Add optional parameter support *)
let gen_open (o: opent) =
  let buf = Cstruct.create 4096 in
  let len = fill_open_buffer buf o in
  let ret, _ = Cstruct.split buf len in
  ret
;;
  
let gen_keepalive =
  let buf = Cstruct.create 19 in
  let _ = fill_header_buffer buf 19 KEEPALIVE in
  buf
;;
  
let len_pfxs_buffer pfxs =
  let f (_, mask) = 
    let num_b = pfxlen_to_bytes mask in
    num_b + 1
  in 
    List.fold_left (+) 0 (List.map f pfxs)
;;

let fill_pfxs_buffer buf pfxs =
  let f total_len (ip, mask) =
    let num_b = pfxlen_to_bytes mask in
    let _, buf_this = Cstruct.split buf total_len in
    Cstruct.set_uint8 buf_this 0 mask;
    (match ip with
    | Afi.IPv4 ip4 ->
      for i = 1 to num_b do
        Cstruct.set_uint8 buf_this i (Int32.to_int (ip4 >>> (32 - i * 8) &&& 0x00ff_l))
      done
    | Afi.IPv6 (hi, lo) ->
      if (num_b <= 8) then 
        for i = 1 to num_b do
          Cstruct.set_uint8 buf_this i (Int64.to_int (hi >>>> (64 - i * 8) &&&& 0x00ff_L))
        done
      else
        for i = 1 to 8 do
          Cstruct.set_uint8 buf_this i (Int64.to_int (hi >>>> (64 - i * 8) &&&& 0x00ff_L))
        done;
        for i = 9 to num_b do
          Cstruct.set_uint8 buf_this i (Int64.to_int (lo >>>> (128 - i * 8) &&&& 0x00ff_L))
        done);
    total_len + num_b + 1
  in
  (* return remaining buffer *)
  List.fold_left f 0 pfxs
;;

let len_attr_ft_buffer = sizeof_ft;;

let fill_attr_ft_buffer buf flags tc len =
  set_ft_flags buf (attr_flags_to_int flags);
  set_ft_tc buf (attr_t_to_int tc);
  set_ft_len buf len;
  sizeof_ft

let gen_attr_ft_buffer flags tc len =
  let buf = Cstruct.create 4096 in
  let len = fill_attr_ft_buffer buf flags tc len in
  let ret, _ = Cstruct.split buf len in
  ret

let fill_attr_fte_buffer buf flags tc len =
  set_fte_flags buf (attr_flags_to_int flags);
  set_fte_tc buf (attr_t_to_int tc);
  set_fte_len buf len;
  sizeof_fte

let fill_attr_as_path_data_buffer buf asp =
  let f total_len set_or_seq = 
    let st, l = match set_or_seq with Set v -> (1, v) | Seq v -> (2, v) in
    let _, buf_this = Cstruct.split buf total_len in
    let l_len = List.length l in
    Cstruct.set_uint8 buf_this 0 st;
    Cstruct.set_uint8 buf_this 1 l_len;

    let i = ref 0 in
    let rec loop l =
      match l with
      | [] -> ()
      | x::xs -> Cstruct.BE.set_uint16 buf_this (2 + (!i) * 2) (Int32.to_int x); i := !i + 1; loop xs
    in
    loop l;
    total_len + (l_len + 1) * 2
  in
  List.fold_left f 0 asp

let gen_attr_as_path_data_buffer asp =
  let buf = Cstruct.create 4096 in
  let len = fill_attr_as_path_data_buffer buf asp in
  let ret, _ = Cstruct.split buf len in ret

let fill_path_attrs_buffer buf path_attrs =
  let f total_len (flags, path_attr) =
    let _, buf_slice = Cstruct.split buf total_len in
    match path_attr with
    | Origin origin -> 
      let len_ft = 
        if flags.transitive then fill_attr_fte_buffer buf_slice flags ORIGIN 1
        else fill_attr_ft_buffer buf_slice flags ORIGIN 1
      in
      Cstruct.set_uint8 buf_slice len_ft (origin_to_int origin);
      total_len + len_ft + 1
    | As_path asp ->
      let buf_ft, buf_p = Cstruct.split buf_slice sizeof_ft in
      let len_p = fill_attr_as_path_data_buffer buf_p asp in
      let len_ft = 
        if flags.transitive then 
          fill_attr_fte_buffer buf_slice flags AS4_PATH len_p
        else fill_attr_ft_buffer buf_slice flags AS_PATH len_p
      in
      total_len + len_ft + len_p
    | Next_hop ip4 -> 
      let buf_ft, buf_p = Cstruct.split buf_slice sizeof_ft in
      let len_ft = 
        if flags.transitive then fill_attr_fte_buffer buf_slice flags NEXT_HOP 4
        else fill_attr_ft_buffer buf_slice flags NEXT_HOP 4
      in
      Cstruct.BE.set_uint32 buf_p 0 ip4;
      total_len + len_ft + 4
    | _ -> total_len
  in
  List.fold_left f 0 path_attrs
;;

let fill_update_buffer buf { withdrawn; path_attrs; nlri } = 
  let buf_h, buf_p = Cstruct.split buf sizeof_h in
  let buf_len_wd, buf_wd_rest = Cstruct.split buf_p 2 in 
  let len_wd = fill_pfxs_buffer buf_wd_rest withdrawn in
  let buf_rest = Cstruct.shift buf_wd_rest len_wd in
  let buf_len_pa, buf_pa_rest = Cstruct.split buf_rest 2 in
  let len_pa = fill_path_attrs_buffer buf_pa_rest path_attrs in
  let buf_nlri = Cstruct.shift buf_pa_rest len_pa in
  let len_nlri = fill_pfxs_buffer buf_nlri nlri in
  Cstruct.BE.set_uint16 buf_len_wd 0 len_wd;
  Cstruct.BE.set_uint16 buf_len_pa 0 len_pa;
  let _ = fill_header_buffer buf_h (sizeof_h + len_wd + len_pa + len_nlri + 4) UPDATE in
  sizeof_h + len_wd + len_pa + len_nlri + 4
;;

let gen_update u =
  let buf = Cstruct.create 4096 in
  let len = fill_update_buffer buf u in
  let ret, _ = Cstruct.split buf len in ret
;;
  
let fill_notification_buffer buf e =
  let buf_h, buf_p = Cstruct.split buf sizeof_h in
  let len_p = match e with
  | Message_header_error sub ->
    set_err_ec buf_p (error_t_to_int MESSAGE_HEADER_ERROR);
    (match sub with 
    | Connection_not_synchroniszed ->
      set_err_sec buf_p (message_header_error_t_to_int CONNECTION_NOT_SYNCHRONIZED);
      sizeof_err
    | Bad_message_length bad_len ->
      set_err_sec buf_p (message_header_error_t_to_int BAD_MESSAGE_LENGTH);
      Cstruct.BE.set_uint16 buf_p 2 bad_len;
      sizeof_err + 2
    | Bad_message_type bad_type ->
      set_err_sec buf_p (message_header_error_t_to_int BAD_MESSAGE_TYPE);
      Cstruct.set_uint8 buf_p 2 bad_type;
      sizeof_err + 1
    )
  | Open_message_error sub ->
    set_err_ec buf_p (error_t_to_int OPEN_MESSAGE_ERROR);
    (match sub with
    | Unspecific -> sizeof_err
    | Unsupported_version_number vn ->
      Cstruct.BE.set_uint16 buf_p 2 vn;
      sizeof_err + 2
    | Bad_peer_as -> 
      set_err_sec buf_p (open_message_error_t_to_int BAD_PEER_AS);
      sizeof_err
    | Bad_bgp_identifier ->
      set_err_sec buf_p (open_message_error_t_to_int BAD_BGP_IDENTIFIER);
      sizeof_err
    | Unsupported_optional_parameter ->
      set_err_sec buf_p (open_message_error_t_to_int UNSUPPORTED_OPTIONAL_PARAMETER);
      sizeof_err
    | Unacceptable_hold_time ->
      set_err_sec buf_p (open_message_error_t_to_int UNACCEPTABLE_HOLD_TIME);
      sizeof_err
    )
  | Update_message_error sub ->
    set_err_ec buf_p (error_t_to_int UPDATE_MESSAGE_ERROR);
    let fill buf_p err buf_d =
      set_err_sec buf_p (update_message_error_t_to_int err);
      let buf_rest = Cstruct.shift buf_p sizeof_err in
      let n, _ = Cstruct.fillv [buf_d] buf_rest in
      sizeof_err + n
    in (match sub with
    | Malformed_attribute_list ->
      set_err_sec buf_p (update_message_error_t_to_int MALFORMED_ATTRIBUTE_LIST);
      sizeof_err
    | Unrecognized_wellknown_attribute buf_attr ->
      fill buf_p UNRECOGNIZED_WELLKNOWN_ATTRIBUTE buf_attr
    | Missing_wellknown_attribute attr ->
      set_err_sec buf_p (update_message_error_t_to_int MISSING_WELLKNOWN_ATTRIBUTE);
      Cstruct.set_uint8 buf_p 2 attr;
      sizeof_err + 1
    | Attribute_flags_error buf_attr ->
      fill buf_p ATTRIBUTE_FLAGS_ERROR buf_attr
    | Attribute_length_error buf_attr ->
      fill buf_p ATTRIBUTE_LENGTH_ERROR buf_attr
    | Invalid_origin_attribute buf_attr ->
      fill buf_p INVALID_ORIGIN_ATTRIBUTE buf_attr
    | Invalid_next_hop_attribute buf_attr ->
      fill buf_p INVALID_NEXT_HOP_ATTRIBUTE buf_attr
    | Optional_attribute_error buf_attr ->
      fill buf_p OPTIONAL_ATTRIBUTE_ERROR buf_attr
    | Invalid_network_field ->
      set_err_sec buf_p (update_message_error_t_to_int INVALID_NETWORK_FIELD);
      sizeof_err
    | Malformed_as_path ->
      set_err_sec buf_p (update_message_error_t_to_int MALFORMED_AS_PATH);
      sizeof_err
    )
  | Hold_timer_expired ->
    set_err_ec buf_p (error_t_to_int HOLD_TIMER_EXPIRED);
    sizeof_err
  | Finite_state_machine_error ->
    set_err_ec buf_p (error_t_to_int FINITE_STATE_MACHINE_ERROR);
    sizeof_err
  | Cease ->
    set_err_ec buf_p (error_t_to_int CEASE);
    sizeof_err
  in
  let _ = fill_header_buffer buf_h (sizeof_h + len_p) NOTIFICATION in
  sizeof_h + len_p
;;

let gen_notification e =
  let buf = Cstruct.create 4096 in
  let len = fill_notification_buffer buf e in
  let ret, _ = Cstruct.split buf len in
  ret
;;

let gen_msg = function
  | Open o -> gen_open o
  | Update u -> gen_update u
  | Keepalive -> gen_keepalive
  | Notification e -> gen_notification e
;;

