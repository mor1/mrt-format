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
include Bgp_cstruct

(* Lame, lame, lame. RFC6396, sec. 4.3.4 says that AS_PATHs MUST be encoded as
   4 bytes in a TABLE_DUMP_V2 RIB_ENTRY, no matter what. Similarly in BGP4MP
   MESSAGE_AS4 and LOCAL_AS4 message types (4.4.3 and 4.4.6). The first
   section (4.3.4) then says, in the same section, that MP_REACH_NLRI
   attributes contain only the nexthop address length and address, not the
   AFI, SAFI and NLRI fields as these are encoded in the RIB entry header.

   We hack around this via the `caller` parameter, typed appropriately; and by
   forcing aspath to always contain `int32`.

   MRT remains IMO, in random ways, a half-witted format. *)

let parser_log = Logs.Src.create "Parser" ~doc:"Log for parser"
module Parser_log = (val Logs.src_log parser_log : Logs.LOG)

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
;;

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
;;

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
;;

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
;;




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

type opt_param =
  | Reserved (* wtf? *)
  | Authentication (* deprecated, rfc 4271 *)
  | Capability of capability


let opt_param_to_string = function
  | Reserved -> "RESERVED"
  | Authentication -> "AUTH"
  | Capability c -> sprintf "CAP(%s)" (capability_to_string c)
;;

type opent = {
  version: int;
  local_asn: int32;
  hold_time: int;
  local_id: Ipaddr.V4.t;
  options: opt_param list;
}

let opent_to_string o =
  sprintf "version:%d, my_as:%s, hold_time:%d, bgp_id:%s, options:[%s]"
          o.version (Int32.to_string o.local_asn) o.hold_time 
          (Ipaddr.V4.to_string o.local_id)
          (o.options ||> opt_param_to_string |> String.concat "; ")
;;

let is_optional f = is_bit 7 f
let is_transitive f = is_bit 6 f
let is_partial f = is_bit 5 f
let is_extlen f = is_bit 4 f


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


type error = 
  | Message_header_error of message_header_error
  | Open_message_error of open_message_error
  | Update_message_error of update_message_error
  | Hold_timer_expired
  | Finite_state_machine_error
  | Cease

type msg_fmt_error = 
  | Parse_msg_h_err of message_header_error
  | Parse_open_msg_err of open_message_error
  | Parse_update_msg_err of update_message_error 

type notif_fmt_error =
  | Invalid_error_code
  | Invalid_sub_error_code
  | Bad_message_length_n
  | Connection_not_synchroniszed_n

type parse_error =
  | Parsing_error
  | Msg_fmt_error of msg_fmt_error
  | Notif_fmt_error of notif_fmt_error

exception Msg_fmt_err of msg_fmt_error
exception Notif_fmt_err of notif_fmt_error

type asp_segment = 
  | Asn_set of int32 list 
  | Asn_seq of int32 list

let parse_nlris buf =
  let lenf buf = Some (1 + (pfxlen_to_bytes (Cstruct.get_uint8 buf 0))) in
  
  let get_nlri4 buf off =
    Cstruct.(
      let v = ref 0l in
      let mask = get_uint8 buf off in
      let bytes = pfxlen_to_bytes mask in
      if bytes > len buf then 
        raise (Msg_fmt_err (Parse_update_msg_err Invalid_network_field))
      else begin
        for i = 0 to bytes-1 do
          v := (!v <<< 8) +++ (Int32.of_int (get_uint8 buf (off+i+1)))
        done;
        Ipaddr.V4.Prefix.make mask (Ipaddr.V4.of_int32 (!v <<< (8 * (4 - bytes))))
      end
    )
  in

  let pf buf =
    (* This could be a bug. What if the mask of ip6 address is less than 32? *)
    if pfxlen_to_bytes (Cstruct.get_uint8 buf 0) <= 4 then 
      get_nlri4 buf 0
    else
      (* Currently, I don't want to support IPv6. *)
      raise (Msg_fmt_err (Parse_update_msg_err Invalid_network_field))
  in
  cstruct_iter_to_list (Cstruct.iter lenf pf buf)
;;

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
      raise (Msg_fmt_err (Parse_update_msg_err Malformed_as_path))
    | Some AS_SET -> Asn_set (cstruct_iter_to_list vs)
    | Some AS_SEQ -> Asn_seq (cstruct_iter_to_list vs)
  in
  cstruct_iter_to_list (Cstruct.iter lenf pf buf)

let asp_segments_to_string asp_segments =
  let f segment acc =
    let rec seq_to_string asn_list = 
      let f v acc = sprintf "%ld <- %s" v acc in
      List.fold_right f asn_list ""
    in 
    let rec set_to_string asn_list =
      let f v acc = sprintf "%ld, %s" v acc in
      List.fold_right f asn_list ""
    in
    let s = 
      match segment with 
      | Asn_set asn_list -> sprintf "[%s])" (set_to_string asn_list)
      | Asn_seq asn_list -> sprintf "%s" (seq_to_string asn_list)
    in
    sprintf "%s <- %s" s acc
  in
  List.fold_right f asp_segments ""
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
      raise (Msg_fmt_err (Parse_update_msg_err Malformed_as_path))
    | Some AS_SET -> Asn_set (cstruct_iter_to_list vs)
    | Some AS_SEQ -> Asn_seq (cstruct_iter_to_list vs)
  in
  cstruct_iter_to_list (Cstruct.iter lenf pf buf)
;;

type path_attr_flags = {
  optional: bool;
  transitive: bool;
  partial: bool;
  extlen: bool;
}

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
}

  
type path_attr =
  | Origin of origin
  | As_path of asp_segment list
  | Next_hop of Ipaddr.V4.t
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

type path_attrs = (path_attr_flags * path_attr) list;;

let rec path_attrs_to_string path_attrs = 
  let f (_, path_attr) acc =
    match path_attr with 
    | Origin v ->
      sprintf "ORIGIN(%s); %s" (origin_to_string v) acc
    | As_path v ->
      sprintf "AS_PATH(%s); %s"
        (asp_segments_to_string v) acc
    | As4_path v ->
      sprintf "AS4_PATH(%s); %s"
        (asp_segments_to_string v) acc
    | Next_hop v ->
      sprintf "NEXT_HOP(%s); %s"
        (Ipaddr.V4.to_string v) acc
    | Community v ->
      sprintf "COMMUNITY(%ld:%ld); %s"
        (v >>> 16 &&& 0xffff_l) (v &&& 0xffff_l) acc
    | Ext_communities -> "EXT_COMMUNITIES; " ^ acc
    | Med v -> sprintf "MED(%ld); %s" v acc
    | Atomic_aggr -> "ATOMIC_AGGR; " ^ acc
    | Aggregator -> "AGGREGATOR; " ^ acc
    | Mp_reach_nlri -> "MP_REACH_NLRI; " ^ acc
    | Mp_unreach_nlri -> "MP_UNREACH_NLRI; " ^ acc
    | Local_pref p -> (sprintf "LOCAL_PREF %d" p) ^ acc
    | Unknown tc -> sprintf "Unknown attribute with tc %d" tc
  in
  List.fold_right f path_attrs ""
;;

let is_valid_ip_addrs addr = 
  let invalid_list = [
    Ipaddr.V4.of_string_exn "0.0.0.0";
    Ipaddr.V4.of_string_exn "255.255.255.255";
  ] in
  not (List.mem addr invalid_list)
;;

 let find_origin path_attrs =
  let rec loop = function
    | [] -> None
    | hd::tl -> match hd with
      | (_, Origin v) -> Some v
      | _ -> loop tl
  in
  loop path_attrs
;;
    
let find_aspath path_attrs =
  let rec loop = function
    | [] -> None
    | hd::tl -> match hd with
      | (_, As_path v) -> Some v 
      | _ -> loop tl
  in
  loop path_attrs
;;

let find_next_hop path_attrs =
  let rec loop = function
    | [] -> None
    | hd::tl -> match hd with
      | (_, Next_hop v) -> Some v 
      | _ -> loop tl
  in
  loop path_attrs
;;

let path_attr_to_attr_t = function
  | Origin _ -> ORIGIN
  | As_path _ -> AS_PATH
  | Next_hop _ -> NEXT_HOP
  | Community _ -> COMMUNITY
  | Ext_communities -> EXT_COMMUNITIES
  | Med _ -> MED
  | Atomic_aggr -> ATOMIC_AGGR
  | Aggregator -> AGGREGATOR
  | Mp_reach_nlri -> MP_REACH_NLRI
  | Mp_unreach_nlri -> MP_UNREACH_NLRI
  | As4_path _ -> AS4_PATH
  | Local_pref _ -> LOCAL_PREF
  | Unknown _ -> UNKNOWN
;;

let path_attrs_mem attr_t path_attrs = 
  let f (_, pa) = path_attr_to_attr_t pa = attr_t in
  List.exists f path_attrs
;;

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

    let hlen = if flags.extlen then sizeof_fte else sizeof_ft in
    let h, p = Cstruct.split buf hlen in

    let pa_len = if flags.extlen then get_fte_len h else get_ft_len h in

    let path_attr = match h |> get_ft_tc |> int_to_attr_t with
    | Some ORIGIN -> begin
      if flags.optional = true then 
        let b = Cstruct.shift buf 1 in
        raise (Msg_fmt_err (Parse_update_msg_err (Attribute_flags_error b)))
      else if pa_len != 1 then
        let b = Cstruct.shift buf 1 in
        raise (Msg_fmt_err (Parse_update_msg_err (Attribute_length_error b)))
      else 
        match Cstruct.get_uint8 p 0 |> int_to_origin with
        | Some v -> Origin v 
        | None -> 
          let b = Cstruct.shift buf 1 in
          raise (Msg_fmt_err (Parse_update_msg_err (Invalid_origin_attribute b)))
    end
    | Some AS_PATH -> begin
      if flags.optional = true then 
        let b = Cstruct.shift buf 1 in
        raise (Msg_fmt_err (Parse_update_msg_err (Attribute_flags_error b)))
      else
        match caller with
        | Normal -> As_path (parse_aspath p)
        | Table2 | Bgp4mp_as4 -> As4_path (parse_as4path p)
    end
    | Some AS4_PATH -> As4_path (parse_as4path p)
    | Some NEXT_HOP -> 
      if flags.optional = true then 
        let b = Cstruct.shift buf 1 in
        raise (Msg_fmt_err (Parse_update_msg_err (Attribute_flags_error b)))
      else if pa_len != 4 then
        let b = Cstruct.shift buf 1 in
        raise (Msg_fmt_err (Parse_update_msg_err (Attribute_length_error b)))
      else 
        let addr = Ipaddr.V4.of_int32 (Cstruct.BE.get_uint32 p 0) in 
        if is_valid_ip_addrs addr then Next_hop addr 
        else 
          let b = Cstruct.shift buf 1 in
          raise (Msg_fmt_err (Parse_update_msg_err (Invalid_next_hop_attribute b)))
    | Some COMMUNITY -> Community (Cstruct.BE.get_uint32 p 0)
    | Some EXT_COMMUNITIES -> Ext_communities
    | Some MED -> 
      if flags.optional = false then 
        let b = Cstruct.shift buf 1 in
        raise (Msg_fmt_err (Parse_update_msg_err (Attribute_flags_error b)))
      else
        Med (Cstruct.BE.get_uint32 p 0)
    | Some ATOMIC_AGGR -> 
      if flags.optional = false then 
        let b = Cstruct.shift buf 1 in
        raise (Msg_fmt_err (Parse_update_msg_err (Attribute_flags_error b)))
      else Atomic_aggr
    | Some AGGREGATOR -> 
      if flags.optional = false then 
        let b = Cstruct.shift buf 1 in
        raise (Msg_fmt_err (Parse_update_msg_err (Attribute_flags_error b)))
      else Aggregator
    | Some MP_REACH_NLRI -> Mp_reach_nlri
    | Some MP_UNREACH_NLRI -> Mp_unreach_nlri
    | Some LOCAL_PREF -> 
      if flags.optional = false then 
        let b = Cstruct.shift buf 1 in
        raise (Msg_fmt_err (Parse_update_msg_err (Attribute_flags_error b)))
      else Local_pref 0
    | Some UNKNOWN -> Unknown 0
    | None -> Unknown (get_ft_tc h)
    in (flags, path_attr)
  in

  let rec loop iter acc =
    match iter () with
    | None -> acc
    | Some ((_, pa) as v) ->
      let typ = path_attr_to_attr_t pa in
      if path_attrs_mem typ acc then 
        raise (Msg_fmt_err (Parse_update_msg_err Malformed_attribute_list))
      else loop iter (v::acc)
  in

  let path_attrs = loop (Cstruct.iter lenf pf buf) [] in

  if not (path_attrs_mem ORIGIN path_attrs) then
    let tc = attr_t_to_int ORIGIN in
    raise (Msg_fmt_err (Parse_update_msg_err (Missing_wellknown_attribute tc)))
  else if not (path_attrs_mem AS_PATH path_attrs) then
    let tc = attr_t_to_int AS_PATH in
    raise (Msg_fmt_err (Parse_update_msg_err (Missing_wellknown_attribute tc)))
  else if not (path_attrs_mem NEXT_HOP path_attrs) then
    let tc = attr_t_to_int NEXT_HOP in
    raise (Msg_fmt_err (Parse_update_msg_err (Missing_wellknown_attribute tc)))
  else 
    (* This is a temporary workaround for ease of testing *)
    List.rev path_attrs
;;

type update = {
  withdrawn: Ipaddr.V4.Prefix.t list;
  path_attrs: path_attrs;
  nlri: Ipaddr.V4.Prefix.t list;
}


let rec nlris_to_string l_pfx = 
  let f pfx acc = (Ipaddr.V4.Prefix.to_string pfx) ^ "; " ^ acc in
  List.fold_right f l_pfx ""
;;

let update_to_string u =
  sprintf "withdrawn:[%s], path_attrs:[%s], nlri:[%s]"
    (nlris_to_string u.withdrawn)
    (path_attrs_to_string u.path_attrs)
    (nlris_to_string u.nlri)
;;

let parse_notif p =
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
    | None -> raise (Notif_fmt_err Invalid_sub_error_code)
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
    | None -> raise (Notif_fmt_err Invalid_sub_error_code)
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
    | None -> raise (Notif_fmt_err Invalid_sub_error_code)
    in Update_message_error suberror
  | Some HOLD_TIMER_EXPIRED ->
    Hold_timer_expired
  | Some FINITE_STATE_MACHINE_ERROR ->
    Finite_state_machine_error
  | Some CEASE -> Cease
  | None -> 
    raise (Notif_fmt_err Invalid_error_code)
;;


let msg_h_err_to_string = function
  | Connection_not_synchroniszed ->
    "Connection not synchronized"
  | Bad_message_length bad_len ->
    "Bad message length"
  | Bad_message_type bad_type ->
    "Bad message type"
;;

let open_msg_err_to_string = function
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
;;

let update_msg_err_to_string = function
  | Malformed_attribute_list ->
    "Malformed attribute list"
  | Unrecognized_wellknown_attribute buf_attr ->
    "Unrecognized wellknown attribute"
  | Missing_wellknown_attribute attr ->
    sprintf "Missing wellknown attribute %d" attr
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
;;

let error_to_string err =
  match err with
  | Message_header_error sub ->
    let error = "Message header error" in
    let suberror = msg_h_err_to_string sub in
    sprintf "%s : %s" error suberror
  | Open_message_error sub ->
    let error = "Open message error" in
    let suberror = open_msg_err_to_string sub in 
    sprintf "%s : %s" error suberror
  | Update_message_error sub ->
    let error = "Update message error" in
    let suberror = update_msg_err_to_string sub in
    sprintf "%s : %s" error suberror
  | Hold_timer_expired ->
    "Hold timer expired"
  | Finite_state_machine_error ->
    "Finite state machine error"
  | Cease -> "Cease"
;;

let parse_error_to_string = function
  | Parsing_error -> "Parsing error"
  | Msg_fmt_error err -> begin
    match err with
    | Parse_msg_h_err sub -> msg_h_err_to_string sub
    | Parse_open_msg_err sub -> open_msg_err_to_string sub 
    | Parse_update_msg_err sub -> update_msg_err_to_string sub
  end
  | Notif_fmt_error _ -> "Notif format err"
;;
    

type t =
  | Open of opent
  | Update of update
  | Notification of error
  | Keepalive

let to_string = function
  | Open o -> sprintf "OPEN(%s)" (opent_to_string o)
  | Update u -> sprintf "UPDATE(%s)" (update_to_string u)
  | Notification e -> sprintf "NOTIFICATION(%s)" (error_to_string e)
  | Keepalive -> "KEEPALIVE"
;;

let default_marker = 
  Cstruct.(
    let buf = create 16 in
    memset buf 0x00ff;
    buf
  )
;;

let parse ?(caller=Normal) buf =
  let lenf buf = Some (get_h_len buf) in
  let pf buf =
    let header, payload = Cstruct.split buf sizeof_h in
    let msg_len = get_h_len header in
    let tc_opt = get_h_typ header |> int_to_tc in
    
    if not (Cstruct.equal (get_h_marker header) default_marker) then
      (match tc_opt with
      | Some NOTIFICATION -> 
        raise (Notif_fmt_err Connection_not_synchroniszed_n)
      | _ -> 
        raise (Msg_fmt_err (Parse_msg_h_err Connection_not_synchroniszed))
      );
    
    if (msg_len < 19 || msg_len > 4096) then
      raise (Msg_fmt_err (Parse_msg_h_err (Bad_message_length msg_len)));   

    (* Parse payload *)
    match tc_opt with
    | None -> 
      raise (Msg_fmt_err (Parse_msg_h_err (Bad_message_type (get_h_typ header))))
    | Some OPEN ->
      if (msg_len < 29) then
        raise (Msg_fmt_err (Parse_msg_h_err (Bad_message_length msg_len)));
      
      let opt_len = get_opent_opt_len payload in
      let m, opts = Cstruct.split payload (msg_len - sizeof_h - opt_len) in
      let opts =
        let rec aux len acc bs =
          if opt_len = opt_len then acc else (
            let t, opt, bs = Tlv.get_tlv bs in
            let opt = match int_to_oc t with
              | None -> failwith "bad option"
              | Some RESERVED -> Reserved
              | Some AUTHENTICATION -> Authentication
              | Some CAPABILITY ->
                let t,c, _ = Tlv.get_tlv bs in
                Capability (parse_capability c (int_to_cc t))
            in aux (opt_len + Tlv.sizeof_tl + Tlv.get_tl_l bs) (opt :: acc) bs
          )
        in aux 0 [] opts
      in
      let opent = { 
        version = get_opent_version m;
        local_asn = Int32.of_int (get_opent_local_asn m);
        hold_time = get_opent_hold_time m;
        local_id = Ipaddr.V4.of_int32 (get_opent_local_id m);
        options = opts;
      } in
      Open opent
    | Some UPDATE ->
      if msg_len < 23 then
        raise (Msg_fmt_err (Parse_msg_h_err (Bad_message_length msg_len)));

      let wd_len = Cstruct.BE.get_uint16 payload 0 in
      let pa_len = Cstruct.BE.get_uint16 payload (2 + wd_len) in
      if wd_len + pa_len + 23 > msg_len then
        raise (Msg_fmt_err (Parse_update_msg_err (Malformed_attribute_list)))
      else
        let withdrawn, bs =
          let wl = Cstruct.BE.get_uint16 payload 0 in
          Cstruct.split ~start:2 payload wl
        in
        let path_attrs, nlri =
          let pl = Cstruct.BE.get_uint16 bs 0 in
          Cstruct.split ~start:2 bs pl
        in
        let withdrawn = parse_nlris withdrawn in
        let nlri = parse_nlris nlri in
        if nlri = [] then
          Update {
            withdrawn;
            path_attrs = [];
            nlri;
          }
        else
          Update {
            withdrawn;
            path_attrs = parse_path_attrs ~caller path_attrs;
            nlri;
          }
    | Some NOTIFICATION -> 
      if (msg_len < 21) then
        raise (Notif_fmt_err Bad_message_length_n);
      let error = parse_notif payload in
      Notification error
    | Some KEEPALIVE ->
      if msg_len != 19 then 
        raise (Msg_fmt_err (Parse_msg_h_err (Bad_message_length msg_len)));
      Keepalive
  in
  Cstruct.iter lenf pf buf
;;

let parse_buffer_to_t buf =
  try 
    match parse buf () with
    | None -> 
      Parser_log.err (fun m -> m "This is a marker. Something unexpected occurs in Bgp.parse_buffer_to_t."); 
      assert false
    | Some it -> Ok it 
  with
  | Msg_fmt_err err -> Error (Msg_fmt_error err)
  | Notif_fmt_err err -> Error (Notif_fmt_error err)
  | Invalid_argument str -> Error Parsing_error
;;

let len_header_buffer = sizeof_h

let fill_header_buffer buf len typ = 
  let marker, _ = Cstruct.split buf 16 in
  Cstruct.memset marker 0x00ff; 
  set_h_len buf len;
  set_h_typ buf (tc_to_int typ);
  sizeof_h
;;

let len_open_buffer (o: opent) = sizeof_h + sizeof_opent

let fill_open_buffer buf (o: opent) =
  let buf_h, buf_p = Cstruct.split buf sizeof_h in
  let buf_opent, buf_opt = Cstruct.split buf_p sizeof_opent in
  let _ = fill_header_buffer buf_h (sizeof_h + sizeof_opent) OPEN in
  set_opent_version buf_opent o.version;
  set_opent_local_asn buf_opent (Int32.to_int o.local_asn);
  set_opent_hold_time buf_opent o.hold_time;
  set_opent_local_id buf_opent (Ipaddr.V4.to_int32 o.local_id);
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
  
let gen_keepalive () =
  let buf = Cstruct.create 19 in
  let _ = fill_header_buffer buf 19 KEEPALIVE in
  buf
;;
  
let len_pfxs_buffer pfxs =
  let f prefix = 
    let num_b = pfxlen_to_bytes (Ipaddr.V4.Prefix.bits prefix) in
    num_b + 1
  in 
  List.fold_left (+) 0 (List.map f pfxs)
;;

let fill_pfxs_buffer buf pfxs =
  let f total_len pfx =
    let mask = Ipaddr.V4.Prefix.bits pfx in
    let ip = Ipaddr.V4.Prefix.network pfx in

    (* Set mask *)
    let num_b = pfxlen_to_bytes mask in
    let _, buf_this = Cstruct.split buf total_len in
    Cstruct.set_uint8 buf_this 0 mask;
    
    (* Fill in address *)
    let ip4 = Ipaddr.V4.to_int32 ip in
    for i = 1 to num_b do
      Cstruct.set_uint8 buf_this i (Int32.to_int (ip4 >>> (32 - i * 8) &&& 0x00ff_l))
    done;

    total_len + num_b + 1
  in
  (* return length of used buffer *)
  List.fold_left f 0 pfxs
;;

let len_attr_ft_buffer = sizeof_ft

let fill_attr_ft_buffer buf flags tc len =
  set_ft_flags buf (attr_flags_to_int flags);
  set_ft_tc buf (attr_t_to_int tc);
  set_ft_len buf len;
  sizeof_ft
;;

let len_attr_fte_buffer = sizeof_fte

let fill_attr_fte_buffer buf flags tc len =
  set_fte_flags buf (attr_flags_to_int flags);
  set_fte_tc buf (attr_t_to_int tc);
  set_fte_len buf len;
  sizeof_fte
;;

let len_attr_as_path_data_buffer ?(sizeof_asn=2) asp =
  let f total_len segment = 
    let set_or_seq, asn_list = 
      match segment with 
      | Asn_set v -> (1, v) 
      | Asn_seq v -> (2, v) 
    in
    total_len + 2 + sizeof_asn * (List.length asn_list)
  in
  List.fold_left f 0 asp
;;

let fill_attr_as_path_data_buffer ?(sizeof_asn=2) buf asp =
  let f total_len segment = 
    let set_or_seq, asn_list = 
      match segment with 
      | Asn_set v -> (1, v) 
      | Asn_seq v -> (2, v) 
    in
    let buf_slice = Cstruct.shift buf total_len in
    
    Cstruct.set_uint8 buf_slice 0 set_or_seq;
    Cstruct.set_uint8 buf_slice 1 (List.length asn_list);
    
    let g len asn =
      let () = if (sizeof_asn = 2) then
        Cstruct.BE.set_uint16 buf_slice len (Int32.to_int asn)
      else
        Cstruct.BE.set_uint32 buf_slice len asn
      in len + sizeof_asn
    in 
    
    total_len + (List.fold_left g 2 asn_list)
  in
  List.fold_left f 0 asp
;;

let gen_attr_as_path_data_buffer asp =
  let buf = Cstruct.create 4096 in
  let len = fill_attr_as_path_data_buffer buf asp in
  let ret, _ = Cstruct.split buf len in 
  ret
;;

let len_path_attrs_buffer path_attrs = 
  let f total_len (flags, path_attr) =
    let len_h = if flags.extlen then sizeof_fte else sizeof_ft in
    
    let len_p, attr_t, new_flags = 
      match path_attr with
      | Origin origin -> 
        1, ORIGIN, flags
      | As_path asp ->
        let len_p = len_attr_as_path_data_buffer asp in
        len_p, AS_PATH, flags
      | Next_hop ip4 -> 
        4, NEXT_HOP, flags
      | As4_path asp ->
        let new_flags = {
          optional=true;
          transitive=flags.transitive;
          partial=flags.partial;
          extlen=flags.extlen;
        } in
        let len_p = len_attr_as_path_data_buffer ~sizeof_asn:4 asp in
        len_p, AS4_PATH, new_flags
      | _ -> 0, UNKNOWN, flags
    in
    
    if attr_t != UNKNOWN then total_len + len_h + len_p else total_len
  in
  List.fold_left f 0 path_attrs
;;

let fill_path_attrs_buffer buf path_attrs =
  let f total_len (flags, path_attr) =
    let buf_slice = Cstruct.shift buf total_len in
    let len_h = if flags.extlen then sizeof_fte else sizeof_ft in
    let buf_h, buf_p = Cstruct.split buf_slice len_h in
    
    let len_p, attr_t, new_flags = 
      match path_attr with
      | Origin origin -> 
        Cstruct.set_uint8 buf_p 0 (origin_to_int origin);
        1, ORIGIN, flags
      | As_path asp ->
        let len_p = fill_attr_as_path_data_buffer buf_p asp in
        len_p, AS_PATH, flags
      | Next_hop ip4 -> 
        Cstruct.BE.set_uint32 buf_p 0 (Ipaddr.V4.to_int32 ip4);
        4, NEXT_HOP, flags
      | As4_path asp ->
        let new_flags = {
          optional=true;
          transitive=flags.transitive;
          partial=flags.partial;
          extlen=flags.extlen;
        } in
        let len_p = fill_attr_as_path_data_buffer ~sizeof_asn:4 buf_p asp in
        len_p, AS4_PATH, new_flags
      | _ -> 0, UNKNOWN, flags
    in
    
    if attr_t != UNKNOWN then
      let _ = if flags.extlen then
        fill_attr_fte_buffer buf_h new_flags attr_t len_p
      else
        fill_attr_ft_buffer buf_h new_flags attr_t len_p
      in
      total_len + len_h + len_p
    else total_len
  in
  List.fold_left f 0 path_attrs
;;

let len_update_buffer { withdrawn; path_attrs; nlri } = 
  let len_wd = len_pfxs_buffer withdrawn in
  let len_pa = len_path_attrs_buffer path_attrs in
  let len_nlri = len_pfxs_buffer nlri in
  sizeof_h + len_wd + len_pa + len_nlri + 4
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

let gen_update ({ withdrawn; path_attrs; nlri } as u) =
  let buf = Cstruct.create 4096 in
  let len = fill_update_buffer buf u in
  let ret, _ = Cstruct.split buf len in 
  ret
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
  | Keepalive -> gen_keepalive ()
  | Notification e -> gen_notification e
;;

let get_msg_len buf = get_h_len buf
