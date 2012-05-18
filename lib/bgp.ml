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

type asn = Asn of int | Asn4 of int32
let asn_to_string = function
  | Asn a -> sprintf "%d" a
  | Asn4 a -> 
      if a < 65536_l then sprintf "%ld" a 
      else 
        sprintf "%ld.%ld" (a >>> 16) (a &&& 0xFFFF_l)

let pfxlen_to_bytes l = ((l+7) / 8)

let get_partial_ip4 buf = 
  Cstruct.( 
    let v = ref 0l in
    for i = 0 to (min 3 ((len buf)-1)) do
      v := (!v <<< 8) +++ (Int32.of_int (get_uint8 buf i))
    done;
    !v <<< (8*(4 - len buf))
  )

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

let get_partial buf = 
  let l = Cstruct.get_uint8 buf 0 in
  let bl = pfxlen_to_bytes l in
  let ip,bs = Cstruct.split ~start:1 buf bl in
  let ip = 
    if bl > 4 then
      let (hi,lo) = get_partial_ip6 ip in Afi.IPv6 (hi,lo) 
    else
      Afi.IPv4 (get_partial_ip4 ip)
  in (ip,l), bs

cstruct h {
  uint8_t marker[16];
  uint16_t len;
  uint8_t typ
} as big_endian

type tc = OPEN | UPDATE | NOTIFICATION | KEEPALIVE | ETC of int
let tc_to_int = function
  | OPEN         -> 1
  | UPDATE       -> 2
  | NOTIFICATION -> 3
  | KEEPALIVE    -> 4
  | ETC n        -> n
and int_to_tc = function
  | 1 -> OPEN
  | 2 -> UPDATE
  | 3 -> NOTIFICATION
  | 4 -> KEEPALIVE
  | n -> ETC n
and tc_to_string = function
  | OPEN         -> "OPEN"
  | UPDATE       -> "UPDATE"
  | NOTIFICATION -> "NOTIFICATION"
  | KEEPALIVE    -> "KEEPALIVE"
  | ETC n        -> sprintf "ETC %d" n

type cc = 
  | MP_EXT 
  | ROUTE_REFRESH 
  | OUTBOUND_ROUTE_FILTERING
  | MULTIPLE_ROUTES_DESTINATION
  | EXT_HEXTHOP_ENC
  | GRACEFUL_RESTART
  | AS4_SUPPORT
  | ENHANCED_REFRESH
let cc_to_int = function
  | MP_EXT -> 1
  | ROUTE_REFRESH -> 2
  | OUTBOUND_ROUTE_FILTERING -> 3
  | MULTIPLE_ROUTES_DESTINATION -> 4
  | EXT_HEXTHOP_ENC -> 5
  | GRACEFUL_RESTART -> 64
  | AS4_SUPPORT -> 65
  | ENHANCED_REFRESH -> 70
and int_to_cc = function
  | 1 -> MP_EXT
  | 2 -> ROUTE_REFRESH
  | 3 -> OUTBOUND_ROUTE_FILTERING
  | 4 -> MULTIPLE_ROUTES_DESTINATION
  | 5 -> EXT_HEXTHOP_ENC
  | 64 -> GRACEFUL_RESTART
  | 65 -> AS4_SUPPORT
  | 70 -> ENHANCED_REFRESH
and cc_to_string = function
  | MP_EXT -> "MP_EXT"
  | ROUTE_REFRESH -> "ROUTE_REFRESH"
  | OUTBOUND_ROUTE_FILTERING -> "OUTBOUND_ROUTE_FILTERING"
  | MULTIPLE_ROUTES_DESTINATION -> "MULTIPLE_ROUTES_DESTINATION"
  | EXT_HEXTHOP_ENC -> "EXT_HEXTHOP_ENC"
  | GRACEFUL_RESTART -> "GRACEFUL_RESTART"
  | AS4_SUPPORT -> "AS4_SUPPORT"
  | ENHANCED_REFRESH -> "ENHANCED_REFRESH"
    
cstruct mp_ext {
  uint16_t afi;
  uint16_t safi
} as big_endian

type capability =
  | Mp_ext of Afi.tc * Safi.tc
  | Ecapability of Cstruct.buf

let capability_to_string = function
  | Mp_ext (a,s) -> 
      sprintf "MP_EXT(%s,%s)" (Afi.tc_to_string a) (Safi.tc_to_string s)
  | Ecapability _ -> "UNKNOWN_CAPABILITY"
       
let parse_capability buf = function
  | MP_EXT -> Mp_ext (get_mp_ext_afi buf |> Afi.int_to_tc, 
                      get_mp_ext_safi buf |> Safi.int_to_tc)
  | _ -> Ecapability buf

type oc = AUTHENTICATION | CAPABILITY
let oc_to_int = function
  | AUTHENTICATION -> 1
  | CAPABILITY -> 2
and int_to_oc = function
  | 1 -> AUTHENTICATION
  | 2 -> CAPABILITY
and oc_to_string = function
  | AUTHENTICATION -> "AUTHENTICATION"
  | CAPABILITY -> "CAPABILITY"

type opt_param =
  | Authentication (* deprecated, rfc 4271 *)
  | Capability of capability

let opt_param_to_string = function
  | Authentication -> "AUTH"
  | Capability c -> sprintf "CAP(%s)" (capability_to_string c)

cstruct bgp_open {
  uint8_t version;
  uint16_t my_as;
  uint16_t hold_time;
  uint32_t bgp_id;
  uint8_t opt_len
} as big_endian

type bgp_open = {
  version: int;
  my_as: asn;
  hold_time: int;
  bgp_id: int32;
  options: opt_param list;
}

let bgp_open_to_string o = 
  sprintf "version:%d, my_as:%s, hold_time:%d, bgp_id:0x%08lx, options:[%s]"
    o.version (asn_to_string o.my_as) o.hold_time o.bgp_id 
    (o.options ||> opt_param_to_string |> String.concat "; ")
    
cenum attr {
  ORIGIN = 1;
  AS_PATH = 2;
  NEXT_HOP = 3;
  MED = 4;
  LOCAL_PREF = 5;
  ATOMIC_AGGR = 6;
  AGGREGATOR = 7;
  COMMUNITY = 8;
  MP_REACH_NLRI = 14;
  MP_UNREACH_NLRI = 15;
  AS4_PATH = 17
} as uint8_t

cenum origin { IGP; EGP; INCOMPLETE } as uint8_t

type path_attr = 
  | Origin of (origin option)
  | As_path 
  | Next_hop
  | Community
  | Med
  | Atomic_aggr
  | Aggregator
  | Mp_reach_nlri
  | Mp_unreach_nlri
  | As4_path
           
cstruct ft {
  uint8_t flags;
  uint8_t tc;
  uint8_t len
} as big_endian

cstruct fte {
  uint8_t flags;
  uint8_t tc;
  uint16_t len
} as big_endian

let is_optional f = is_bit 7 f
let is_transitive f = is_bit 6 f
let is_partial f = is_bit 5 f
let is_extlen f = is_bit 4 f
  
let path_attrs_iter buf = 
  let lenfn buf = 
    let f = get_ft_flags buf in
    Cstruct.(if is_extlen f then sizeof_fte,get_fte_len buf else sizeof_ft, get_ft_len buf)
  in
  let pfn hlen buf =
    let h,p = Cstruct.split buf hlen in
    match h |> get_ft_tc |> attr_of_int with
      | Some ORIGIN -> 
          let p = Cstruct.get_uint8 p 0 |> origin_of_int in 
          Origin p
            
      | Some AS_PATH ->
          As_path
      | Some AS4_PATH ->
          As4_path

      | Some NEXT_HOP ->
          Next_hop

      | Some COMMUNITY ->
          Community

      | Some MED ->
          Med

      | Some ATOMIC_AGGR ->
          Atomic_aggr

      | Some AGGREGATOR ->
          Aggregator

      | Some MP_REACH_NLRI ->
          Mp_reach_nlri
      
      | Some MP_UNREACH_NLRI ->
          Mp_unreach_nlri

      | _ -> 
          printf "U %d %d\n%!" (get_ft_tc h) (Cstruct.len p);
          Cstruct.hexdump p; failwith "unknown path attr"
  in
  Cstruct.(iter lenfn pfn buf) 

type update = {
  withdrawn: Afi.prefix list;
  path_attrs: (unit -> path_attr option);
  nlri: Afi.prefix list;  
}

let update_to_string u = 
  let rec path_attrs () = match u.path_attrs () with
    | None -> ""
    | Some Origin p -> "ORIGIN; " ^ (path_attrs ())
    | Some As_path -> "AS_PATH; " ^ (path_attrs ())
    | Some As4_path -> "AS4_PATH; " ^ (path_attrs ())
    | Some Next_hop -> "NEXT_HOP; " ^ (path_attrs ())
    | Some Community -> "COMMUNITY; " ^ (path_attrs ())
    | Some Med -> "MED; " ^ (path_attrs ())
    | Some Atomic_aggr -> "ATOMIC_AGGR; " ^ (path_attrs ())
    | Some Aggregator -> "AGGREGATOR; " ^ (path_attrs ())
    | Some Mp_reach_nlri -> "MP_REACH_NLRI; " ^ (path_attrs ())
    | Some Mp_unreach_nlri -> "MP_UNREACH_NLRI; " ^ (path_attrs ())
  in
  sprintf "withdrawn:[XX], path_attrs:[%s], nlri:[XX]" (path_attrs ())

type header = unit

type payload = 
  | Open of bgp_open
  | Update of update
  | Notification
  | Keepalive

let payload_to_string = function 
  | Open o -> sprintf "OPEN(%s)" (bgp_open_to_string o)
  | Update u -> sprintf "UPDATE(%s)" (update_to_string u)
  | Notification -> "NOTIFICATION"
  | Keepalive -> "KEEPALIVE"

type t = header * payload

let parse buf = 
  let h,message = Cstruct.split buf sizeof_h in
  let payload = 
    match get_h_typ h |> int_to_tc with
      | OPEN ->
          let m,opts = Cstruct.split message (get_bgp_open_opt_len message) in
          let opts = 
            let rec aux acc bs =
              if Cstruct.len bs = 0 then acc else (
                let t,opt, bs = Tlv.get_tlv bs in
                let opt = match int_to_oc t with
                  | AUTHENTICATION -> Authentication
                  | CAPABILITY -> 
                      let t,c, _ = Tlv.get_tlv bs in
                      Capability (parse_capability c (int_to_cc t))
                  | _ -> failwith (sprintf "bad opt %d" t)
                in aux (opt :: acc) bs
              )
            in aux [] opts
          in
          Open { version = get_bgp_open_version m;
                 my_as = Asn (get_bgp_open_my_as m);
                 hold_time = get_bgp_open_hold_time m;
                 bgp_id = get_bgp_open_bgp_id m;
                 options = opts;
               }
      | UPDATE -> 
          let withdrawn,bs = 
            let wl = Cstruct.BE.get_uint16 message 0 in
            Cstruct.split ~start:2 message wl
          in
          let path_attrs,nlri = 
            let pl = Cstruct.BE.get_uint16 bs 0 in
            Cstruct.split ~start:2 bs pl
          in
          Update {
            withdrawn = Cstruct.getz get_partial withdrawn;
            path_attrs = path_attrs_iter path_attrs;
            nlri = Cstruct.getz get_partial nlri;
          }
      | NOTIFICATION -> Notification
      | KEEPALIVE -> Keepalive
  in
  ((), payload)

let to_string (h,p) = 
  sprintf "BGP(%s)" (payload_to_string p)
