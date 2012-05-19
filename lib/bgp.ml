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
  in (ip,l)

let nlri_iter buf = 
  let lenf buf = 0, 1 + (pfxlen_to_bytes (Cstruct.get_uint8 buf 0)) in
  let pf _ buf = 
    if pfxlen_to_bytes (Cstruct.get_uint8 buf 0) <= 4 then
      get_nlri4 buf 0
    else
      get_nlri6 buf 0
  in
  Cstruct.iter lenf pf buf

cstruct h {
  uint8_t marker[16];
  uint16_t len;
  uint8_t typ
} as big_endian

cenum tc {
  OPEN         = 1;
  UPDATE       = 2;
  NOTIFICATION = 3;
  KEEPALIVE    = 4
} as uint8_t

cenum cc {
  MP_EXT                      = 1;
  ROUTE_REFRESH               = 2;
  OUTBOUND_ROUTE_FILTERING    = 3;
  MULTIPLE_ROUTES_DESTINATION = 4;
  EXT_HEXTHOP_ENC             = 5;
  GRACEFUL_RESTART            = 64;
  AS4_SUPPORT                 = 65;
  ENHANCED_REFRESH            = 70
} as uint8_t

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
  | Some MP_EXT -> Mp_ext (get_mp_ext_afi buf |> Afi.int_to_tc, 
                           get_mp_ext_safi buf |> Safi.int_to_tc)
  | _ -> failwith "unrecognised capability"

cenum oc {
  RESERVED = 0;
  AUTHENTICATION = 1;
  CAPABILITY = 2
} as uint8_t 

type opt_param =
  | Reserved (* wtf? *)
  | Authentication (* deprecated, rfc 4271 *)
  | Capability of capability

let opt_param_to_string = function
  | Reserved -> "RESERVED"
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
  EXT_COMMUNITIES = 16;
  AS4_PATH = 17
} as uint8_t

cenum origin { IGP; EGP; INCOMPLETE } as uint8_t

type path_attr = 
  | Origin of (origin option)
  | As_path 
  | Next_hop
  | Community
  | Ext_communities
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
  let lenf buf = 
    let f = get_ft_flags buf in
    Cstruct.(if is_extlen f then sizeof_fte,get_fte_len buf else sizeof_ft, get_ft_len buf)
  in
  let pf hlen buf =
    let h,p = Cstruct.split buf hlen in
    match h |> get_ft_tc |> int_to_attr with
      | Some ORIGIN -> 
          let p = Cstruct.get_uint8 p 0 |> int_to_origin in 
          Origin p
            
      | Some AS_PATH ->
          As_path
      | Some AS4_PATH ->
          As4_path

      | Some NEXT_HOP ->
          Next_hop

      | Some COMMUNITY ->
          Community

      | Some EXT_COMMUNITIES ->
          Ext_communities

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
  Cstruct.iter lenf pf buf

type update = {
  withdrawn: Afi.prefix Cstruct.iter;
  path_attrs: path_attr Cstruct.iter;
  nlri: Afi.prefix Cstruct.iter;  
}

let rec path_attrs_to_string iter = match iter () with
  | None -> ""
  | Some Origin p -> "ORIGIN; " ^ (path_attrs_to_string iter)
  | Some As_path -> "AS_PATH; " ^ (path_attrs_to_string iter)
  | Some As4_path -> "AS4_PATH; " ^ (path_attrs_to_string iter)
  | Some Next_hop -> "NEXT_HOP; " ^ (path_attrs_to_string iter)
  | Some Community -> "COMMUNITY; " ^ (path_attrs_to_string iter)
  | Some Ext_communities -> "EXT_COMMUNITIES; " ^ (path_attrs_to_string iter)
  | Some Med -> "MED; " ^ (path_attrs_to_string iter)
  | Some Atomic_aggr -> "ATOMIC_AGGR; " ^ (path_attrs_to_string iter)
  | Some Aggregator -> "AGGREGATOR; " ^ (path_attrs_to_string iter)
  | Some Mp_reach_nlri -> "MP_REACH_NLRI; " ^ (path_attrs_to_string iter)
  | Some Mp_unreach_nlri -> "MP_UNREACH_NLRI; " ^ (path_attrs_to_string iter)

let rec nlris_to_string iter = match iter () with
  | None -> ""
  | Some p -> (Afi.prefix_to_string p) ^ "; " ^ (nlris_to_string iter)

let update_to_string u = 
  sprintf "withdrawn:[%s], path_attrs:[%s], nlri:[%s]" 
    (nlris_to_string u.withdrawn) 
    (path_attrs_to_string u.path_attrs) 
    (nlris_to_string u.nlri)

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
  let lenf buf = sizeof_h, get_h_len buf - sizeof_h in
  let pf hlen buf = 
    let h,p = Cstruct.split buf hlen in
    let payload = 
      match get_h_typ h |> int_to_tc with
        | None -> failwith "pf: bad BGP packet"
        | Some OPEN ->
            let m,opts = Cstruct.split p (get_bgp_open_opt_len p) in
            let opts = 
              let rec aux acc bs =
                if Cstruct.len bs = 0 then acc else (
                  let t,opt, bs = Tlv.get_tlv bs in
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
            Open { version = get_bgp_open_version m;
                   my_as = Asn (get_bgp_open_my_as m);
                   hold_time = get_bgp_open_hold_time m;
                   bgp_id = get_bgp_open_bgp_id m;
                   options = opts;
                 }
        | Some UPDATE -> 
            let withdrawn,bs = 
              let wl = Cstruct.BE.get_uint16 p 0 in
              Cstruct.split ~start:2 p wl
            in
            let path_attrs,nlri = 
              let pl = Cstruct.BE.get_uint16 bs 0 in
              Cstruct.split ~start:2 bs pl
            in
            Update {
              withdrawn = nlri_iter withdrawn;
              path_attrs = path_attrs_iter path_attrs;
              nlri = nlri_iter nlri;
            }
        | Some NOTIFICATION -> Notification
        | Some KEEPALIVE -> Keepalive
    in
    ((), payload)
  in
  Cstruct.iter lenf pf buf

let to_string (h,p) = 
  sprintf "BGP(%s)" (payload_to_string p)
