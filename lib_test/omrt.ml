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

let print_bgp4mp subtype pkt = 
  let peer_as, local_as, ifc, afi, bs = 
    Bgp4mp.(match subtype with 
      | Message ->
          let h,bs = Cstruct.split pkt sizeof_h in 
          ( Asn (get_h_peer_as h), Asn (get_h_local_as h), 
            (get_h_ifc h), h |> get_h_afi |> Afi.int_to_t, 
            bs
          )

      | Message_as4
      | State_as4 ->
          let h,bs = Cstruct.split pkt Bgp4mp.sizeof_h_as4 in
          ( Asn4 (get_h_as4_peer_as h), Asn4 (get_h_as4_local_as h),
            (get_h_as4_ifc h), h |> get_h_as4_afi |> Afi.int_to_t,
            bs
          )
            
      | t -> 
          invalid_arg (sprintf "BGP4MP subtype (%s)" Bgp4mp.(t_to_string t))
    )
  in
  printf "\tpeer_as:%s local_as:%s ifc:%d afi:%s\n%!"
    (Bgp4mp.asn_to_string peer_as) (Bgp4mp.asn_to_string local_as) 
    ifc Afi.(t_to_string afi);

  let peer_ip, local_ip, bs =
    Afi.(Bgp4mp.(match afi with 
      | IP4 -> 
          let h,bs = Cstruct.split bs Bgp4mp.sizeof_h4 in 
          IPv4 (get_h4_peer_ip h), IPv4 (get_h4_local_ip h), bs
      | IP6 ->
          let h,bs = Cstruct.split bs Bgp4mp.sizeof_h6 in 
          IPv6 ((get_h6_peer_ip_hi h), (get_h6_peer_ip_lo h)), 
          IPv6 ((get_h6_local_ip_hi h), (get_h6_local_ip_lo h)),
          bs
    ))
  in
  printf "\tpeer_ip:%s\n\tlocal_ip:%s\n%!"
    (Afi.ip_to_string peer_ip) (Afi.ip_to_string local_ip);

  Bgp4mp.(match subtype with 
    | State
    | State_as4 ->
        printf "\t\told:%s new:%s\n%!"
          (bs |> get_state_change_oldstate |> int_to_state |> state_to_string)
          (bs |> get_state_change_newstate |> int_to_state |> state_to_string)
    | _ -> ()
  )

let print_table subtype pkt = 
  Afi.(Table.(match subtype with
    | IP4 ->
        printf "\tviewno:%d seqno:%d status:%d otime:%ld\n" 
          (get_h4_viewno pkt) (get_h4_seqno pkt) 
          (get_h4_status pkt) (get_h4_otime pkt);
        printf "\tpeer_ip:%s peer_as:%d prefix:%s/%d\n%!"
          (IPv4 (get_h4_peer_ip pkt) |> ip_to_string) 
          (get_h4_peer_as pkt)
          (IPv4 (get_h4_prefix pkt) |> ip_to_string) (get_h4_pfxlen pkt)

    | IP6 ->
        printf "\tviewno:%d seqno:%d status:%d otime:%ld\n" 
          (get_h6_viewno pkt) (get_h6_seqno pkt) 
          (get_h6_status pkt) (get_h6_otime pkt);
        printf "\tpeer_ip:%s peer_as:%d prefix:%s/%d\n%!"
          (IPv6 ((get_h6_peer_ip_hi pkt), (get_h6_peer_ip_lo pkt))
              |> ip_to_string)
          (get_h6_peer_as pkt)
          (IPv6 ((get_h6_prefix_hi pkt), (get_h6_prefix_lo pkt))
              |> ip_to_string) (get_h6_pfxlen pkt)
  ))

let rec print_packets buf = 
  incr npackets;
  
  let h,bs = Cstruct.split buf sizeof_h in
  let plen = Int32.to_int (get_h_length h) in
  let p,rest = Cstruct.split bs plen in

  printf "#%d %s\n%!" !npackets (h_to_string h);
  (match (get_h_mrttype h |> int_to_t) with
    | Bgp4mp -> print_bgp4mp (h |> get_h_subtype |> Bgp4mp.int_to_t) p
    | Table  -> print_table  (h |> get_h_subtype |> Afi.int_to_t) p
    | _      -> invalid_arg "mrttype"
  );
  if Cstruct.len rest > 0 then print_packets rest

let print fn =
  let fd = Unix.(openfile fn [O_RDONLY] 0) in

  let buf = Bigarray.(Array1.map_file fd Bigarray.char c_layout false (-1)) in
  Printf.printf "file length %d\n" (Cstruct.len buf);

  print_packets buf;
  Printf.printf "num packets %d\n%!" !npackets

let _ = 
  print Sys.argv.(1)
