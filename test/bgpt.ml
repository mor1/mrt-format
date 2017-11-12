open Bgp
open Alcotest

let ip4_of_ints a b c d =
  Int32.of_int ((a lsl 24) lor (b lsl 16) lor (c lsl 8) lor d)
;;

let ip6_half_of_ints a b c d = Int64.logor
  (Int64.logor (Int64.shift_left (Int64.of_int a) 48) (Int64.shift_left (Int64.of_int b) 32))
  (Int64.logor (Int64.shift_left (Int64.of_int c) 16) (Int64.of_int d))
;;

let ip6_of_ints a b c d e f g h = 
  ((ip6_half_of_ints a b c d), (ip6_half_of_ints e f g h))
;;

(* module Buf_testable : TESTABLE with type t := Cstruct.t = struct
  type t = Cstruct.t
  let pp = Fmt.nop;;
  let equal = Cstruct.equal;;
end;; *)

let test t =
  let msg1 = gen_msg t in
  let t2 = match (parse_buffer_to_t msg1) with Error e -> assert false | Ok v -> v in
  let msg2 = gen_msg t2 in
  assert (Cstruct.equal msg1 msg2);
  Printf.printf "Test pass: %s\n" (Bgp.to_string t2)
;;

let () =
  let withdrawn = 
    [(Afi.IPv4 (ip4_of_ints 192 168 0 0), 16); 
      (Afi.IPv4 (ip4_of_ints 10 0 0 0), 8); 
      (Afi.IPv4 (ip4_of_ints 172 16 84 0), 24);
      ] 
  in
  let nlri = [(Afi.IPv4 (ip4_of_ints 192 168 0 0), 24)] in
  let flags = {optional=false; transitive=false; partial=false; extlen=false} in
  let path_attrs = [
    flags, Origin IGP;
    flags, As_path [Set [2_l; 5_l; 3_l]; Seq [10_l; 20_l; 30_l]];
    flags, Next_hop (ip4_of_ints 192 168 1 253);
  ] in 
  let u = Update {withdrawn; path_attrs; nlri} in
  test u
;;

let () =
  let o = {
    version=4;
    my_as= Asn 2;
    hold_time=180;
    bgp_id=1001_l;
    options=[]
  } in
  test (Open o)
;;

let () = 
  let err = Message_header_error (Bad_message_length 50) in
  test (Notification err)
;;

let () =
  test Keepalive
;;