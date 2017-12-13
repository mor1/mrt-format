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

let test_parse_gen_combo t =
  let msg1 = gen_msg t in
  let t2 = 
    match (parse_buffer_to_t msg1) with 
    | Some (Error e) -> assert false 
    | None -> assert false 
    | Some (Ok (v, _)) -> v 
  in
  let msg2 = gen_msg t2 in
  assert (Cstruct.equal msg1 msg2);
  Printf.printf "Test pass: %s\n" (Bgp.to_string t2)
;;

let test_parse_exn buf wanted_err =
  parse_buffer_to_t buf |> function
  | Some (Ok _) | None -> fail "This should give an exception."
  | Some (Error e) -> 
    if e = wanted_err then () else fail "Wrong exception type"
;;

let test_update =
  let f () =
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
    test_parse_gen_combo u
  in
  test_case 
    "Naive test for parsing and generation of update messages"
    `Slow f 
;;

let test_open =
  let f () =
    let o = {
      version=4;
      my_as= Asn 2;
      hold_time=180;
      bgp_id=1001_l;
      options=[]
    } in
    test_parse_gen_combo (Open o)
  in 
  test_case "General test for open messages." `Quick f
;;

let test_notify =
  let f () = 
    let err = Message_header_error (Bad_message_length 50) in
    test_parse_gen_combo (Notification err)
  in 
  test_case "Simple test for notification" `Slow f
;;

let test_keepalive =
  let f () = test_parse_gen_combo Keepalive in
  test_case "Simple test for keepalive." `Slow f
;;

let test_header_sync_error =
  let f () =
    let buf = Cstruct.create 19 in
    Cstruct.BE.set_uint16 buf 16 19;
    Cstruct.set_uint8 buf 18 4;
    test_parse_exn buf (General (Message_header_error Connection_not_synchroniszed))
  in
  test_case "test error: connection_not_synchronized" `Slow f
;;

let test_header_bad_length_error =
  let f () =
    let buf = Cstruct.create 19 in
    let marker, _ = Cstruct.split buf 16 in
    Cstruct.memset marker 0xff;
    Cstruct.BE.set_uint16 buf 16 19;
    Cstruct.set_uint8 buf 18 2;
    test_parse_exn buf (General (Message_header_error (Bad_message_length 19)))
  in
  test_case "test error: bad length" `Slow f
;;

let () =
  run "bgp" [
    "header", [test_header_sync_error; test_header_bad_length_error];
    "update", [test_update];
    "open", [test_open];
    "keepalive", [test_keepalive];
    "notification", [test_notify]
  ]
;;



