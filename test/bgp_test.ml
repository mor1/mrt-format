open Bgp
open Alcotest

module Prefix = Ipaddr.V4.Prefix

let test_parse_gen_combo t =
  let msg1 = gen_msg t in
  let t2 = 
    match (parse_buffer_to_t msg1) with 
    | Error e -> assert false 
    | Ok v -> v 
  in
  let msg2 = gen_msg t2 in
  assert (Cstruct.equal msg1 msg2);
  Printf.printf "Test pass: %s\n" (Bgp.to_string t2)
;;

let test_parse_exn buf wanted_err =
  parse_buffer_to_t buf |> function
  | Ok _ -> fail "This should give an exception."
  | Error e -> if e = wanted_err then () else fail "Wrong exception type"
;;

let test_update =
  let f () =
    let withdrawn = [
      (Prefix.make 16 (Ipaddr.V4.of_string_exn "192.168.0.0")); 
      (Prefix.make 8 (Ipaddr.V4.of_string_exn "10.0.0.0"));
      (Prefix.make 24 (Ipaddr.V4.of_string_exn "172.16.84.0"));  
    ] in
    let nlri = [
      (Prefix.make 16 (Ipaddr.V4.of_string_exn "192.169.0.0")); 
    ] in
    let flags = {optional=false; transitive=false; partial=false; extlen=false} in
    let path_attrs = [
      flags, Origin IGP;
      flags, As_path [Asn_set [2_l; 5_l; 3_l]; Asn_seq [10_l; 20_l; 30_l]];
      flags, Next_hop (Ipaddr.V4.of_string_exn "192.168.1.253");
    ] in 
    let u = Update {withdrawn; path_attrs; nlri} in
    test_parse_gen_combo u
  in
  test_case 
    "Naive test for parsing and generation of update messages"
    `Slow f 
;;

let test_update_only_withdrawn =
  let f () =
    let withdrawn = [
      (Prefix.make 16 (Ipaddr.V4.of_string_exn "192.168.0.0")); 
      (Prefix.make 8 (Ipaddr.V4.of_string_exn "10.0.0.0"));
      (Prefix.make 24 (Ipaddr.V4.of_string_exn "172.16.84.0"));  
    ] in  
    let u = Update {withdrawn; path_attrs=[]; nlri=[]} in
    test_parse_gen_combo u
  in
  test_case 
    "test_update_only_withdrawn"
    `Slow f 
;;

let test_update_only_nlri =
  let f () =
    let nlri = [
      (Prefix.make 16 (Ipaddr.V4.of_string_exn "192.169.0.0")); 
    ] in
    let flags = {optional=false; transitive=false; partial=false; extlen=false} in
    let path_attrs = [
      flags, Origin IGP;
      flags, As_path [Asn_set [2_l; 5_l; 3_l]; Asn_seq [10_l; 20_l; 30_l]];
      flags, Next_hop (Ipaddr.V4.of_string_exn "192.168.1.253");
    ] in 
    let u = Update {withdrawn = []; path_attrs; nlri} in
    test_parse_gen_combo u
  in
  test_case 
    "test_update_only_nlri"
    `Slow f
;;

let test_open =
  let f () =
    let o = {
      version=4;
      local_asn = 2_l;
      hold_time=180;
      local_id = Ipaddr.V4.of_string_exn "172.19.0.3";
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
    test_parse_exn buf (Msg_fmt_error (Message_header_error Connection_not_synchroniszed))
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
    test_parse_exn buf (Msg_fmt_error (Message_header_error (Bad_message_length 19)))
  in
  test_case "test error: bad length" `Slow f
;;

let test_len_pfxs_buffer () = 
  let pfxs = [
    (Prefix.make 16 (Ipaddr.V4.of_string_exn "192.168.0.0")); 
    (Prefix.make 8 (Ipaddr.V4.of_string_exn "10.0.0.0"));
    (Prefix.make 24 (Ipaddr.V4.of_string_exn "172.16.84.0")); 
  ] in
  assert (len_pfxs_buffer pfxs = 9)
;;

let test_len_path_attrs_buffer () = 
  let flags = {optional=false; transitive=false; partial=false; extlen=false} in
  let path_attrs = [
    flags, Origin IGP;
    flags, As_path [Asn_set [2_l; 5_l; 3_l]; Asn_seq [10_l; 20_l; 30_l]];
    flags, Next_hop (Ipaddr.V4.of_string_exn "192.168.1.253");
  ] in 
  assert (len_path_attrs_buffer path_attrs = 4 + 19 + 7)
;;

let test_len_update_buffer () =
  let nlri = [Prefix.make 24 (Ipaddr.V4.of_string_exn "192.168.45.0")] in
  let flags = {optional=false; transitive=false; partial=false; extlen=false} in
  let path_attrs = [
    flags, Origin IGP;
    flags, As_path [Asn_set [2_l; 5_l; 3_l]; Asn_seq [10_l; 20_l; 30_l]];
    flags, Next_hop (Ipaddr.V4.of_string_exn "192.168.1.253");
  ] in 
  let u = {withdrawn = []; path_attrs; nlri} in
  assert (len_update_buffer u = 23 + len_path_attrs_buffer path_attrs + len_pfxs_buffer nlri)
;;


let () =
  run "bgp" [
    "header", [test_header_sync_error; test_header_bad_length_error];
    "update", [test_update; test_update_only_nlri; test_update_only_withdrawn ];
    "open", [test_open];
    "keepalive", [test_keepalive];
    "notification", [test_notify];
    "len", [
      test_case "test len pfxs buffer" `Slow test_len_pfxs_buffer;
      test_case "test len path attrs buffer" `Slow test_len_path_attrs_buffer;
      test_case "test len update buffer" `Slow test_len_update_buffer;
    ]
  ]
;;





