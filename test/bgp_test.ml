open Bgp
open Alcotest

open Bgp_cstruct

module Prefix = Ipaddr.V4.Prefix

let test_find_origin () =
  let flags = {
    transitive = false;
    optional = false;
    partial = false;
    extlen = false;
  } in
  let path_attrs = [
    (flags, Origin EGP);
    (flags, As_path [Asn_seq [1_l]]);
  ] in
  assert (find_origin path_attrs = Some Bgp.EGP);

  let flags = {
    transitive = false;
    optional = false;
    partial = false;
    extlen = false;
  } in
  let path_attrs = [
    (flags, As_path [Asn_seq [1_l]]);
  ] in
  assert (find_origin path_attrs = None);
;;

let test_find_origin () =
  let flags = {
    transitive = false;
    optional = false;
    partial = false;
    extlen = false;
  } in
  let path_attrs = [
    (flags, Origin EGP);
    (flags, As_path [Asn_seq [1_l]]);
  ] in
  assert (find_aspath path_attrs = Some [Asn_seq [1_l]]);

  let flags = {
    transitive = false;
    optional = false;
    partial = false;
    extlen = false;
  } in
  let path_attrs = [
    (flags, Origin EGP);
  ] in
  assert (find_aspath path_attrs = None);
;;

let test_find_aspath () =
  let flags = {
    transitive = false;
    optional = false;
    partial = false;
    extlen = false;
  } in
  let path_attrs = [
    (flags, Origin EGP);
    (flags, As_path [Asn_seq [1_l]]);
  ] in
  assert (find_aspath path_attrs = Some [Asn_seq [1_l]]);

  let flags = {
    transitive = false;
    optional = false;
    partial = false;
    extlen = false;
  } in
  let path_attrs = [
    (flags, Origin EGP);
  ] in
  assert (find_aspath path_attrs = None);
;;

let test_find_next_hop () =
  let flags = {
    transitive = false;
    optional = false;
    partial = false;
    extlen = false;
  } in
  let id = Ipaddr.V4.of_string_exn "172.19.10.1" in
  let path_attrs = [
    (flags, Origin EGP);
    (flags, As_path [Asn_seq [1_l]]);
    (flags, Next_hop id)
  ] in
  assert (find_next_hop path_attrs = Some id);

  let flags = {
    transitive = false;
    optional = false;
    partial = false;
    extlen = false;
  } in
  let path_attrs = [
    (flags, Origin EGP);
    (flags, As_path [Asn_seq [1_l]]);
  ] in
  assert (find_next_hop path_attrs = None);
;;

let test_path_attrs_mem () =
  let flags = {
    transitive = false;
    optional = false;
    partial = false;
    extlen = false;
  } in
  let path_attrs = [
    (flags, Origin EGP);
    (flags, As_path [Asn_seq [1_l]]);
  ] in
  assert (path_attrs_mem ORIGIN path_attrs);
  assert (path_attrs_mem AS_PATH path_attrs);
  assert (path_attrs_mem NEXT_HOP path_attrs = false);
;;

let test_parse_gen_combo t =
  let msg1 = gen_msg t in
  let t2 = 
    match (parse_buffer_to_t msg1) with 
    | Error err -> 
      failwith (parse_error_to_string err)
    | Ok v -> v 
  in
  let msg2 = gen_msg t2 in

  Printf.printf "%s \n" (to_string t);
  Printf.printf "%s \n" (to_string t2);
  
  assert (Cstruct.equal msg1 msg2);
  Printf.printf "Test pass: %s\n" (Bgp.to_string t2)
;;

let test_parse_exn buf wanted_err =
  parse_buffer_to_t buf |> function
    | Ok _ -> fail "This should give an exception."
    | Error e -> assert (e = wanted_err)
;;

let test_normal_update =
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

let test_header_sync_error () =
  let buf = Cstruct.create 19 in
  Cstruct.BE.set_uint16 buf 16 19;
  Cstruct.set_uint8 buf 18 4;

  match parse_buffer_to_t buf with
  | Ok _ -> assert false
  | Error e -> 
    assert (e = (Msg_fmt_error (Parse_msg_h_err Connection_not_synchroniszed)))
;;

let test_header_bad_length_error () =
  let buf = Cstruct.create 19 in
  let marker, _ = Cstruct.split buf 16 in
  Cstruct.memset marker 0xff;
  Cstruct.BE.set_uint16 buf 16 19;
  Cstruct.set_uint8 buf 18 2;
  
  match parse_buffer_to_t buf with
  | Ok _ -> assert false
  | Error err ->
    assert (err = Msg_fmt_error (Parse_msg_h_err (Bad_message_length 19)))
;;

let test_header_bad_message_type () =
  let buf = Cstruct.create 19 in
  let marker, _ = Cstruct.split buf 16 in
  Cstruct.memset marker 0xff;
  Cstruct.BE.set_uint16 buf 16 19;
  set_h_typ buf 6;

  match parse_buffer_to_t buf with
  | Ok _ -> assert false
  | Error err ->
    assert (err = Msg_fmt_error (Parse_msg_h_err (Bad_message_type 6)))
;;

let test_update_duplicated_attr () =
  let flags = {
    transitive = false;
    optional = false;
    partial = false;
    extlen = false;
  } in
  let path_attrs = [
    (flags, Origin EGP);
    (flags, As_path [Asn_seq [1_l]]);
    (flags, Origin EGP);
  ] in
  let nlri = [Prefix.make 24 (Ipaddr.V4.of_string_exn "192.168.45.0")] in
  let buf = gen_msg (Update { withdrawn = []; path_attrs; nlri }) in

  match parse_buffer_to_t buf with
  | Ok _ -> assert false
  | Error err ->
    assert (err = Msg_fmt_error (Parse_update_msg_err Malformed_attribute_list))
;;

let test_update_missing_well_known_attr () = 
  let flags = {
    transitive = false;
    optional = false;
    partial = false;
    extlen = false;
  } in
  let path_attrs = [
    (flags, Origin EGP);
    (flags, As_path [Asn_seq [1_l]]);
  ] in
  let nlri = [Prefix.make 24 (Ipaddr.V4.of_string_exn "192.168.45.0")] in
  let buf = gen_msg (Update { withdrawn = []; path_attrs; nlri }) in

  match parse_buffer_to_t buf with
  | Ok _ -> assert false
  | Error err ->
    assert (err = Msg_fmt_error (Parse_update_msg_err (Missing_wellknown_attribute 3)))
;;

let test_update_attr_flags_err () = 
  let flags = {
    transitive = false;
    optional = true;
    partial = false;
    extlen = false;
  } in
  let path_attrs = [
    (flags, Origin EGP);
    (flags, As_path [Asn_seq [1_l]]);
    flags, Next_hop (Ipaddr.V4.of_string_exn "192.168.1.253");
  ] in
  let nlri = [Prefix.make 24 (Ipaddr.V4.of_string_exn "192.168.45.0")] in
  let buf = gen_msg (Update { withdrawn = []; path_attrs; nlri }) in

  match parse_buffer_to_t buf with
  | Ok _ -> assert false
  | Error (Msg_fmt_error (Parse_update_msg_err (Attribute_flags_error _))) ->
    assert true
  | Error _ -> assert false
;;


let test_update_attr_length_err () = 
  let flags = {
    transitive = false;
    optional = false;
    partial = false;
    extlen = false;
  } in
  let path_attrs = [
    (flags, Origin EGP);
    (flags, As_path [Asn_seq [1_l]]);
    flags, Next_hop (Ipaddr.V4.of_string_exn "192.168.1.253");
  ] in
  let nlri = [Prefix.make 24 (Ipaddr.V4.of_string_exn "192.168.45.0")] in
  let buf = gen_msg (Update { withdrawn = []; path_attrs; nlri }) in

  Cstruct.set_uint8 buf 25 2;

  match parse_buffer_to_t buf with
  | Ok _ -> assert false
  | Error (Msg_fmt_error (Parse_update_msg_err (Attribute_length_error _))) ->
    assert true
  | Error err -> 
    Printf.printf "%s" (parse_error_to_string err);
    assert false
;;

let test_update_invalid_origin () = 
  let flags = {
    transitive = false;
    optional = false;
    partial = false;
    extlen = false;
  } in
  let path_attrs = [
    (flags, Origin EGP);
    (flags, As_path [Asn_seq [1_l]]);
    flags, Next_hop (Ipaddr.V4.of_string_exn "192.168.1.253");
  ] in
  let nlri = [Prefix.make 24 (Ipaddr.V4.of_string_exn "192.168.45.0")] in
  let buf = gen_msg (Update { withdrawn = []; path_attrs; nlri }) in

  Cstruct.set_uint8 buf 26 4;

  match parse_buffer_to_t buf with
  | Ok _ -> assert false
  | Error (Msg_fmt_error (Parse_update_msg_err (Invalid_origin_attribute _))) ->
    assert true
  | Error err -> 
    Printf.printf "%s" (parse_error_to_string err);
    assert false
;;

let () =
  run "bgp" [
    "util", [
      test_case "test find_origin" `Slow test_find_origin;
      test_case "test find_aspath" `Slow test_find_aspath;
      test_case "test find_next_hop" `Slow test_find_next_hop;
      test_case "test path_attrs_mem" `Slow test_path_attrs_mem;
    ];
    "update", [test_normal_update; test_update_only_nlri; test_update_only_withdrawn ];
    "open", [test_open];
    "keepalive", [test_keepalive];
    "notification", [test_notify];
    "len", [
      test_case "test len pfxs buffer" `Slow test_len_pfxs_buffer;
      test_case "test len path attrs buffer" `Slow test_len_path_attrs_buffer;
      test_case "test len update buffer" `Slow test_len_update_buffer;
    ];
    "error", [
      test_case "test error: connection_not_synchronized" `Slow test_header_sync_error; 
      test_case "test error: bad length" `Slow test_header_bad_length_error;
      test_case "test error: bad message type" `Slow test_header_bad_message_type;
      test_case "test error: duplicated attr" `Slow test_update_duplicated_attr;
      test_case "test error: missing well known attr" `Slow test_update_missing_well_known_attr;
      test_case "test error: attribute flags error" `Slow test_update_attr_flags_err;
      test_case "test error: attribute length error" `Slow test_update_attr_length_err;
      test_case "test error: invalid origin attribute" `Slow test_update_invalid_origin;
    ];
  ]
;;





