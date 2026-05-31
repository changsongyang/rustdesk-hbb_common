fn main() {
    let out_dir = format!("{}/protos", std::env::var("OUT_DIR").unwrap());

    std::fs::create_dir_all(&out_dir).unwrap();

    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir(out_dir)
        .inputs(["protos/rendezvous.proto", "protos/message.proto"])
        .include("protos")
        .customize(protobuf_codegen::Customize::default().tokio_bytes(true))
        .run()
        .expect("Codegen failed.");

    let custom_rendezvous = std::env::var("RENDEZVOUS_SERVER")
        .unwrap_or_else(|_| "".to_string());

    let custom_pub_key = std::env::var("RS_PUB_KEY")
        .unwrap_or_else(|_| "".to_string());

    println!("cargo:rustc-env=RENDEZVOUS_SERVER={}", custom_rendezvous);
    println!("cargo:rustc-env=RS_PUB_KEY={}", custom_pub_key);
}