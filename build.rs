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

    let custom_rendezvous = std::env::var("RENDEZVOUS_SERVER").expect("RENDEZVOUS_SERVER environment variable is required");
    let custom_pub_key = std::env::var("RS_PUB_KEY").expect("RS_PUB_KEY environment variable is required");
    let custom_api_server = std::env::var("API_SERVER").unwrap_or_else(|_| "https://api.rustdesk.com".to_string());

    println!("cargo:rustc-env=RENDEZVOUS_SERVER={}", custom_rendezvous);
    println!("cargo:rustc-env=RS_PUB_KEY={}", custom_pub_key);
    println!("cargo:rustc-env=API_SERVER={}", custom_api_server);
}
