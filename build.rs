use prost_build::Config;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    Config::new().out_dir("src/protos/").compile_protos(
        &["tink/proto/tink.proto", "tink/proto/aes_gcm.proto"],
        &["src/protos/", "tink/proto/"],
    )?;

    Ok(())
}
