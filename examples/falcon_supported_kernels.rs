use clap::Parser;
use rusty_falcon::apis::sensor_update_policies_api;
use rusty_falcon::easy::client::FalconHandle;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    distro: String,

    #[arg(short, long)]
    arch: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let falcon = FalconHandle::from_env()
        .await
        .expect("Could not authenticate with CrowdStrike API");

    let filter = format!("distro:'{}'+architecture:'{}'", args.distro, args.arch);
    let offset = 0;
    let limit = 100;
    let sensor_update_response = sensor_update_policies_api::query_combined_sensor_update_kernels(
        &falcon.cfg,
        Some(filter.as_str()),
        Some(offset),
        Some(limit),
    )
    .await
    .expect("Count not fetch sensor update policy.");

    dbg!(&sensor_update_response);
}
