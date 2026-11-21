use std::net::IpAddr;
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand};
use reachmap::inbound_path::{self, Flow, PathError, Snapshot};

use super::{render_chain, write_stdout};

#[derive(Subcommand)]
pub(super) enum Command {
    /// Capture local evidence and print the prediction
    Predict {
        #[command(flatten)]
        args: CaptureArgs,
        /// Print the prediction as JSON
        #[arg(long)]
        json: bool,
    },
    /// Print a versioned snapshot of the evidence behind a prediction
    Capture(CaptureArgs),
    /// Predict from a saved path snapshot without querying the host
    Replay {
        /// File from reachmap path capture
        snapshot: PathBuf,
        /// Print the prediction as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Args)]
pub(super) struct CaptureArgs {
    /// A label you choose for the host
    #[arg(long, value_name = "LABEL")]
    host_ref: String,
    /// Source IP address of the new connection
    #[arg(long)]
    source: IpAddr,
    /// Interface on which the packet arrives
    #[arg(long)]
    ingress: String,
    /// Destination IP address on the arriving packet
    #[arg(long)]
    destination: IpAddr,
    /// Destination TCP port
    #[arg(long)]
    port: NonZeroU16,
}

impl CaptureArgs {
    fn capture(self) -> Result<Snapshot, PathError> {
        let flow = Flow::new(self.source, self.ingress, self.destination, self.port)?;
        inbound_path::capture(flow, self.host_ref)
    }
}

impl Command {
    pub(super) fn run(self) -> ExitCode {
        match self {
            Self::Capture(args) => match args.capture().and_then(|snapshot| snapshot.render()) {
                Ok(text) => write_stdout(&text, ExitCode::SUCCESS),
                Err(error) => fail(&error),
            },
            Self::Predict { args, json } => predict(args.capture(), json),
            Self::Replay { snapshot, json } => predict(inbound_path::read(&snapshot), json),
        }
    }
}

fn predict(snapshot: Result<Snapshot, PathError>, json: bool) -> ExitCode {
    let snapshot = match snapshot {
        Ok(snapshot) => snapshot,
        Err(error) => return fail(&error),
    };
    let report = snapshot.predict();
    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(text) => write_stdout(&format!("{text}\n"), ExitCode::SUCCESS),
            Err(error) => fail(&error),
        }
    } else {
        write_stdout(&report, ExitCode::SUCCESS)
    }
}

fn fail(error: &(dyn std::error::Error + 'static)) -> ExitCode {
    eprintln!("error: {}", render_chain(error));
    ExitCode::FAILURE
}
