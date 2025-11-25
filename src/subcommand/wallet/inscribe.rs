use super::*;

#[derive(Debug, Parser)]
#[clap(group(
  ArgGroup::new("input")
    .required(true)
    .multiple(true)
    .args(&["delegate", "file"]))
)]
pub(crate) struct Inscribe {
  #[command(flatten)]
  shared: SharedArgs,
  #[arg(
    long,
    help = "Include CBOR in file at <METADATA> as inscription metadata",
    conflicts_with = "json_metadata"
  )]
  pub(crate) cbor_metadata: Option<PathBuf>,
  #[arg(long, help = "Delegate inscription content to <DELEGATE>.")]
  pub(crate) delegate: Option<InscriptionId>,
  #[arg(long, help = "Send inscription to <DESTINATION>.")]
  pub(crate) destination: Option<Address<NetworkUnchecked>>,
  #[arg(
    long,
    help = "Inscribe sat with contents of <FILE>. May be omitted if `--delegate` is supplied."
  )]
  pub(crate) file: Option<PathBuf>,
  #[arg(
    long,
    help = "Include JSON in file at <METADATA> converted to CBOR as inscription metadata",
    conflicts_with = "cbor_metadata"
  )]
  pub(crate) json_metadata: Option<PathBuf>,
  #[clap(long, help = "Set inscription metaprotocol to <METAPROTOCOL>.")]
  pub(crate) metaprotocol: Option<String>,
  #[clap(long, help = "Make inscription a child of <PARENT>.")]
  pub(crate) parent: Vec<InscriptionId>,
  #[arg(
    long,
    help = "Include <AMOUNT> postage with inscription. [default: 10000sat]",
    value_name = "AMOUNT"
  )]
  pub(crate) postage: Option<Amount>,
  #[clap(long, help = "Allow reinscription.")]
  pub(crate) reinscribe: bool,
  #[arg(long, help = "Inscribe <SAT>.", conflicts_with = "satpoint")]
  pub(crate) sat: Option<Sat>,
  #[arg(long, help = "Inscribe <SATPOINT>.", conflicts_with = "sat")]
  pub(crate) satpoint: Option<SatPoint>,
  #[arg(
    long,
    help = "Include <INSCRIPTION_ID> in gallery.",
    value_name = "INSCRIPTION_ID"
  )]
  pub(crate) gallery: Vec<InscriptionId>,
}

impl Inscribe {
  pub(crate) fn run(self, wallet: Wallet) -> SubcommandResult {
    let chain = wallet.chain();

    if let Some(delegate) = self.delegate {
      ensure! {
        wallet.inscription_exists(delegate)?,
        "delegate {delegate} does not exist"
      }
    }

    for inscription_id in &self.gallery {
      ensure! {
        wallet.inscription_exists(*inscription_id)?,
        "gallery item does not exist: {inscription_id}",
      }
    }

    let payouts = match self.shared.payouts {
      Some(payouts_str) => payouts_str
        .split(',')
        .map(|payout| {
          let mut parts = payout.split(':');
          let address = parts.next().unwrap();
          let amount_sats = parts.next().unwrap().parse::<u64>().unwrap();
          let destination = Address::from_str(address)
            .unwrap()
            .require_network(wallet.chain().network())
            .unwrap();
          let amount = Amount::from_sat(amount_sats);
          wallet::batch::plan::Payout {
            destination,
            amount,
          }
        })
        .collect(),
      _ => vec![],
    };

    let commit_change_address = if self.shared.commit_change_address.is_some() {
      Some(
        self
          .shared
          .commit_change_address
          .unwrap()
          .require_network(wallet.chain().network())?,
      )
    } else {
      None
    };

    let parent_change_address = if self.shared.parent_change_address.is_some() {
      self
        .shared
        .parent_change_address
        .unwrap()
        .require_network(wallet.chain().network())?
    } else {
      wallet.get_change_address()?
    };

    let parents = self.parent.clone();

    batch::Plan {
      commit_fee_rate: self.shared.commit_fee_rate.unwrap_or(self.shared.fee_rate),
      destinations: vec![match self.destination.clone() {
        Some(destination) => destination.require_network(chain.network())?,
        None => wallet.get_change_address()?,
      }],
      dry_run: self.shared.dry_run,
      etching: None,
      inscriptions: vec![Inscription::new(
        chain,
        self.shared.compress,
        self.delegate,
        WalletCommand::parse_metadata(self.cbor_metadata, self.json_metadata)?,
        self.metaprotocol,
        self.parent.into_iter().collect(),
        self.file,
        None,
        Properties {
          gallery: self.gallery,
        },
        None,
      )?],
      mode: batch::Mode::SeparateOutputs,
      no_backup: self.shared.no_backup,
      no_limit: self.shared.no_limit,
      parent_info: wallet.get_parent_info(&parents, parent_change_address)?,
      postages: vec![self.postage.unwrap_or(TARGET_POSTAGE)],
      reinscribe: self.reinscribe,
      reveal_fee_rate: self.shared.fee_rate,
      reveal_satpoints: Vec::new(),
      satpoint: if let Some(sat) = self.sat {
        Some(wallet.find_sat_in_outputs(sat)?)
      } else {
        self.satpoint
      },
      payouts,
      commit_change_address,
    }
    .inscribe(
      &wallet.locked_utxos().clone().into_keys().collect(),
      wallet.get_runic_outputs()?.unwrap_or_default(),
      wallet.utxos(),
      &wallet,
    )
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn cbor_and_json_metadata_flags_conflict() {
    assert_regex_match!(
      Arguments::try_parse_from([
        "ord",
        "wallet",
        "inscribe",
        "--cbor-metadata",
        "foo",
        "--json-metadata",
        "bar",
        "--file",
        "baz",
      ])
      .unwrap_err()
      .to_string(),
      ".*--cbor-metadata.*cannot be used with.*--json-metadata.*"
    );
  }

  #[test]
  fn satpoint_and_sat_flags_conflict() {
    assert_regex_match!(
      Arguments::try_parse_from([
        "ord",
        "--index-sats",
        "wallet",
        "inscribe",
        "--sat",
        "50000000000",
        "--satpoint",
        "038112028c55f3f77cc0b8b413df51f70675f66be443212da0642b7636f68a00:1:0",
        "--file",
        "baz",
      ])
      .unwrap_err()
      .to_string(),
      ".*--sat.*cannot be used with.*--satpoint.*"
    );
  }

  #[test]
  fn delegate_or_file_must_be_set() {
    assert_regex_match!(
      Arguments::try_parse_from(["ord", "wallet", "inscribe", "--fee-rate", "1"])
        .unwrap_err()
        .to_string(),
      r".*required arguments.*--delegate <DELEGATE>\|--file <FILE>.*"
    );

    assert!(
      Arguments::try_parse_from([
        "ord",
        "wallet",
        "inscribe",
        "--file",
        "hello.txt",
        "--fee-rate",
        "1"
      ])
      .is_ok()
    );

    assert!(
      Arguments::try_parse_from([
        "ord",
        "wallet",
        "inscribe",
        "--delegate",
        "038112028c55f3f77cc0b8b413df51f70675f66be443212da0642b7636f68a00i0",
        "--fee-rate",
        "1"
      ])
      .is_ok()
    );

    assert!(
      Arguments::try_parse_from([
        "ord",
        "wallet",
        "inscribe",
        "--file",
        "hello.txt",
        "--delegate",
        "038112028c55f3f77cc0b8b413df51f70675f66be443212da0642b7636f68a00i0",
        "--fee-rate",
        "1"
      ])
      .is_ok()
    );
  }
}
