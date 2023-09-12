use {
  super::*,
  crate::{subcommand::wallet::transaction_builder::Target, wallet::Wallet},
  bitcoin::{
    blockdata::{opcodes, script},
    key::PrivateKey,
    key::{TapTweak, TweakedKeyPair, TweakedPublicKey, UntweakedKeyPair},
    locktime::absolute::LockTime,
    policy::MAX_STANDARD_TX_WEIGHT,
    secp256k1::{
      self, constants::SCHNORR_SIGNATURE_SIZE, rand, schnorr::Signature, Secp256k1, XOnlyPublicKey,
    },
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder},
    ScriptBuf, Witness,
  },
  bitcoincore_rpc::bitcoincore_rpc_json::{ImportDescriptors, Timestamp},
  bitcoincore_rpc::Client,
  std::collections::BTreeSet,
};

#[derive(Serialize)]
struct Output {
  commit: Txid,
  inscription: InscriptionId,
  reveal: Txid,
  fees: u64,
}

#[derive(Debug, Parser)]
pub(crate) struct Inscribe {
  #[clap(long, help = "Inscribe <SATPOINT>")]
  pub(crate) satpoint: Option<SatPoint>,
  #[clap(long, help = "Use fee rate of <FEE_RATE> sats/vB")]
  pub(crate) fee_rate: FeeRate,
  #[clap(
    long,
    help = "Use <COMMIT_FEE_RATE> sats/vbyte for commit transaction.\nDefaults to <FEE_RATE> if unset."
  )]
  pub(crate) commit_fee_rate: Option<FeeRate>,
  #[clap(help = "Inscribe sat with contents of <FILE>")]
  pub(crate) file: PathBuf,
  #[clap(long, help = "Do not back up recovery key.")]
  pub(crate) no_backup: bool,
  #[clap(
    long,
    help = "Do not check that transactions are equal to or below the MAX_STANDARD_TX_WEIGHT of 400,000 weight units. Transactions over this limit are currently nonstandard and will not be relayed by bitcoind in its default configuration. Do not use this flag unless you understand the implications."
  )]
  pub(crate) no_limit: bool,
  #[clap(long, help = "Don't sign or broadcast transactions.")]
  pub(crate) dry_run: bool,
  #[clap(long, help = "Send inscription to <DESTINATION>.")]
  pub(crate) destination: Option<Address<NetworkUnchecked>>,

  #[clap(long, help = "Sends taker_sats_amount to <TAKER_ADDRESS>.")]
  pub(crate) taker_address: Option<Address<NetworkUnchecked>>,
  #[clap(long, help = "Sends taker_address <TAKER_SATS_AMOUNT> sats.")]
  pub(crate) taker_sats_amount: Option<u64>,

  #[clap(
    long,
    help = "Sends excess sats from the commit_tx to <EXCESS_CHANGE_ADDRESS>."
  )]
  pub(crate) excess_change_address: Option<Address<NetworkUnchecked>>,

  #[clap(
    long,
    help = "Amount of postage to include in the inscription. Default `10000sat`"
  )]
  pub(crate) postage: Option<Amount>,
}

impl Inscribe {
  pub(crate) fn run(self, options: Options) -> Result {
    let inscription = Inscription::from_file(options.chain(), &self.file)?;

    let index = Index::open(&options)?;
    index.update()?;

    let client = options.bitcoin_rpc_client_for_wallet_command(false)?;

    let mut utxos = index.get_unspent_outputs(Wallet::load(&options)?)?;

    let inscriptions = index.get_inscriptions(utxos.clone())?;

    let commit_tx_change = [
      get_change_address(&client, &options)?,
      get_change_address(&client, &options)?,
    ];

    let reveal_tx_destination = match self.destination {
      Some(address) => address.require_network(options.chain().network())?,
      None => get_change_address(&client, &options)?,
    };

    let taker_address_or_none: Option<Address> = match self.taker_address {
      Some(address) => Some(address.require_network(options.chain().network())?),
      None => None,
    };

    let excess_change_address_or_none: Option<Address> = match self.excess_change_address {
      Some(address) => Some(address.require_network(options.chain().network())?),
      None => None,
    };

    let taker_amount_sats = self.taker_sats_amount.map(Amount::from_sat);

    let (unsigned_commit_tx, reveal_tx, recovery_key_pair) =
      Inscribe::create_inscription_transactions(
        self.satpoint,
        inscription,
        inscriptions,
        options.chain().network(),
        utxos.clone(),
        commit_tx_change,
        reveal_tx_destination,
        self.commit_fee_rate.unwrap_or(self.fee_rate),
        self.fee_rate,
        self.no_limit,
        taker_amount_sats,
        taker_address_or_none,
        excess_change_address_or_none,
        match self.postage {
          Some(postage) => postage,
          _ => TransactionBuilder::TARGET_POSTAGE,
        },
      )?;

    utxos.insert(
      reveal_tx.input[0].previous_output,
      Amount::from_sat(
        unsigned_commit_tx.output[reveal_tx.input[0].previous_output.vout as usize].value,
      ),
    );

    let fees =
      Self::calculate_fee(&unsigned_commit_tx, &utxos) + Self::calculate_fee(&reveal_tx, &utxos);

    if self.dry_run {
      print_json(Output {
        commit: unsigned_commit_tx.txid(),
        reveal: reveal_tx.txid(),
        inscription: reveal_tx.txid().into(),
        fees,
      })?;
    } else {
      if !self.no_backup {
        Inscribe::backup_recovery_key(&client, recovery_key_pair, options.chain().network())?;
      }

      let signed_raw_commit_tx = client
        .sign_raw_transaction_with_wallet(&unsigned_commit_tx, None, None)?
        .hex;

      let commit = client
        .send_raw_transaction(&signed_raw_commit_tx)
        .context("Failed to send commit transaction")?;

      let reveal = client
        .send_raw_transaction(&reveal_tx)
        .context("Failed to send reveal transaction")?;

      print_json(Output {
        commit,
        reveal,
        inscription: reveal.into(),
        fees,
      })?;
    };

    Ok(())
  }

  fn calculate_fee(tx: &Transaction, utxos: &BTreeMap<OutPoint, Amount>) -> u64 {
    tx.input
      .iter()
      .map(|txin| utxos.get(&txin.previous_output).unwrap().to_sat())
      .sum::<u64>()
      .checked_sub(tx.output.iter().map(|txout| txout.value).sum::<u64>())
      .unwrap()
  }

  fn create_inscription_transactions(
    satpoint: Option<SatPoint>,
    inscription: Inscription,
    inscriptions: BTreeMap<SatPoint, InscriptionId>,
    network: Network,
    utxos: BTreeMap<OutPoint, Amount>,
    change: [Address; 2],
    destination: Address,
    commit_fee_rate: FeeRate,
    reveal_fee_rate: FeeRate,
    no_limit: bool,
    taker_amount_sats: Option<Amount>,
    taker_address: Option<Address>,
    excess_change_address: Option<Address>,
    postage: Amount,
  ) -> Result<(Transaction, Transaction, TweakedKeyPair)> {
    // validate that if taker_address is set, taker_amount_sats is also set
    if taker_address.is_some() && taker_amount_sats.is_none() {
      return Err(anyhow!(
        "taker_address is set but taker_amount_sats is not set"
      ));
    }

    // validate that if taker_amount_sats is set, taker_address is also set
    if taker_amount_sats.is_some() && taker_address.is_none() {
      return Err(anyhow!(
        "taker_amount_sats is set but taker_address is not set"
      ));
    }

    // validate that if taker_amount_sats is set it is not 0
    if let Some(taker_amount_sats) = taker_amount_sats {
      if taker_amount_sats == Amount::ZERO {
        return Err(anyhow!("taker_amount_sats is set to 0"));
      }
    }

    let satpoint = if let Some(satpoint) = satpoint {
      satpoint
    } else {
      let inscribed_utxos = inscriptions
        .keys()
        .map(|satpoint| satpoint.outpoint)
        .collect::<BTreeSet<OutPoint>>();

      utxos
        .keys()
        .find(|outpoint| !inscribed_utxos.contains(outpoint))
        .map(|outpoint| SatPoint {
          outpoint: *outpoint,
          offset: 0,
        })
        .ok_or_else(|| anyhow!("wallet contains no cardinal utxos"))?
    };

    for (inscribed_satpoint, inscription_id) in &inscriptions {
      if inscribed_satpoint == &satpoint {
        return Err(anyhow!("sat at {} already inscribed", satpoint));
      }

      if inscribed_satpoint.outpoint == satpoint.outpoint {
        return Err(anyhow!(
          "utxo {} already inscribed with inscription {inscription_id} on sat {inscribed_satpoint}",
          satpoint.outpoint,
        ));
      }
    }

    let secp256k1 = Secp256k1::new();
    let key_pair = UntweakedKeyPair::new(&secp256k1, &mut rand::thread_rng());
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let reveal_script = inscription.append_reveal_script(
      ScriptBuf::builder()
        .push_slice(public_key.serialize())
        .push_opcode(opcodes::all::OP_CHECKSIG),
    );

    let taproot_spend_info = TaprootBuilder::new()
      .add_leaf(0, reveal_script.clone())
      .expect("adding leaf should work")
      .finalize(&secp256k1, public_key)
      .expect("finalizing taproot builder should work");

    let control_block = taproot_spend_info
      .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
      .expect("should compute control block");

    let commit_tx_address = Address::p2tr_tweaked(taproot_spend_info.output_key(), network);

    let (_, reveal_fee) = Self::build_reveal_transaction(
      &control_block,
      reveal_fee_rate,
      OutPoint::null(),
      TxOut {
        script_pubkey: destination.script_pubkey(),
        value: 0,
      },
      &reveal_script,
    );

    let unsigned_commit_tx = TransactionBuilder::new(
      satpoint,
      inscriptions,
      utxos,
      commit_tx_address.clone(),
      change,
      commit_fee_rate,
      Target::Value(reveal_fee + postage),
      taker_amount_sats,
      taker_address,
      excess_change_address,
    )
    .build_transaction()?;

    let (vout, output) = unsigned_commit_tx
      .output
      .iter()
      .enumerate()
      .find(|(_vout, output)| output.script_pubkey == commit_tx_address.script_pubkey())
      .expect("should find sat commit/inscription output");

    let (mut reveal_tx, fee) = Self::build_reveal_transaction(
      &control_block,
      reveal_fee_rate,
      OutPoint {
        txid: unsigned_commit_tx.txid(),
        vout: vout.try_into().unwrap(),
      },
      TxOut {
        script_pubkey: destination.script_pubkey(),
        value: output.value,
      },
      &reveal_script,
    );

    reveal_tx.output[0].value = reveal_tx.output[0]
      .value
      .checked_sub(fee.to_sat())
      .context("commit transaction output value insufficient to pay transaction fee")?;

    if reveal_tx.output[0].value < reveal_tx.output[0].script_pubkey.dust_value().to_sat() {
      bail!("commit transaction output would be dust");
    }

    let mut sighash_cache = SighashCache::new(&mut reveal_tx);

    let signature_hash = sighash_cache
      .taproot_script_spend_signature_hash(
        0,
        &Prevouts::All(&[output]),
        TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript),
        TapSighashType::Default,
      )
      .expect("signature hash should compute");

    let signature = secp256k1.sign_schnorr(
      &secp256k1::Message::from_slice(signature_hash.as_ref())
        .expect("should be cryptographically secure hash"),
      &key_pair,
    );

    let witness = sighash_cache
      .witness_mut(0)
      .expect("getting mutable witness reference should work");
    witness.push(signature.as_ref());
    witness.push(reveal_script);
    witness.push(&control_block.serialize());

    let recovery_key_pair = key_pair.tap_tweak(&secp256k1, taproot_spend_info.merkle_root());

    let (x_only_pub_key, _parity) = recovery_key_pair.to_inner().x_only_public_key();
    assert_eq!(
      Address::p2tr_tweaked(
        TweakedPublicKey::dangerous_assume_tweaked(x_only_pub_key),
        network,
      ),
      commit_tx_address
    );

    let reveal_weight = reveal_tx.weight();

    if !no_limit && reveal_weight > bitcoin::Weight::from_wu(MAX_STANDARD_TX_WEIGHT.into()) {
      bail!(
        "reveal transaction weight greater than {MAX_STANDARD_TX_WEIGHT} (MAX_STANDARD_TX_WEIGHT): {reveal_weight}"
      );
    }

    Ok((unsigned_commit_tx, reveal_tx, recovery_key_pair))
  }

  fn backup_recovery_key(
    client: &Client,
    recovery_key_pair: TweakedKeyPair,
    network: Network,
  ) -> Result {
    let recovery_private_key = PrivateKey::new(recovery_key_pair.to_inner().secret_key(), network);

    let info = client.get_descriptor_info(&format!("rawtr({})", recovery_private_key.to_wif()))?;

    let response = client.import_descriptors(ImportDescriptors {
      descriptor: format!("rawtr({})#{}", recovery_private_key.to_wif(), info.checksum),
      timestamp: Timestamp::Now,
      active: Some(false),
      range: None,
      next_index: None,
      internal: Some(false),
      label: Some("commit tx recovery key".to_string()),
    })?;

    for result in response {
      if !result.success {
        return Err(anyhow!("commit tx recovery key import failed"));
      }
    }

    Ok(())
  }

  fn build_reveal_transaction(
    control_block: &ControlBlock,
    fee_rate: FeeRate,
    input: OutPoint,
    output: TxOut,
    script: &Script,
  ) -> (Transaction, Amount) {
    let reveal_tx = Transaction {
      input: vec![TxIn {
        previous_output: input,
        script_sig: script::Builder::new().into_script(),
        witness: Witness::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
      }],
      output: vec![output],
      lock_time: LockTime::ZERO,
      version: 1,
    };

    let fee = {
      let mut reveal_tx = reveal_tx.clone();

      reveal_tx.input[0].witness.push(
        Signature::from_slice(&[0; SCHNORR_SIGNATURE_SIZE])
          .unwrap()
          .as_ref(),
      );
      reveal_tx.input[0].witness.push(script);
      reveal_tx.input[0].witness.push(&control_block.serialize());

      fee_rate.fee(reveal_tx.vsize())
    };

    (reveal_tx, fee)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn reveal_transaction_pays_fee() {
    let utxos = vec![(outpoint(1), Amount::from_sat(20000))];
    let inscription = inscription("text/plain", "ord");
    let commit_address = change(0);
    let reveal_address = recipient();

    let (commit_tx, reveal_tx, _private_key) = Inscribe::create_inscription_transactions(
      Some(satpoint(1, 0)),
      inscription,
      BTreeMap::new(),
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address, change(1)],
      reveal_address,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      false,
      None,
      None,
      None,
      TransactionBuilder::TARGET_POSTAGE,
    )
    .unwrap();

    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    let fee = Amount::from_sat((1.0 * (reveal_tx.vsize() as f64)).ceil() as u64);

    assert_eq!(
      reveal_tx.output[0].value,
      20000 - fee.to_sat() - (20000 - commit_tx.output[0].value),
    );
  }

  #[test]
  fn with_taker_fees() {
    let utxos = vec![(outpoint(1), Amount::from_sat(20000))];
    let inscription = inscription("text/plain", "ord");
    let commit_address = change(0);
    let change_address: Address = "2N83imGV3gPwBzKJQvWJ7cRUY2SpUyU6A5e"
      .parse::<Address<NetworkUnchecked>>()
      .unwrap()
      .assume_checked();

    let reveal_address = recipient();
    let taker_address = change(2);
    let taker_amount_sats = Amount::from_sat(8000);

    let (commit_tx, reveal_tx, _private_key) = Inscribe::create_inscription_transactions(
      Some(satpoint(1, 0)),
      inscription,
      BTreeMap::new(),
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address.clone(), change_address.clone()],
      reveal_address,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      false,
      Some(taker_amount_sats.clone()),
      Some(taker_address.clone()),
      None,
      TransactionBuilder::TARGET_POSTAGE,
    )
    .unwrap();

    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    let fee = Amount::from_sat((1.0 * (reveal_tx.vsize() as f64)).ceil() as u64);

    tprintln!("commit output 0: {}", commit_tx.output[0].value);

    tprintln!("commit output 1: {}", commit_tx.output[1].value);

    tprintln!("commit output 2: {}", commit_tx.output[2].value);

    tprintln!("reveal output 0: {}", reveal_tx.output[0].value);

    // Assert reveal TX is 10k sats.
    assert_eq!(
      reveal_tx.output[0].value,
      20000 - fee.to_sat() - (20000 - commit_tx.output[0].value),
    );

    // Assert commit output [1] is taker address
    assert_eq!(
      commit_tx.output[1].script_pubkey,
      taker_address.clone().script_pubkey()
    );

    // Assert commit output [1] is taker amount
    assert_eq!(
      commit_tx.output[1].value,
      taker_amount_sats.clone().to_sat()
    );

    // Assert commit output [2] is change address
    assert_eq!(
      commit_tx.output[2].script_pubkey,
      change_address.clone().script_pubkey(),
    );
  }

  #[test]
  fn with_taker_and_explicit_excess_change_address() {
    let utxos = vec![(outpoint(1), Amount::from_sat(20000))];
    let inscription = inscription("text/plain", "ord");
    let commit_address = change(0);
    let some_change_address: Address = change(1);
    let excess_change_address: Address = "2N83imGV3gPwBzKJQvWJ7cRUY2SpUyU6A5e"
      .parse::<Address<NetworkUnchecked>>()
      .unwrap()
      .assume_checked();
    let reveal_address = recipient();
    let taker_address = change(2);
    let taker_amount_sats = Amount::from_sat(5000);

    let (commit_tx, reveal_tx, _private_key) = Inscribe::create_inscription_transactions(
      Some(satpoint(1, 0)),
      inscription,
      BTreeMap::new(),
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address.clone(), some_change_address.clone()],
      reveal_address,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      false,
      Some(taker_amount_sats.clone()),
      Some(taker_address.clone()),
      Some(excess_change_address.clone()),
      TransactionBuilder::TARGET_POSTAGE,
    )
    .unwrap();

    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    let fee = Amount::from_sat((1.0 * (reveal_tx.vsize() as f64)).ceil() as u64);

    tprintln!("commit output 0: {}", commit_tx.output[0].value);

    tprintln!("commit output 1: {}", commit_tx.output[1].value);

    tprintln!("commit output 2: {}", commit_tx.output[2].value);

    tprintln!("reveal output 0: {}", reveal_tx.output[0].value);

    // Assert reveal TX is 10k sats.
    assert_eq!(
      reveal_tx.output[0].value,
      20000 - fee.to_sat() - (20000 - commit_tx.output[0].value),
    );

    // Assert commit output [1] is taker address
    assert_eq!(
      commit_tx.output[1].script_pubkey,
      taker_address.clone().script_pubkey()
    );

    // Assert commit output [1] is taker amount
    assert_eq!(
      commit_tx.output[1].value,
      taker_amount_sats.clone().to_sat()
    );

    // Assert commit output [2] is change address
    assert_eq!(
      commit_tx.output[2].script_pubkey,
      excess_change_address.clone().script_pubkey(),
    );
  }

  #[test]
  fn with_target_postage() {
    let utxos = vec![(outpoint(1), Amount::from_sat(20000))];
    let inscription = inscription("text/plain", "ord");
    let commit_address = change(0);
    let some_change_address: Address = change(1);
    let excess_change_address: Address = "2N83imGV3gPwBzKJQvWJ7cRUY2SpUyU6A5e"
      .parse::<Address<NetworkUnchecked>>()
      .unwrap()
      .assume_checked();
    let reveal_address = recipient();
    let taker_address = change(2);
    let taker_amount_sats = Amount::from_sat(5000);
    let target_postage_sats = Amount::from_sat(567);

    let (commit_tx, reveal_tx, _private_key) = Inscribe::create_inscription_transactions(
      Some(satpoint(1, 0)),
      inscription,
      BTreeMap::new(),
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address.clone(), some_change_address.clone()],
      reveal_address,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      false,
      Some(taker_amount_sats.clone()),
      Some(taker_address.clone()),
      Some(excess_change_address.clone()),
      target_postage_sats.clone(),
    )
    .unwrap();

    tprintln!("commit output 0: {}", commit_tx.output[0].value);
    tprintln!("commit output 1: {}", commit_tx.output[1].value);
    tprintln!("commit output 2: {}", commit_tx.output[2].value);
    tprintln!("reveal output 0: {}", reveal_tx.output[0].value);

    // Assert reveal TX is 10k sats.
    assert_eq!(reveal_tx.output[0].value, target_postage_sats.to_sat());

    // Assert commit output [1] is taker address
    assert_eq!(
      commit_tx.output[1].script_pubkey,
      taker_address.clone().script_pubkey()
    );

    // Assert commit output [1] is taker amount
    assert_eq!(
      commit_tx.output[1].value,
      taker_amount_sats.clone().to_sat()
    );

    // Assert commit output [2] is change address
    assert_eq!(
      commit_tx.output[2].script_pubkey,
      excess_change_address.clone().script_pubkey(),
    );
  }

  #[test]
  fn with_no_taker_and_explicit_excess_change_address() {
    let utxos = vec![(outpoint(1), Amount::from_sat(20000))];
    let inscription = inscription("text/plain", "ord");
    let commit_address = change(0);
    let some_change_address: Address = change(1);
    let excess_change_address: Address = "2N83imGV3gPwBzKJQvWJ7cRUY2SpUyU6A5e"
      .parse::<Address<NetworkUnchecked>>()
      .unwrap()
      .assume_checked();
    let reveal_address = recipient();

    let (commit_tx, reveal_tx, _private_key) = Inscribe::create_inscription_transactions(
      Some(satpoint(1, 0)),
      inscription,
      BTreeMap::new(),
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address.clone(), some_change_address.clone()],
      reveal_address,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      false,
      None,
      None,
      Some(excess_change_address.clone()),
      TransactionBuilder::TARGET_POSTAGE,
    )
    .unwrap();

    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    let fee = Amount::from_sat((1.0 * (reveal_tx.vsize() as f64)).ceil() as u64);
    // Assert reveal TX is 10k sats.
    assert_eq!(
      reveal_tx.output[0].value,
      20000 - fee.to_sat() - (20000 - commit_tx.output[0].value),
    );

    // Assert commit output [2] is change address
    assert_eq!(
      commit_tx.output[1].script_pubkey,
      excess_change_address.clone().script_pubkey(),
    );
  }

  #[test]
  fn taker_address_set_but_not_taker_sats_amount() {
    let utxos = vec![(outpoint(1), Amount::from_sat(20000))];
    let inscription = inscription("text/plain", "ord");
    let commit_address = change(0);
    let change_address: Address = "2N83imGV3gPwBzKJQvWJ7cRUY2SpUyU6A5e"
      .parse::<Address<NetworkUnchecked>>()
      .unwrap()
      .assume_checked();
    let reveal_address = recipient();
    let taker_address = change(2);

    let error = Inscribe::create_inscription_transactions(
      Some(satpoint(1, 0)),
      inscription,
      BTreeMap::new(),
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address.clone(), change_address.clone()],
      reveal_address,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      false,
      None,
      Some(taker_address.clone()),
      None,
      TransactionBuilder::TARGET_POSTAGE,
    )
    .unwrap_err()
    .to_string();

    assert!(
      error.contains("taker_address is set but taker_amount_sats is not set"),
      "{}",
      error
    );
  }

  #[test]
  fn taker_sats_amount_set_but_not_taker_address() {
    let utxos = vec![(outpoint(1), Amount::from_sat(20000))];
    let inscription = inscription("text/plain", "ord");
    let commit_address = change(0);
    let change_address: Address = "2N83imGV3gPwBzKJQvWJ7cRUY2SpUyU6A5e"
      .parse::<Address<NetworkUnchecked>>()
      .unwrap()
      .assume_checked();
    let reveal_address = recipient();

    let error = Inscribe::create_inscription_transactions(
      Some(satpoint(1, 0)),
      inscription,
      BTreeMap::new(),
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address.clone(), change_address.clone()],
      reveal_address,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      false,
      Some(Amount::from_sat(5000)),
      None,
      None,
      TransactionBuilder::TARGET_POSTAGE,
    )
    .unwrap_err()
    .to_string();

    assert!(
      error.contains("taker_amount_sats is set but taker_address is not set"),
      "{}",
      error
    );
  }

  #[test]
  fn taker_amount_sats_not_0() {
    let utxos = vec![(outpoint(1), Amount::from_sat(20000))];
    let inscription = inscription("text/plain", "ord");
    let commit_address = change(0);
    let change_address: Address = "2N83imGV3gPwBzKJQvWJ7cRUY2SpUyU6A5e"
      .parse::<Address<NetworkUnchecked>>()
      .unwrap()
      .assume_checked();
    let reveal_address = recipient();

    let error = Inscribe::create_inscription_transactions(
      Some(satpoint(1, 0)),
      inscription,
      BTreeMap::new(),
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address.clone(), change_address.clone()],
      reveal_address,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      false,
      Some(Amount::from_sat(0)),
      Some(change(1)),
      None,
      TransactionBuilder::TARGET_POSTAGE,
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("taker_amount_sats is set to 0"), "{}", error);
  }

  #[test]
  fn inscript_tansactions_opt_in_to_rbf() {
    let utxos = vec![(outpoint(1), Amount::from_sat(20000))];
    let inscription = inscription("text/plain", "ord");
    let commit_address = change(0);
    let reveal_address = recipient();

    let (commit_tx, reveal_tx, _) = Inscribe::create_inscription_transactions(
      Some(satpoint(1, 0)),
      inscription,
      BTreeMap::new(),
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address, change(1)],
      reveal_address,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      false,
      None,
      None,
      None,
      TransactionBuilder::TARGET_POSTAGE,
    )
    .unwrap();

    assert!(commit_tx.is_explicitly_rbf());
    assert!(reveal_tx.is_explicitly_rbf());
  }

  #[test]
  fn inscribe_with_no_satpoint_and_no_cardinal_utxos() {
    let utxos = vec![(outpoint(1), Amount::from_sat(1000))];
    let mut inscriptions = BTreeMap::new();
    inscriptions.insert(
      SatPoint {
        outpoint: outpoint(1),
        offset: 0,
      },
      inscription_id(1),
    );

    let inscription = inscription("text/plain", "ord");
    let satpoint = None;
    let commit_address = change(0);
    let reveal_address = recipient();

    let error = Inscribe::create_inscription_transactions(
      satpoint,
      inscription,
      inscriptions,
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address, change(1)],
      reveal_address,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      false,
      None,
      None,
      None,
      TransactionBuilder::TARGET_POSTAGE,
    )
    .unwrap_err()
    .to_string();

    assert!(
      error.contains("wallet contains no cardinal utxos"),
      "{}",
      error
    );
  }

  #[test]
  fn inscribe_with_no_satpoint_and_enough_cardinal_utxos() {
    let utxos = vec![
      (outpoint(1), Amount::from_sat(20_000)),
      (outpoint(2), Amount::from_sat(20_000)),
    ];
    let mut inscriptions = BTreeMap::new();
    inscriptions.insert(
      SatPoint {
        outpoint: outpoint(1),
        offset: 0,
      },
      inscription_id(1),
    );

    let inscription = inscription("text/plain", "ord");
    let satpoint = None;
    let commit_address = change(0);
    let reveal_address = recipient();

    assert!(Inscribe::create_inscription_transactions(
      satpoint,
      inscription,
      inscriptions,
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address, change(1)],
      reveal_address,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      false,
      None,
      None,
      None,
      TransactionBuilder::TARGET_POSTAGE,
    )
    .is_ok())
  }

  #[test]
  fn inscribe_with_custom_fee_rate() {
    let utxos = vec![
      (outpoint(1), Amount::from_sat(10_000)),
      (outpoint(2), Amount::from_sat(20_000)),
    ];
    let mut inscriptions = BTreeMap::new();
    inscriptions.insert(
      SatPoint {
        outpoint: outpoint(1),
        offset: 0,
      },
      inscription_id(1),
    );

    let inscription = inscription("text/plain", "ord");
    let satpoint = None;
    let commit_address = change(0);
    let reveal_address = recipient();
    let fee_rate = 3.3;

    let (commit_tx, reveal_tx, _private_key) = Inscribe::create_inscription_transactions(
      satpoint,
      inscription,
      inscriptions,
      bitcoin::Network::Signet,
      utxos.into_iter().collect(),
      [commit_address, change(1)],
      reveal_address,
      FeeRate::try_from(fee_rate).unwrap(),
      FeeRate::try_from(fee_rate).unwrap(),
      false,
      None,
      None,
      None,
      TransactionBuilder::TARGET_POSTAGE,
    )
    .unwrap();

    let sig_vbytes = 17;
    let fee = FeeRate::try_from(fee_rate)
      .unwrap()
      .fee(commit_tx.vsize() + sig_vbytes)
      .to_sat();

    let reveal_value = commit_tx
      .output
      .iter()
      .map(|o| o.value)
      .reduce(|acc, i| acc + i)
      .unwrap();

    assert_eq!(reveal_value, 20_000 - fee);

    let fee = FeeRate::try_from(fee_rate)
      .unwrap()
      .fee(reveal_tx.vsize())
      .to_sat();

    assert_eq!(
      reveal_tx.output[0].value,
      20_000 - fee - (20_000 - commit_tx.output[0].value),
    );
  }

  #[test]
  fn inscribe_with_commit_fee_rate() {
    let utxos = vec![
      (outpoint(1), Amount::from_sat(10_000)),
      (outpoint(2), Amount::from_sat(20_000)),
    ];
    let mut inscriptions = BTreeMap::new();
    inscriptions.insert(
      SatPoint {
        outpoint: outpoint(1),
        offset: 0,
      },
      inscription_id(1),
    );

    let inscription = inscription("text/plain", "ord");
    let satpoint = None;
    let commit_address = change(0);
    let reveal_address = recipient();
    let commit_fee_rate = 3.3;
    let fee_rate = 1.0;

    let (commit_tx, reveal_tx, _private_key) = Inscribe::create_inscription_transactions(
      satpoint,
      inscription,
      inscriptions,
      bitcoin::Network::Signet,
      utxos.into_iter().collect(),
      [commit_address, change(1)],
      reveal_address,
      FeeRate::try_from(commit_fee_rate).unwrap(),
      FeeRate::try_from(fee_rate).unwrap(),
      false,
      None,
      None,
      None,
      TransactionBuilder::TARGET_POSTAGE,
    )
    .unwrap();

    let sig_vbytes = 17;
    let fee = FeeRate::try_from(commit_fee_rate)
      .unwrap()
      .fee(commit_tx.vsize() + sig_vbytes)
      .to_sat();

    let reveal_value = commit_tx
      .output
      .iter()
      .map(|o| o.value)
      .reduce(|acc, i| acc + i)
      .unwrap();

    assert_eq!(reveal_value, 20_000 - fee);

    let fee = FeeRate::try_from(fee_rate)
      .unwrap()
      .fee(reveal_tx.vsize())
      .to_sat();

    assert_eq!(
      reveal_tx.output[0].value,
      20_000 - fee - (20_000 - commit_tx.output[0].value),
    );
  }

  #[test]
  fn inscribe_over_max_standard_tx_weight() {
    let utxos = vec![(outpoint(1), Amount::from_sat(50 * COIN_VALUE))];

    let inscription = inscription("text/plain", [0; MAX_STANDARD_TX_WEIGHT as usize]);
    let satpoint = None;
    let commit_address = change(0);
    let reveal_address = recipient();

    let error = Inscribe::create_inscription_transactions(
      satpoint,
      inscription,
      BTreeMap::new(),
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address, change(1)],
      reveal_address,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      false,
      None,
      None,
      None,
      TransactionBuilder::TARGET_POSTAGE,
    )
    .unwrap_err()
    .to_string();

    assert!(
      error.contains(&format!("reveal transaction weight greater than {MAX_STANDARD_TX_WEIGHT} (MAX_STANDARD_TX_WEIGHT): 402799")),
      "{}",
      error
    );
  }

  #[test]
  fn inscribe_with_no_max_standard_tx_weight() {
    let utxos = vec![(outpoint(1), Amount::from_sat(50 * COIN_VALUE))];

    let inscription = inscription("text/plain", [0; MAX_STANDARD_TX_WEIGHT as usize]);
    let satpoint = None;
    let commit_address = change(0);
    let reveal_address = recipient();

    let (_commit_tx, reveal_tx, _private_key) = Inscribe::create_inscription_transactions(
      satpoint,
      inscription,
      BTreeMap::new(),
      Network::Bitcoin,
      utxos.into_iter().collect(),
      [commit_address, change(1)],
      reveal_address,
      FeeRate::try_from(1.0).unwrap(),
      FeeRate::try_from(1.0).unwrap(),
      true,
      None,
      None,
      None,
      TransactionBuilder::TARGET_POSTAGE,
    )
    .unwrap();

    assert!(reveal_tx.size() >= MAX_STANDARD_TX_WEIGHT as usize);
  }
}
