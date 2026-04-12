//! `kob-cli estimate-fee` -- Estimate transaction mass and fees before submitting.
//!
//! Computes mass = max(transaction_mass, storage_mass) and the required fee.
//! Storage mass is based on C / value for each output and -C / value credit for each input.
//! Transaction mass accounts for input/output byte sizes.

use clap::Subcommand;
use tracing::error;

/// Storage mass constant C = 4 * 10^12 (Kaspa KIP-0009).
const C: u64 = 4_000_000_000_000;

/// Minimum relay fee (1000 sompi). Nodes reject TXs below this.
const MIN_RELAY_FEE: u64 = 1_000;

/// Fee per gram of mass (1 sompi/gram at minimum relay rate).
const FEE_PER_GRAM: u64 = 1;

/// Base transaction mass overhead (header, lock_time, etc.).
const TX_BASE_MASS: u64 = 68;

/// Mass per input byte (includes outpoint 36B + sequence 8B + sigscript).
const MASS_PER_INPUT_BYTE: u64 = 1;

/// Mass per output byte (includes value 8B + script_version 2B + script).
const MASS_PER_OUTPUT_BYTE: u64 = 1;

/// Mass per signature operation.
const MASS_PER_SIG_OP: u64 = 1000;

/// P2PK sigscript size: [pushData(sig+sighash 65B)] = 66B.
const P2PK_SIGSCRIPT_SIZE: u64 = 66;

/// P2SH overhead per input: outpoint (36B) + sequence (8B) = 44B (sigscript counted separately).
const INPUT_FIXED_SIZE: u64 = 44;

/// Output fixed size: value (8B) + script_version (2B) + script_length varint (1B).
const OUTPUT_FIXED_SIZE: u64 = 11;

/// P2PK scriptPublicKey size: [0x20][pubkey 32B][0xac] = 34 bytes.
const P2PK_SPK_SIZE: u64 = 34;

/// P2SH scriptPublicKey size: [0xaa][0x20][hash 32B][0x87] = 35 bytes.
const P2SH_SPK_SIZE: u64 = 35;


/// buy_order v13 redeemScript: 145B state + 242B body = 387B.
const BUY_RS_SIZE: u64 = 387;
/// sell_order v13 redeemScript: 112B state + 244B body = 356B.
const SELL_RS_SIZE: u64 = 356;
/// bracket_order v4 redeemScript: 238B state + 142B body = 380B.
#[allow(dead_code)] // Kept for fee estimation reference
const BRACKET_RS_SIZE: u64 = 380;
/// oco_pair v4 redeemScript: 181B state + 147B body = 328B.
#[allow(dead_code)] // Kept for fee estimation reference
const OCO_RS_SIZE: u64 = 328;
/// call_option v3 redeemScript: 126B state + 33B body = 159B.
const CALL_OPTION_RS_SIZE: u64 = 159;
/// put_option v4 redeemScript: 159B state + 46B body = 205B.
const PUT_OPTION_RS_SIZE: u64 = 205;


/// buy_v13 fill sigscript: 4 opcodes + pushData(387) = 4 + 3 + 387 = 394.
const BUY_FILL_SS_SIZE: u64 = 394;
/// sell_v13 fill sigscript: 2 opcodes + pushData(356) = 2 + 3 + 356 = 361.
const SELL_FILL_SS_SIZE: u64 = 361;

/// buy_v13 cancel sigscript: 1 + 66 + 33 + 3 + 387 = 490.
const BUY_CANCEL_SS_SIZE: u64 = 490;
/// sell_v13 cancel sigscript: 66 + 33 + 1 + 3 + 356 = 459.
const SELL_CANCEL_SS_SIZE: u64 = 459;

/// buy_v13 partial fill sigscript: 1 + 1 + 9 + 1 + 3 + 387 = 402.
const BUY_PARTIAL_SS_SIZE: u64 = 402;
/// sell_v13 partial fill sigscript: 1 + 1 + 9 + 1 + 3 + 356 = 371.
const SELL_PARTIAL_SS_SIZE: u64 = 371;

/// P2PK wallet input sigscript: pushData(sig+sighash 65B) = 66B.
const WALLET_INPUT_SS_SIZE: u64 = P2PK_SIGSCRIPT_SIZE;

#[derive(Subcommand, Debug)]
pub enum EstimateCommand {
    /// Estimate fee for deploying a buy order.
    DeployBuy {
        /// Amount of KAS to lock (in sompi).
        #[arg(long)]
        amount: u64,
        /// Contract version (only 13 supported).
        #[arg(long, default_value = "13")]
        version: u8,
    },
    /// Estimate fee for deploying a sell order.
    DeploySell {
        /// Amount of tokens to lock (in sompi value).
        #[arg(long)]
        amount: u64,
        /// Contract version (only 13 supported).
        #[arg(long, default_value = "13")]
        version: u8,
    },
    /// Estimate fee for matching a buy and sell order.
    Match {
        /// Buy order value in sompi.
        #[arg(long)]
        buy_value: u64,
        /// Sell order value in sompi.
        #[arg(long)]
        sell_value: u64,
        /// Contract version (only 13 supported).
        #[arg(long, default_value = "13")]
        version: u8,
    },
    /// Estimate fee for a partial fill.
    PartialFill {
        /// Order side: buy or sell.
        #[arg(long)]
        side: String,
        /// Fill amount in sompi (KAS for buy, token value for sell).
        #[arg(long)]
        fill_amount: u64,
        /// Total order value in sompi.
        #[arg(long)]
        order_value: u64,
        /// Contract version (only 13 supported).
        #[arg(long, default_value = "13")]
        version: u8,
    },
    /// Estimate fee for cancelling an order.
    Cancel {
        /// Order side: buy or sell.
        #[arg(long)]
        side: String,
        /// Order UTXO value in sompi.
        #[arg(long)]
        order_value: u64,
        /// Contract version (only 13 supported).
        #[arg(long, default_value = "13")]
        version: u8,
    },
    /// Estimate fee for consolidating multiple UTXOs into one.
    Consolidate {
        /// Number of UTXOs to consolidate.
        #[arg(long)]
        utxo_count: u64,
        /// Total value of all UTXOs being consolidated (in sompi).
        /// Defaults to 10 KAS per UTXO if omitted.
        #[arg(long)]
        total_value: Option<u64>,
    },
    /// Estimate fee for deploying a bracket order (bracket_order_v4, 380B RS).
    Bracket {
        /// Amount to lock in the bracket order (in sompi).
        #[arg(long)]
        amount: u64,
    },
    /// Estimate fee for deploying an OCO pair (oco_pair_v4, 328B RS).
    Oco {
        /// Amount to lock in the OCO order (in sompi).
        #[arg(long)]
        amount: u64,
    },
    /// Estimate fee for deploying an option contract (call or put).
    Option {
        /// Option type: call or put.
        #[arg(long, name = "type")]
        option_type: String,
        /// Amount to lock as collateral (in sompi).
        #[arg(long)]
        amount: u64,
    },
}

// Mass Estimation

/// A single input's contribution to mass calculation.
#[derive(Debug, Clone)]
struct InputEstimate {
    label: String,
    sigscript_size: u64,
    sig_ops: u64,
    value: u64,
}

/// A single output's contribution to mass calculation.
#[derive(Debug, Clone)]
struct OutputEstimate {
    label: String,
    spk_size: u64,
    value: u64,
}

/// Full estimation result for a transaction type.
#[derive(Debug)]
struct FeeEstimate {
    tx_type: String,
    inputs: Vec<InputEstimate>,
    outputs: Vec<OutputEstimate>,
    transaction_mass: u64,
    storage_mass: i64,
    effective_mass: u64,
    required_fee: u64,
}

/// Compute pushData overhead for a given data length.
fn pushdata_overhead(data_len: u64) -> u64 {
    if data_len <= 75 {
        1
    } else if data_len <= 255 {
        2
    } else {
        3
    }
}

/// Compute the size of pushData(data) encoding.
fn pushdata_size(data_len: u64) -> u64 {
    pushdata_overhead(data_len) + data_len
}

/// Compute transaction mass from inputs and outputs.
fn compute_transaction_mass(inputs: &[InputEstimate], outputs: &[OutputEstimate]) -> u64 {
    let mut mass = TX_BASE_MASS;

    for inp in inputs {
        // Input serialized size: fixed + sigscript_size + varint for sigscript length
        let ss_varint = if inp.sigscript_size < 253 { 1 } else { 3 };
        let input_bytes = INPUT_FIXED_SIZE + ss_varint + inp.sigscript_size;
        mass += input_bytes * MASS_PER_INPUT_BYTE;
        mass += inp.sig_ops * MASS_PER_SIG_OP;
    }

    for out in outputs {
        let output_bytes = OUTPUT_FIXED_SIZE + out.spk_size;
        mass += output_bytes * MASS_PER_OUTPUT_BYTE;
    }

    mass
}

/// Compute storage mass from inputs and outputs.
///
/// storage_mass = sum(C / output.value) - sum(C / input.value)
/// Clamped to 0 (negative means net storage reduction).
fn compute_storage_mass(inputs: &[InputEstimate], outputs: &[OutputEstimate]) -> i64 {
    let mut output_mass: i64 = 0;
    for out in outputs {
        if out.value > 0 {
            output_mass += (C / out.value) as i64;
        }
    }

    let mut input_credit: i64 = 0;
    for inp in inputs {
        if inp.value > 0 {
            input_credit += (C / inp.value) as i64;
        }
    }

    output_mass - input_credit
}

/// Build a FeeEstimate from inputs, outputs, and a label.
fn build_estimate(
    tx_type: &str,
    inputs: Vec<InputEstimate>,
    outputs: Vec<OutputEstimate>,
) -> FeeEstimate {
    let transaction_mass = compute_transaction_mass(&inputs, &outputs);
    let storage_mass = compute_storage_mass(&inputs, &outputs);
    // Mempool enforces compute mass only; storage mass affects block template
    // priority but is not required for relay. Use compute mass for fee estimation
    // to match actual deploy/cancel behavior.
    let effective_mass = transaction_mass;
    let fee = std::cmp::max(effective_mass * FEE_PER_GRAM, MIN_RELAY_FEE);

    FeeEstimate {
        tx_type: tx_type.to_string(),
        inputs,
        outputs,
        transaction_mass,
        storage_mass,
        effective_mass,
        required_fee: fee,
    }
}

/// Format a number with thousand separators.
fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

/// Format a signed number with thousand separators.
fn fmt_signed(n: i64) -> String {
    if n < 0 {
        format!("-{}", fmt_num((-n) as u64))
    } else {
        fmt_num(n as u64)
    }
}

/// Print a FeeEstimate in a readable format.
fn print_estimate(est: &FeeEstimate) {
    println!("Transaction: {}", est.tx_type);
    println!("  Inputs:  {}", est.inputs.len());
    println!("  Outputs: {}", est.outputs.len());
    println!();

    println!("  Transaction mass: {} grams", fmt_num(est.transaction_mass));
    if est.storage_mass >= 0 {
        println!("  Storage mass:     {} grams", fmt_num(est.storage_mass as u64));
    } else {
        println!("  Storage mass:     {} grams (net reduction)", fmt_signed(est.storage_mass));
    }
    println!("  Effective mass:   {} grams (max)", fmt_num(est.effective_mass));
    println!("  Required fee:     {} sompi ({:.8} KAS)", fmt_num(est.required_fee), est.required_fee as f64 / 1e8);
    println!();

    // Storage mass breakdown
    println!("  Storage mass breakdown:");
    for (i, out) in est.outputs.iter().enumerate() {
        let sm = if out.value > 0 { C / out.value } else { 0 };
        println!("    Output {} ({}, {} sompi): {} mass",
            i, out.label, fmt_num(out.value), fmt_num(sm));
    }
    for (i, inp) in est.inputs.iter().enumerate() {
        let credit = if inp.value > 0 { C / inp.value } else { 0 };
        if credit > 0 {
            println!("    Input {} credit ({}, {} sompi): -{} mass",
                i, inp.label, fmt_num(inp.value), fmt_num(credit));
        }
    }
    println!();

    // Input detail
    println!("  Input details:");
    for (i, inp) in est.inputs.iter().enumerate() {
        println!("    Input {}: {} (sigscript {}B, {} sigOps, {} sompi)",
            i, inp.label, inp.sigscript_size, inp.sig_ops, fmt_num(inp.value));
    }

    // Output detail
    println!("  Output details:");
    for (i, out) in est.outputs.iter().enumerate() {
        println!("    Output {}: {} (SPK {}B, {} sompi)",
            i, out.label, out.spk_size, fmt_num(out.value));
    }
}

// Estimators for each TX type

fn estimate_deploy_buy(amount: u64, version: u8) -> FeeEstimate {
    let rs_size = BUY_RS_SIZE;
    let label = format!("deploy-buy (v{})", version);

    // Assume 1 wallet input with enough value
    let wallet_value = amount + 10_000; // amount + estimated fee
    let inputs = vec![
        InputEstimate {
            label: "wallet P2PK".to_string(),
            sigscript_size: WALLET_INPUT_SS_SIZE,
            sig_ops: 1,
            value: wallet_value,
        },
    ];

    let outputs = vec![
        OutputEstimate {
            label: "buy_order P2SH".to_string(),
            spk_size: P2SH_SPK_SIZE,
            value: amount,
        },
        OutputEstimate {
            label: "change P2PK".to_string(),
            spk_size: P2PK_SPK_SIZE,
            value: wallet_value - amount, // change = fee placeholder
        },
    ];

    // Note: deploy also carries RS in payload (for order discovery), adding to TX size.
    // Payload mass = pushData(RS) encoded in payload field.
    let _payload_size = pushdata_size(rs_size) + 8; // KOB_PAYLOAD_PREFIX + RS

    build_estimate(&label, inputs, outputs)
}

fn estimate_deploy_sell(amount: u64, version: u8) -> FeeEstimate {
    let _rs_size = SELL_RS_SIZE;
    let label = format!("deploy-sell (v{})", version);

    // Sell deploy: 1 token input (P2SH) + 1 wallet input for fee
    // Actually for initial deploy, the token UTXO comes from a P2PK output
    let wallet_value = amount + 10_000;
    let inputs = vec![
        InputEstimate {
            label: "wallet P2PK (tokens)".to_string(),
            sigscript_size: WALLET_INPUT_SS_SIZE,
            sig_ops: 1,
            value: wallet_value,
        },
    ];

    let outputs = vec![
        OutputEstimate {
            label: "sell_order P2SH".to_string(),
            spk_size: P2SH_SPK_SIZE,
            value: amount,
        },
        OutputEstimate {
            label: "change P2PK".to_string(),
            spk_size: P2PK_SPK_SIZE,
            value: wallet_value - amount,
        },
    ];

    build_estimate(&label, inputs, outputs)
}

fn estimate_match(buy_value: u64, sell_value: u64, version: u8) -> FeeEstimate {
    let buy_ss = BUY_FILL_SS_SIZE;
    let sell_ss = SELL_FILL_SS_SIZE;
    let label = format!("match (v{})", version);

    // Match TX: sell[0] buy[1] fee[2] => outputs: seller_kas[0] buyer_tokens[1] change[2]
    let fee_value = 10_000u64;
    let inputs = vec![
        InputEstimate {
            label: "sell_order P2SH".to_string(),
            sigscript_size: sell_ss,
            sig_ops: 0, // no CheckSig in fill path
            value: sell_value,
        },
        InputEstimate {
            label: "buy_order P2SH".to_string(),
            sigscript_size: buy_ss,
            sig_ops: 0,
            value: buy_value,
        },
        InputEstimate {
            label: "fee P2PK".to_string(),
            sigscript_size: WALLET_INPUT_SS_SIZE,
            sig_ops: 1,
            value: fee_value,
        },
    ];

    // Seller receives KAS, buyer receives tokens, matcher gets change
    let seller_kas = buy_value; // simplified: all buy KAS goes to seller
    let buyer_tokens = sell_value; // simplified: all sell tokens go to buyer
    let outputs = vec![
        OutputEstimate {
            label: "seller KAS P2PK".to_string(),
            spk_size: P2PK_SPK_SIZE,
            value: seller_kas,
        },
        OutputEstimate {
            label: "buyer tokens P2SH".to_string(),
            spk_size: P2SH_SPK_SIZE,
            value: buyer_tokens,
        },
        OutputEstimate {
            label: "matcher change P2PK".to_string(),
            spk_size: P2PK_SPK_SIZE,
            value: fee_value, // approximate
        },
    ];

    build_estimate(&label, inputs, outputs)
}

fn estimate_partial_fill(side: &str, fill_amount: u64, order_value: u64, version: u8) -> FeeEstimate {
    let is_buy = side == "buy";
    let ss_size = if is_buy {
        BUY_PARTIAL_SS_SIZE
    } else {
        SELL_PARTIAL_SS_SIZE
    };
    let label = format!("partial-fill {} (v{})", side, version);

    let fee_value = 10_000u64;
    let residual_value = order_value - fill_amount;

    let mut inputs = vec![
        InputEstimate {
            label: format!("{}_order P2SH", side),
            sigscript_size: ss_size,
            sig_ops: 0,
            value: order_value,
        },
    ];

    if is_buy {
        // Buy partial fill needs a token input from the filler
        inputs.push(InputEstimate {
            label: "token P2SH".to_string(),
            sigscript_size: WALLET_INPUT_SS_SIZE,
            sig_ops: 1,
            value: fill_amount, // token value
        });
    }

    inputs.push(InputEstimate {
        label: "fee P2PK".to_string(),
        sigscript_size: WALLET_INPUT_SS_SIZE,
        sig_ops: 1,
        value: fee_value,
    });

    let mut outputs = vec![
        OutputEstimate {
            label: format!("residual {} P2SH", side),
            spk_size: P2SH_SPK_SIZE,
            value: residual_value,
        },
    ];

    if is_buy {
        outputs.push(OutputEstimate {
            label: "buyer tokens P2SH".to_string(),
            spk_size: P2SH_SPK_SIZE,
            value: fill_amount,
        });
        outputs.push(OutputEstimate {
            label: "seller KAS P2PK".to_string(),
            spk_size: P2PK_SPK_SIZE,
            value: fill_amount,
        });
    } else {
        outputs.push(OutputEstimate {
            label: "seller KAS P2PK".to_string(),
            spk_size: P2PK_SPK_SIZE,
            value: fill_amount,
        });
        outputs.push(OutputEstimate {
            label: "buyer tokens P2SH".to_string(),
            spk_size: P2SH_SPK_SIZE,
            value: fill_amount,
        });
    }

    outputs.push(OutputEstimate {
        label: "change P2PK".to_string(),
        spk_size: P2PK_SPK_SIZE,
        value: fee_value,
    });

    build_estimate(&label, inputs, outputs)
}

fn estimate_cancel(side: &str, order_value: u64, version: u8) -> FeeEstimate {
    let is_buy = side == "buy";
    let ss_size = if is_buy {
        BUY_CANCEL_SS_SIZE
    } else {
        SELL_CANCEL_SS_SIZE
    };
    let label = format!("cancel {} (v{})", side, version);

    let inputs = vec![
        InputEstimate {
            label: format!("{}_order P2SH", side),
            sigscript_size: ss_size,
            sig_ops: 1, // cancel path has CheckSigVerify
            value: order_value,
        },
    ];

    // Cancel returns value to owner minus fee
    let return_value = order_value.saturating_sub(10_000);
    let outputs = vec![
        OutputEstimate {
            label: "owner P2PK".to_string(),
            spk_size: P2PK_SPK_SIZE,
            value: return_value,
        },
    ];

    build_estimate(&label, inputs, outputs)
}

fn estimate_consolidate(utxo_count: u64, total_value: Option<u64>) -> FeeEstimate {
    let per_utxo_value = 10_000_000_000u64; // 100 KAS default
    let total = total_value.unwrap_or(utxo_count * per_utxo_value);
    let per_value = total / utxo_count;
    let label = format!("consolidate ({} UTXOs)", utxo_count);

    let inputs: Vec<InputEstimate> = (0..utxo_count)
        .map(|i| InputEstimate {
            label: format!("wallet P2PK #{}", i),
            sigscript_size: WALLET_INPUT_SS_SIZE,
            sig_ops: 1,
            value: per_value,
        })
        .collect();

    let fee_estimate = utxo_count * 200 + 1000; // rough estimate for mass
    let output_value = total.saturating_sub(fee_estimate);
    let outputs = vec![
        OutputEstimate {
            label: "consolidated P2PK".to_string(),
            spk_size: P2PK_SPK_SIZE,
            value: output_value,
        },
    ];

    build_estimate(&label, inputs, outputs)
}

fn estimate_bracket(amount: u64) -> FeeEstimate {
    let label = "deploy-bracket (v4)".to_string();
    let wallet_value = amount + 10_000;
    let inputs = vec![InputEstimate {
        label: "wallet P2PK".to_string(),
        sigscript_size: WALLET_INPUT_SS_SIZE,
        sig_ops: 1,
        value: wallet_value,
    }];
    let outputs = vec![
        OutputEstimate {
            label: "bracket_order P2SH".to_string(),
            spk_size: P2SH_SPK_SIZE,
            value: amount,
        },
        OutputEstimate {
            label: "change P2PK".to_string(),
            spk_size: P2PK_SPK_SIZE,
            value: wallet_value - amount,
        },
    ];
    build_estimate(&label, inputs, outputs)
}

fn estimate_oco(amount: u64) -> FeeEstimate {
    let label = "deploy-oco (v4)".to_string();
    let wallet_value = amount + 10_000;
    let inputs = vec![InputEstimate {
        label: "wallet P2PK".to_string(),
        sigscript_size: WALLET_INPUT_SS_SIZE,
        sig_ops: 1,
        value: wallet_value,
    }];
    let outputs = vec![
        OutputEstimate {
            label: "oco_pair P2SH".to_string(),
            spk_size: P2SH_SPK_SIZE,
            value: amount,
        },
        OutputEstimate {
            label: "change P2PK".to_string(),
            spk_size: P2PK_SPK_SIZE,
            value: wallet_value - amount,
        },
    ];
    build_estimate(&label, inputs, outputs)
}

fn estimate_option(option_type: &str, amount: u64) -> FeeEstimate {
    let is_call = option_type == "call";
    let rs_size = if is_call { CALL_OPTION_RS_SIZE } else { PUT_OPTION_RS_SIZE };
    let label = format!("deploy-option {} ({}B RS)", option_type, rs_size);
    let wallet_value = amount + 10_000;
    let inputs = vec![InputEstimate {
        label: "wallet P2PK".to_string(),
        sigscript_size: WALLET_INPUT_SS_SIZE,
        sig_ops: 1,
        value: wallet_value,
    }];
    let outputs = vec![
        OutputEstimate {
            label: format!("{}_option P2SH", option_type),
            spk_size: P2SH_SPK_SIZE,
            value: amount,
        },
        OutputEstimate {
            label: "change P2PK".to_string(),
            spk_size: P2PK_SPK_SIZE,
            value: wallet_value - amount,
        },
    ];
    build_estimate(&label, inputs, outputs)
}

// Public Entry Point

/// Run the estimate-fee command (no network/wallet needed).
pub fn run(cmd: &EstimateCommand) {
    let estimate = match cmd {
        EstimateCommand::DeployBuy { amount, version } => {
            validate_version(*version);
            estimate_deploy_buy(*amount, *version)
        }
        EstimateCommand::DeploySell { amount, version } => {
            validate_version(*version);
            estimate_deploy_sell(*amount, *version)
        }
        EstimateCommand::Match { buy_value, sell_value, version } => {
            validate_version(*version);
            estimate_match(*buy_value, *sell_value, *version)
        }
        EstimateCommand::PartialFill { side, fill_amount, order_value, version } => {
            validate_version(*version);
            validate_side(side);
            if *fill_amount >= *order_value {
                error!("fill_amount ({}) must be less than order_value ({})", fill_amount, order_value);
                std::process::exit(1);
            }
            estimate_partial_fill(side, *fill_amount, *order_value, *version)
        }
        EstimateCommand::Cancel { side, order_value, version } => {
            validate_version(*version);
            validate_side(side);
            estimate_cancel(side, *order_value, *version)
        }
        EstimateCommand::Consolidate { utxo_count, total_value } => {
            if *utxo_count == 0 {
                error!("utxo_count must be > 0");
                std::process::exit(1);
            }
            estimate_consolidate(*utxo_count, *total_value)
        }
        EstimateCommand::Bracket { amount } => {
            if *amount == 0 {
                error!("amount must be > 0");
                std::process::exit(1);
            }
            estimate_bracket(*amount)
        }
        EstimateCommand::Oco { amount } => {
            if *amount == 0 {
                error!("amount must be > 0");
                std::process::exit(1);
            }
            estimate_oco(*amount)
        }
        EstimateCommand::Option { option_type, amount } => {
            if option_type != "call" && option_type != "put" {
                error!("option type must be 'call' or 'put', got '{}'", option_type);
                std::process::exit(1);
            }
            if *amount == 0 {
                error!("amount must be > 0");
                std::process::exit(1);
            }
            estimate_option(option_type, *amount)
        }
    };

    print_estimate(&estimate);
}

fn validate_version(version: u8) {
    if version != 6 && version != 8 && version != 9 && version != 10 && version != 11 && version != 12 && version != 13 && version != 14 {
        error!("unsupported contract version {}. Use 6, 8, 9, 10, 11, 12, 13, or 14.", version);
        std::process::exit(1);
    }
    if version != 14 {
        eprintln!("WARNING: Only contract version 14 is supported. Got v{}.", version);
    }
}

fn validate_side(side: &str) {
    if side != "buy" && side != "sell" {
        error!("side must be 'buy' or 'sell', got '{}'", side);
        std::process::exit(1);
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;


    #[test]
    fn storage_mass_basic() {
        // Single output of 10M sompi
        let outputs = vec![OutputEstimate {
            label: "test".to_string(),
            spk_size: P2SH_SPK_SIZE,
            value: 10_000_000,
        }];
        let inputs = vec![];
        let sm = compute_storage_mass(&inputs, &outputs);
        // C / 10M = 4e12 / 1e7 = 400_000
        assert_eq!(sm, 400_000);
    }

    #[test]
    fn storage_mass_with_input_credit() {
        let outputs = vec![OutputEstimate {
            label: "out".to_string(),
            spk_size: P2SH_SPK_SIZE,
            value: 10_000_000,
        }];
        let inputs = vec![InputEstimate {
            label: "in".to_string(),
            sigscript_size: 66,
            sig_ops: 1,
            value: 10_000_000,
        }];
        let sm = compute_storage_mass(&inputs, &outputs);
        // Same value in and out: net zero
        assert_eq!(sm, 0);
    }

    #[test]
    fn storage_mass_net_negative() {
        // Consuming a small UTXO, creating a large output
        let outputs = vec![OutputEstimate {
            label: "out".to_string(),
            spk_size: P2PK_SPK_SIZE,
            value: 1_000_000_000_000, // 10,000 KAS
        }];
        let inputs = vec![InputEstimate {
            label: "in".to_string(),
            sigscript_size: 66,
            sig_ops: 1,
            value: 5_000_000, // 0.05 KAS
        }];
        let sm = compute_storage_mass(&inputs, &outputs);
        // output: C / 1e12 = 4, input credit: C / 5e6 = 800_000
        // Net: 4 - 800_000 = -799_996
        assert_eq!(sm, 4 - 800_000);
    }

    #[test]
    fn storage_mass_very_small_output() {
        // Minimum UTXO ~3M sompi
        let outputs = vec![OutputEstimate {
            label: "dust".to_string(),
            spk_size: P2SH_SPK_SIZE,
            value: 3_000_000,
        }];
        let inputs = vec![];
        let sm = compute_storage_mass(&inputs, &outputs);
        // C / 3M = 4e12 / 3e6 = 1_333_333
        assert_eq!(sm, 1_333_333);
    }

    #[test]
    fn storage_mass_large_output() {
        // 1000 KAS output
        let outputs = vec![OutputEstimate {
            label: "big".to_string(),
            spk_size: P2PK_SPK_SIZE,
            value: 100_000_000_000, // 1000 KAS
        }];
        let inputs = vec![];
        let sm = compute_storage_mass(&inputs, &outputs);
        // C / 1e11 = 40
        assert_eq!(sm, 40);
    }


    #[test]
    fn tx_mass_simple_p2pk() {
        // 1 input, 1 output, P2PK
        let inputs = vec![InputEstimate {
            label: "wallet".to_string(),
            sigscript_size: 66,
            sig_ops: 1,
            value: 10_000_000,
        }];
        let outputs = vec![OutputEstimate {
            label: "recipient".to_string(),
            spk_size: P2PK_SPK_SIZE,
            value: 9_990_000,
        }];
        let tm = compute_transaction_mass(&inputs, &outputs);
        // base(68) + input(44 + 1 + 66 = 111) + sigop(1000) + output(11 + 34 = 45) = 1224
        assert_eq!(tm, 68 + 111 + 1000 + 45);
    }

    #[test]
    fn tx_mass_match_v12() {
        // Match TX: sell + buy + fee inputs, 3 outputs
        let inputs = vec![
            InputEstimate {
                label: "sell".to_string(),
                sigscript_size: SELL_FILL_SS_SIZE,
                sig_ops: 0,
                value: 10_000_000,
            },
            InputEstimate {
                label: "buy".to_string(),
                sigscript_size: BUY_FILL_SS_SIZE,
                sig_ops: 0,
                value: 50_000_000,
            },
            InputEstimate {
                label: "fee".to_string(),
                sigscript_size: 66,
                sig_ops: 1,
                value: 10_000,
            },
        ];
        let outputs = vec![
            OutputEstimate { label: "o0".to_string(), spk_size: P2PK_SPK_SIZE, value: 50_000_000 },
            OutputEstimate { label: "o1".to_string(), spk_size: P2SH_SPK_SIZE, value: 10_000_000 },
            OutputEstimate { label: "o2".to_string(), spk_size: P2PK_SPK_SIZE, value: 10_000 },
        ];
        let tm = compute_transaction_mass(&inputs, &outputs);
        // Sell input: 44 + 3 + 361 = 408 (>253 so varint = 3)
        // Buy input: 44 + 3 + 394 = 441 (>253 so varint = 3)
        // Fee input: 44 + 1 + 66 = 111
        // SigOps: 1 * 1000 = 1000
        // Outputs: (11+34) + (11+35) + (11+34) = 45 + 46 + 45 = 136
        // Total: 68 + 408 + 441 + 111 + 1000 + 136 = 2164
        assert_eq!(tm, 68 + 408 + 441 + 111 + 1000 + 136);
    }


    #[test]
    fn effective_mass_compute_only() {
        let est = estimate_deploy_buy(3_000_000, 8);
        // Effective mass uses compute mass only (mempool enforces compute mass;
        // storage mass affects block template priority only).
        assert_eq!(est.effective_mass, est.transaction_mass,
            "effective mass should equal compute mass, not max(compute, storage)");
        // Storage mass is still computed for informational display
        assert!(est.storage_mass > 0, "storage mass should be positive for small output");
    }

    #[test]
    fn effective_mass_tx_dominant() {
        // Use a consolidation TX with large UTXOs: storage mass is net negative (consuming many, creating one)
        let est = estimate_consolidate(10, Some(100_000_000_000));
        // Consuming 10 UTXOs of 10 KAS each into 1 big output: storage mass is negative
        assert!(est.storage_mass <= 0,
            "storage mass should be negative for consolidation of large UTXOs: storage={}", est.storage_mass);
        assert!(est.transaction_mass > 0, "tx mass should be positive");
        // Effective mass always equals compute mass (storage mass is informational only)
        assert_eq!(est.effective_mass, est.transaction_mass,
            "effective mass should equal compute mass");
    }


    #[test]
    fn fee_minimum_enforced() {
        // A cancel of a large UTXO: low mass, should still be >= MIN_RELAY_FEE
        let est = estimate_cancel("buy", 100_000_000_000, 8);
        assert!(est.required_fee >= MIN_RELAY_FEE,
            "fee must be >= MIN_RELAY_FEE ({}), got {}", MIN_RELAY_FEE, est.required_fee);
    }


    #[test]
    fn deploy_buy_v8_produces_estimate() {
        let est = estimate_deploy_buy(10_000_000, 8);
        assert_eq!(est.inputs.len(), 1);
        assert_eq!(est.outputs.len(), 2);
        assert!(est.required_fee > 0);
        assert!(est.transaction_mass > 0);
    }

    #[test]
    fn deploy_buy_v6_produces_estimate() {
        let est = estimate_deploy_buy(10_000_000, 6);
        assert_eq!(est.inputs.len(), 1);
        assert_eq!(est.outputs.len(), 2);
        assert!(est.required_fee > 0);
    }

    #[test]
    fn deploy_sell_v8_produces_estimate() {
        let est = estimate_deploy_sell(10_000_000, 8);
        assert_eq!(est.inputs.len(), 1);
        assert_eq!(est.outputs.len(), 2);
        assert!(est.required_fee > 0);
    }

    #[test]
    fn match_v8_produces_estimate() {
        let est = estimate_match(50_000_000, 10_000_000, 8);
        assert_eq!(est.inputs.len(), 3);
        assert_eq!(est.outputs.len(), 3);
        assert!(est.required_fee > 0);
    }

    #[test]
    fn match_v6_produces_estimate() {
        let est = estimate_match(50_000_000, 10_000_000, 6);
        assert_eq!(est.inputs.len(), 3);
        assert_eq!(est.outputs.len(), 3);
        assert!(est.required_fee > 0);
    }

    #[test]
    fn partial_fill_buy_produces_estimate() {
        let est = estimate_partial_fill("buy", 5_000_000, 10_000_000, 8);
        assert_eq!(est.inputs.len(), 3); // order + token + fee
        assert_eq!(est.outputs.len(), 4); // residual + tokens + KAS + change
        assert!(est.required_fee > 0);
    }

    #[test]
    fn partial_fill_sell_produces_estimate() {
        let est = estimate_partial_fill("sell", 5_000_000, 10_000_000, 8);
        assert_eq!(est.inputs.len(), 2); // order + fee
        assert_eq!(est.outputs.len(), 4); // residual + KAS + tokens + change
        assert!(est.required_fee > 0);
    }

    #[test]
    fn cancel_buy_produces_estimate() {
        let est = estimate_cancel("buy", 10_000_000, 8);
        assert_eq!(est.inputs.len(), 1);
        assert_eq!(est.outputs.len(), 1);
        assert!(est.required_fee > 0);
    }

    #[test]
    fn cancel_sell_produces_estimate() {
        let est = estimate_cancel("sell", 10_000_000, 6);
        assert_eq!(est.inputs.len(), 1);
        assert_eq!(est.outputs.len(), 1);
        assert!(est.required_fee > 0);
    }

    #[test]
    fn consolidate_produces_estimate() {
        let est = estimate_consolidate(10, None);
        assert_eq!(est.inputs.len(), 10);
        assert_eq!(est.outputs.len(), 1);
        assert!(est.required_fee > 0);
    }

    #[test]
    fn consolidate_with_custom_value() {
        let est = estimate_consolidate(5, Some(500_000_000));
        assert_eq!(est.inputs.len(), 5);
        assert_eq!(est.outputs.len(), 1);
        assert!(est.required_fee > 0);
    }


    #[test]
    fn very_small_output_high_storage_mass() {
        // Minimum UTXO value: storage mass should be significant
        let est = estimate_deploy_buy(3_000_000, 8);
        // C / 3M = 1_333_333 for the order output alone
        assert!(est.storage_mass >= 1_333_333,
            "expected high storage mass for 3M sompi output, got {}", est.storage_mass);
    }

    #[test]
    fn very_large_output_minimal_storage_mass() {
        // Direct storage mass calculation for a single large output
        let outputs = vec![OutputEstimate {
            label: "big".to_string(),
            spk_size: P2PK_SPK_SIZE,
            value: 1_000_000_000_000, // 10000 KAS
        }];
        let inputs = vec![];
        let sm = compute_storage_mass(&inputs, &outputs);
        // C / 1e12 = 4
        assert_eq!(sm, 4, "expected storage mass = 4 for 10000 KAS output, got {}", sm);
    }


    #[test]
    fn fmt_num_formatting() {
        assert_eq!(fmt_num(0), "0");
        assert_eq!(fmt_num(999), "999");
        assert_eq!(fmt_num(1000), "1,000");
        assert_eq!(fmt_num(1_000_000), "1,000,000");
        assert_eq!(fmt_num(4_000_000_000_000), "4,000,000,000,000");
    }

    #[test]
    fn fmt_signed_formatting() {
        assert_eq!(fmt_signed(0), "0");
        assert_eq!(fmt_signed(1000), "1,000");
        assert_eq!(fmt_signed(-1000), "-1,000");
        assert_eq!(fmt_signed(-800_000), "-800,000");
    }

    #[test]
    fn pushdata_overhead_values() {
        assert_eq!(pushdata_overhead(10), 1);
        assert_eq!(pushdata_overhead(75), 1);
        assert_eq!(pushdata_overhead(76), 2);
        assert_eq!(pushdata_overhead(255), 2);
        assert_eq!(pushdata_overhead(256), 3);
        assert_eq!(pushdata_overhead(354), 3);
    }

    #[test]
    fn pushdata_size_matches_primitives() {
        // Verify our size calculation matches the actual push_data encoding
        use kob_core::primitives::push_data;

        let test_sizes = [10, 50, 75, 76, 100, 200, 255, 256, 287, 348, 354, 380];
        for &sz in &test_sizes {
            let data = vec![0u8; sz];
            let encoded = push_data(&data);
            assert_eq!(
                pushdata_size(sz as u64),
                encoded.len() as u64,
                "pushdata_size mismatch for data length {}",
                sz
            );
        }
    }


    #[test]
    fn buy_v12_fill_ss_size_matches() {
        use kob_core::contract::{build_buy_redeem_script, build_buy_fill_sigscript};
        let tcid = [0u8; 32];
        let owner = [0u8; 32];
        let bspkh = [0u8; 32];
        let rs = build_buy_redeem_script(&tcid, 1, 2, 1000, &owner, &bspkh, 0, 0, 0).unwrap();
        let ss = build_buy_fill_sigscript(1, 1, 0, &rs);
        assert!(BUY_FILL_SS_SIZE >= ss.len() as u64,
            "BUY_FILL_SS_SIZE ({}) < actual ({})", BUY_FILL_SS_SIZE, ss.len());
    }

    #[test]
    fn sell_v12_fill_ss_size_matches() {
        use kob_core::contract::{build_sell_redeem_script, build_sell_fill_sigscript};
        let owner = [0u8; 32];
        let sspkh = [0u8; 32];
        let rs = build_sell_redeem_script(1, 2, 1000, &owner, &sspkh, 0, 0, 0).unwrap();
        let ss = build_sell_fill_sigscript(0, &rs);
        assert!(SELL_FILL_SS_SIZE >= ss.len() as u64,
            "SELL_FILL_SS_SIZE ({}) < actual ({})", SELL_FILL_SS_SIZE, ss.len());
    }

    #[test]
    fn buy_v12_rs_size_matches() {
        use kob_core::contract::build_buy_redeem_script;
        let tcid = [0u8; 32];
        let owner = [0u8; 32];
        let bspkh = [0u8; 32];
        let rs = build_buy_redeem_script(&tcid, 1, 2, 1000, &owner, &bspkh, 0, 0, 0).unwrap();
        assert_eq!(BUY_RS_SIZE, rs.len() as u64,
            "BUY_RS_SIZE ({}) != actual ({})", BUY_RS_SIZE, rs.len());
    }

    #[test]
    fn sell_v12_rs_size_matches() {
        use kob_core::contract::build_sell_redeem_script;
        let owner = [0u8; 32];
        let sspkh = [0u8; 32];
        let rs = build_sell_redeem_script(1, 2, 1000, &owner, &sspkh, 0, 0, 0).unwrap();
        assert_eq!(SELL_RS_SIZE, rs.len() as u64,
            "SELL_RS_SIZE ({}) != actual ({})", SELL_RS_SIZE, rs.len());
    }


    #[test]
    fn buy_v12_cancel_ss_size_matches() {
        use kob_core::contract::{build_buy_redeem_script, build_buy_cancel_sigscript};
        let tcid = [0u8; 32];
        let owner = [0u8; 32];
        let bspkh = [0u8; 32];
        let rs = build_buy_redeem_script(&tcid, 1, 2, 1000, &owner, &bspkh, 0, 0, 0).unwrap();
        let sig = [0u8; 64];
        let pubkey = [0u8; 32];
        let ss = build_buy_cancel_sigscript(&sig, &pubkey, &rs);
        assert_eq!(BUY_CANCEL_SS_SIZE, ss.len() as u64,
            "BUY_CANCEL_SS_SIZE ({}) != actual ({})", BUY_CANCEL_SS_SIZE, ss.len());
    }

    #[test]
    fn sell_v12_cancel_ss_size_matches() {
        use kob_core::contract::{build_sell_redeem_script, build_sell_cancel_sigscript};
        let owner = [0u8; 32];
        let sspkh = [0u8; 32];
        let rs = build_sell_redeem_script(1, 2, 1000, &owner, &sspkh, 0, 0, 0).unwrap();
        let sig = [0u8; 64];
        let pubkey = [0u8; 32];
        let ss = build_sell_cancel_sigscript(&sig, &pubkey, &rs);
        assert_eq!(SELL_CANCEL_SS_SIZE, ss.len() as u64,
            "SELL_CANCEL_SS_SIZE ({}) != actual ({})", SELL_CANCEL_SS_SIZE, ss.len());
    }


    #[test]
    fn buy_v12_partial_ss_size_matches() {
        use kob_core::contract::{build_buy_redeem_script, build_buy_partial_fill_sigscript};
        let tcid = [0u8; 32];
        let owner = [0u8; 32];
        let bspkh = [0u8; 32];
        let rs = build_buy_redeem_script(&tcid, 1, 2, 1000, &owner, &bspkh, 0, 0, 0).unwrap();
        let ss = build_buy_partial_fill_sigscript(&rs, 5_000_000, 2, 1);
        assert_eq!(BUY_PARTIAL_SS_SIZE, ss.len() as u64,
            "BUY_PARTIAL_SS_SIZE ({}) != actual ({})", BUY_PARTIAL_SS_SIZE, ss.len());
    }

    #[test]
    fn sell_v12_partial_ss_size_matches() {
        use kob_core::contract::{build_sell_redeem_script, build_sell_partial_fill_sigscript};
        let owner = [0u8; 32];
        let sspkh = [0u8; 32];
        let rs = build_sell_redeem_script(1, 2, 1000, &owner, &sspkh, 0, 0, 0).unwrap();
        let ss = build_sell_partial_fill_sigscript(&rs, 5_000_000, 0, 2);
        assert_eq!(SELL_PARTIAL_SS_SIZE, ss.len() as u64,
            "SELL_PARTIAL_SS_SIZE ({}) != actual ({})", SELL_PARTIAL_SS_SIZE, ss.len());
    }


    #[test]
    fn bracket_produces_estimate() {
        let est = estimate_bracket(10_000_000);
        assert_eq!(est.inputs.len(), 1);
        assert_eq!(est.outputs.len(), 2);
        assert!(est.required_fee > 0);
    }

    #[test]
    fn bracket_small_amount_high_storage_mass() {
        let est = estimate_bracket(3_000_000);
        assert!(est.storage_mass >= 1_333_333);
    }

    #[test]
    fn bracket_large_amount_has_estimate() {
        let est = estimate_bracket(100_000_000_000);
        assert!(est.required_fee > 0);
        // Large order output has low storage mass (C/100B=40), but change
        // output at 10_000 sompi has high storage mass (C/10_000=400M).
        assert!(est.required_fee >= MIN_RELAY_FEE);
    }


    #[test]
    fn oco_produces_estimate() {
        let est = estimate_oco(10_000_000);
        assert_eq!(est.inputs.len(), 1);
        assert_eq!(est.outputs.len(), 2);
        assert!(est.required_fee > 0);
    }

    #[test]
    fn oco_small_amount() {
        let est = estimate_oco(3_000_000);
        assert!(est.storage_mass >= 1_333_333);
    }

    #[test]
    fn oco_rs_size_constant() {
        use kob_core::contract::build_oco_pair_redeem_script;
        let nonce = [0u8; 32];
        let tcid = [0u8; 32];
        let ohash = [0u8; 32];
        let ospk = [0u8; 36];
        let rs = build_oco_pair_redeem_script(&nonce, 0, &tcid, 1, 2, 1, 1000, &ohash, &ospk).unwrap();
        assert_eq!(OCO_RS_SIZE, rs.len() as u64,
            "OCO_RS_SIZE ({}) != actual ({})", OCO_RS_SIZE, rs.len());
    }


    #[test]
    fn option_call_produces_estimate() {
        let est = estimate_option("call", 10_000_000);
        assert_eq!(est.inputs.len(), 1);
        assert_eq!(est.outputs.len(), 2);
        assert!(est.required_fee > 0);
        assert!(est.tx_type.contains("call"));
    }

    #[test]
    fn option_put_produces_estimate() {
        let est = estimate_option("put", 10_000_000);
        assert_eq!(est.inputs.len(), 1);
        assert_eq!(est.outputs.len(), 2);
        assert!(est.required_fee > 0);
        assert!(est.tx_type.contains("put"));
    }

    #[test]
    fn option_call_rs_size_constant() {
        use kob_core::contract::build_call_option_redeem_script;
        let writer = [0u8; 32];
        let holder = [0u8; 32];
        let wspk = [0u8; 32];
        let rs = build_call_option_redeem_script(&writer, &holder, 1_000_000, &wspk, 0, u64::MAX).unwrap();
        assert_eq!(CALL_OPTION_RS_SIZE, rs.len() as u64,
            "CALL_OPTION_RS_SIZE ({}) != actual ({})", CALL_OPTION_RS_SIZE, rs.len());
    }

    #[test]
    fn option_put_rs_size_constant() {
        use kob_core::contract::build_put_option_redeem_script;
        let writer = [0u8; 32];
        let holder = [0u8; 32];
        let tcid = [0u8; 32];
        let wspk = [0u8; 32];
        let rs = build_put_option_redeem_script(&writer, &holder, 1_000_000, &tcid, &wspk, 0, u64::MAX).unwrap();
        assert_eq!(PUT_OPTION_RS_SIZE, rs.len() as u64,
            "PUT_OPTION_RS_SIZE ({}) != actual ({})", PUT_OPTION_RS_SIZE, rs.len());
    }

    #[test]
    fn option_call_small_amount() {
        let est = estimate_option("call", 3_000_000);
        assert!(est.storage_mass >= 1_333_333);
        assert!(est.required_fee >= MIN_RELAY_FEE);
    }

    #[test]
    fn option_put_large_amount() {
        let est = estimate_option("put", 100_000_000_000);
        assert!(est.required_fee > 0);
        // Storage mass dominated by small change output
        assert!(est.required_fee >= MIN_RELAY_FEE);
    }

    #[test]
    fn bracket_v4_rs_size_constant() {
        use kob_core::contract::build_bracket_redeem_script;
        let tcid = [0u8; 32];
        let tp_spk = [0u8; 37];
        let sl_spk = [0u8; 37];
        let rcid = [0u8; 32];
        let ohash = [0u8; 32];
        let rs = build_bracket_redeem_script(
            0, &tcid, 1, 2, &tp_spk, 1000, &sl_spk, 1000, 100, 1000, &rcid, &ohash,
        ).unwrap();
        assert_eq!(BRACKET_RS_SIZE, rs.len() as u64,
            "BRACKET_RS_SIZE ({}) != actual ({})", BRACKET_RS_SIZE, rs.len());
    }
}
