//! Smart market order support with trustless-first price discovery.
//!
//! Priority order:
//! 1. **Node fill TX scan** (trustless) — scan recent blocks for v18 fill TXs
//! 2. **External Matcher API** (trust required) — only if `--matcher-url` is
//!    explicitly provided AND no fills found on-chain
//! 3. **Error** — if neither source has price data
//!
//! The Matcher API endpoint used is `GET /api/v1/depth?pair=<token>&limit=100`,
//! which returns `{ bids: [[price, qty], ...], asks: [[price, qty], ...] }`.

use serde::Deserialize;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Default slippage in basis points (100 = 1%).
pub const DEFAULT_SLIPPAGE_BPS: u64 = 100;

/// A price level from the Matcher depth API.
#[derive(Debug, Clone)]
pub struct DepthLevel {
    /// Price as a decimal string (e.g. "0.500000").
    pub price: f64,
    /// Quantity in sompi.
    pub quantity: u64,
}

/// Response from the Matcher `/api/v1/depth` endpoint.
#[derive(Debug, Deserialize)]
struct DepthResponse {
    bids: Vec<[String; 2]>,
    asks: Vec<[String; 2]>,
}

/// Result of market price calculation.
#[derive(Debug, Clone)]
pub struct MarketPriceResult {
    /// Calculated limit price numerator.
    pub price_num: u64,
    /// Calculated limit price denominator.
    pub price_den: u64,
    /// Worst execution price (before slippage).
    pub worst_price: f64,
    /// Final price (after slippage).
    pub final_price: f64,
    /// Total depth consumed.
    pub depth_consumed: u64,
    /// Number of price levels consumed.
    pub levels_consumed: usize,
}

/// Fetch the order book depth from the Matcher API.
///
/// `matcher_url`: e.g. "http://127.0.0.1:8080"
/// `token`: token covenant ID (used as the pair parameter)
pub fn fetch_depth(matcher_url: &str, token: &str) -> anyhow::Result<(Vec<DepthLevel>, Vec<DepthLevel>)> {
    let url_str = format!("{}/api/v1/depth?pair={}&limit=100", matcher_url.trim_end_matches('/'), token);

    // Parse URL to extract host, port, path
    let url_str = if !url_str.starts_with("http://") && !url_str.starts_with("https://") {
        format!("http://{}", url_str)
    } else {
        url_str
    };

    if url_str.starts_with("https://") {
        anyhow::bail!("HTTPS not supported for Matcher API. Use http://");
    }

    let without_scheme = url_str.strip_prefix("http://").expect("url_str always has http:// prefix");
    let (host_port, path) = match without_scheme.find('/') {
        Some(idx) => (&without_scheme[..idx], &without_scheme[idx..]),
        None => (without_scheme, "/"),
    };

    let (host, port) = match host_port.find(':') {
        Some(idx) => (&host_port[..idx], host_port[idx + 1..].parse::<u16>().unwrap_or(80)),
        None => (host_port, 80u16),
    };

    // Connect with timeout
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(
        &addr.parse().map_err(|e| anyhow::anyhow!("Invalid Matcher address '{}': {}", addr, e))?,
        Duration::from_secs(5),
    ).map_err(|e| {
        anyhow::anyhow!(
            "Market orders require a running Matcher. Could not connect to {}: {}. \
             Use --matcher-url or deploy a limit order instead.",
            matcher_url, e
        )
    })?;

    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    // Send HTTP GET
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: application/json\r\n\r\n",
        path, host_port
    );
    stream.write_all(request.as_bytes())?;

    // Read response
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;

    let response_str = String::from_utf8_lossy(&response);

    // Parse HTTP response: find body after \r\n\r\n
    let body = response_str
        .find("\r\n\r\n")
        .map(|idx| &response_str[idx + 4..])
        .ok_or_else(|| anyhow::anyhow!("Invalid HTTP response from Matcher"))?;

    // Check for HTTP error status
    let status_line = response_str.lines().next().unwrap_or("");
    if !status_line.contains("200") {
        anyhow::bail!(
            "Matcher API returned error: {}. Ensure the token pair '{}' exists on the order book.",
            status_line.trim(), token
        );
    }

    // Handle chunked transfer encoding
    let body_str = if response_str.contains("Transfer-Encoding: chunked") {
        decode_chunked(body)?
    } else {
        body.to_string()
    };

    let depth: DepthResponse = serde_json::from_str(&body_str).map_err(|e| {
        anyhow::anyhow!("Failed to parse Matcher depth response: {}. Body: {}", e, &body_str[..body_str.len().min(200)])
    })?;

    let bids = parse_levels(&depth.bids)?;
    let asks = parse_levels(&depth.asks)?;

    Ok((bids, asks))
}

/// Decode HTTP chunked transfer encoding.
fn decode_chunked(body: &str) -> anyhow::Result<String> {
    let mut result = String::new();
    let mut remaining = body;

    loop {
        // Skip leading whitespace/newlines
        remaining = remaining.trim_start();
        if remaining.is_empty() {
            break;
        }

        // Read chunk size (hex)
        let size_end = remaining.find("\r\n").unwrap_or(remaining.len());
        let size_str = remaining[..size_end].trim();
        if size_str.is_empty() {
            break;
        }
        let chunk_size = usize::from_str_radix(size_str, 16)
            .map_err(|e| anyhow::anyhow!("Invalid chunk size '{}': {}", size_str, e))?;

        if chunk_size == 0 {
            break;
        }

        // Read chunk data
        let data_start = size_end + 2; // skip \r\n
        if data_start + chunk_size > remaining.len() {
            // Partial chunk - take what we have
            result.push_str(&remaining[data_start..]);
            break;
        }
        result.push_str(&remaining[data_start..data_start + chunk_size]);
        remaining = &remaining[data_start + chunk_size..];
    }

    Ok(result)
}

/// Parse depth levels from the API response format: [[price_str, qty_str], ...]
fn parse_levels(levels: &[[String; 2]]) -> anyhow::Result<Vec<DepthLevel>> {
    levels
        .iter()
        .map(|[price_str, qty_str]| {
            let price: f64 = price_str.parse().map_err(|e| {
                anyhow::anyhow!("Invalid price '{}': {}", price_str, e)
            })?;
            let quantity: u64 = qty_str.parse().map_err(|e| {
                anyhow::anyhow!("Invalid quantity '{}': {}", qty_str, e)
            })?;
            Ok(DepthLevel { price, quantity })
        })
        .collect()
}

/// Calculate the optimal limit price for a market order.
///
/// For a market BUY: walks asks (sell orders) from lowest to highest price.
/// For a market SELL: walks bids (buy orders) from highest to lowest price.
///
/// Returns the worst execution price plus a slippage buffer, converted to
/// an integer price_num/price_den ratio.
///
/// # Arguments
/// - `side`: "buy" or "sell"
/// - `amount`: order amount in sompi
/// - `bids`: bid levels (highest first, from API)
/// - `asks`: ask levels (lowest first, from API)
/// - `slippage_bps`: slippage buffer in basis points (100 = 1%)
pub fn calculate_market_price(
    side: &str,
    amount: u64,
    bids: &[DepthLevel],
    asks: &[DepthLevel],
    slippage_bps: u64,
) -> anyhow::Result<MarketPriceResult> {
    let (levels, side_name) = match side {
        "buy" => {
            if asks.is_empty() {
                anyhow::bail!("No sell orders (asks) on the book. Cannot determine market buy price.");
            }
            (asks, "buy")
        }
        "sell" => {
            if bids.is_empty() {
                anyhow::bail!("No buy orders (bids) on the book. Cannot determine market sell price.");
            }
            (bids, "sell")
        }
        _ => anyhow::bail!("Invalid side '{}'. Use 'buy' or 'sell'.", side),
    };

    let mut remaining = amount;
    let mut worst_price = 0.0_f64;
    let mut levels_consumed = 0_usize;
    let mut total_consumed = 0_u64;

    for level in levels {
        if remaining == 0 {
            break;
        }
        let consume = remaining.min(level.quantity);
        remaining = remaining.saturating_sub(consume);
        total_consumed += consume;
        worst_price = level.price;
        levels_consumed += 1;
    }

    if remaining > 0 {
        anyhow::bail!(
            "Insufficient depth for {} market {} of {} sompi. \
             Book has only {} sompi available across {} level(s). \
             Reduce the order size or use a limit order.",
            side_name, side_name, amount, total_consumed, levels_consumed
        );
    }

    // Apply slippage
    let final_price = if side == "buy" {
        // Buy: willing to pay more -> increase price
        worst_price * (1.0 + slippage_bps as f64 / 10_000.0)
    } else {
        // Sell: willing to accept less -> decrease price
        worst_price * (1.0 - slippage_bps as f64 / 10_000.0)
    };

    // Convert f64 price to integer ratio price_num/price_den.
    // Use a precision factor to preserve decimal precision.
    let (price_num, price_den) = float_to_ratio(final_price);

    Ok(MarketPriceResult {
        price_num,
        price_den,
        worst_price,
        final_price,
        depth_consumed: total_consumed,
        levels_consumed,
    })
}

/// Convert a floating-point price to an integer ratio (num, den).
///
/// Strategy: multiply by 10^8 (sompi precision) then simplify with GCD.
fn float_to_ratio(price: f64) -> (u64, u64) {
    if price <= 0.0 {
        return (0, 1);
    }

    // Use 10^8 as the denominator base (sompi precision)
    let precision: u64 = 100_000_000;
    let num = (price * precision as f64).round() as u64;
    let den = precision;

    if num == 0 {
        return (0, 1);
    }

    let g = gcd(num, den);
    (num / g, den / g)
}

/// Greatest common divisor (Euclidean algorithm).
fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

// Trustless-first market price resolution

/// Resolve market price using trustless-first fallback chain.
///
/// 1. Scan recent blocks for v18 fill TXs (trustless, from node)
/// 2. Fall back to Matcher API only if `matcher_url` is explicitly provided
///    and no on-chain fills were found
/// 3. Error if neither source has data
///
/// Returns (price_num, price_den) with slippage applied.
pub async fn resolve_market_price_smart(
    node_url: &str,
    token: &str,
    side: &str,
    _amount: u64,
    slippage_bps: u64,
    matcher_url: Option<&str>,
) -> anyhow::Result<(u64, u64)> {
    // Step 1: Trustless — scan recent blocks for fill TXs
    let fills = crate::watch::scan_recent_fills(node_url, token, 200).await;

    if !fills.is_empty() {
        let summary = crate::watch::summarize_fills(&fills)
            .ok_or_else(|| anyhow::anyhow!("Failed to summarize fill data"))?;

        let last_price = summary.last_price_num as f64 / summary.last_price_den as f64;

        // Apply slippage based on side
        let final_price = if side == "buy" {
            last_price * (1.0 + slippage_bps as f64 / 10_000.0)
        } else {
            last_price * (1.0 - slippage_bps as f64 / 10_000.0)
        };

        let (price_num, price_den) = float_to_ratio(final_price);

        println!("Trustless market {}: {} fill(s) from on-chain data", side, fills.len());
        println!("  Last traded price: {:.8} ({}/{})",
            last_price, summary.last_price_num, summary.last_price_den);
        println!("  VWAP:              {:.8} ({}/{})",
            summary.vwap_num as f64 / summary.vwap_den as f64,
            summary.vwap_num, summary.vwap_den);
        println!("  Slippage buffer:   {} bps", slippage_bps);
        println!("  Final limit price: {:.8} ({}/{})", final_price, price_num, price_den);

        return Ok((price_num, price_den));
    }

    // Step 2: Fallback — Matcher API (only if explicitly provided)
    if let Some(url) = matcher_url {
        println!("No on-chain fills found. Falling back to Matcher API at {}", url);

        let (bids, asks) = fetch_depth(url, token)?;
        let result = calculate_market_price(
            side, _amount, &bids, &asks, slippage_bps,
        )?;

        println!("Matcher API market {}: queried {} level(s)", side,
            if side == "buy" { asks.len() } else { bids.len() });
        println!("  Worst execution price: {:.8}", result.worst_price);
        println!("  Slippage buffer:       {} bps", slippage_bps);
        println!("  Final limit price:     {:.8} ({}/{})",
            result.final_price, result.price_num, result.price_den);
        println!("  Depth consumed:        {} sompi across {} level(s)",
            result.depth_consumed, result.levels_consumed);

        return Ok((result.price_num, result.price_den));
    }

    // Step 3: Error — no data from either source
    anyhow::bail!(
        "No recent fills found on-chain and no --matcher-url provided.\n\
         Either:\n\
         - Wait for fills to appear on the order book, or\n\
         - Provide --matcher-url to query a Matcher API, or\n\
         - Deploy a limit order with explicit --price-num/--price-den."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_asks(levels: &[(f64, u64)]) -> Vec<DepthLevel> {
        levels.iter().map(|&(price, quantity)| DepthLevel { price, quantity }).collect()
    }

    fn make_bids(levels: &[(f64, u64)]) -> Vec<DepthLevel> {
        levels.iter().map(|&(price, quantity)| DepthLevel { price, quantity }).collect()
    }

    // --- Basic price calculation ---

    #[test]
    fn market_buy_single_level_exact_fill() {
        let asks = make_asks(&[(0.5, 1_000_000)]);
        let result = calculate_market_price("buy", 1_000_000, &[], &asks, 100).unwrap();
        assert_eq!(result.depth_consumed, 1_000_000);
        assert_eq!(result.levels_consumed, 1);
        assert!((result.worst_price - 0.5).abs() < 1e-10);
        // With 1% slippage: 0.5 * 1.01 = 0.505
        assert!((result.final_price - 0.505).abs() < 1e-10);
        assert!(result.price_num > 0);
        assert!(result.price_den > 0);
    }

    #[test]
    fn market_buy_multiple_levels() {
        let asks = make_asks(&[
            (0.50, 500_000),
            (0.55, 500_000),
            (0.60, 500_000),
        ]);
        let result = calculate_market_price("buy", 1_200_000, &[], &asks, 100).unwrap();
        assert_eq!(result.depth_consumed, 1_200_000);
        assert_eq!(result.levels_consumed, 3);
        // Worst price is 0.60 (third level)
        assert!((result.worst_price - 0.60).abs() < 1e-10);
        // With 1% slippage: 0.60 * 1.01 = 0.606
        assert!((result.final_price - 0.606).abs() < 1e-10);
    }

    #[test]
    fn market_sell_single_level() {
        let bids = make_bids(&[(0.50, 1_000_000)]);
        let result = calculate_market_price("sell", 500_000, &bids, &[], 100).unwrap();
        assert_eq!(result.depth_consumed, 500_000);
        assert_eq!(result.levels_consumed, 1);
        assert!((result.worst_price - 0.5).abs() < 1e-10);
        // With 1% slippage: 0.5 * 0.99 = 0.495
        assert!((result.final_price - 0.495).abs() < 1e-10);
    }

    #[test]
    fn market_sell_multiple_levels() {
        let bids = make_bids(&[
            (0.60, 300_000),
            (0.55, 300_000),
            (0.50, 300_000),
        ]);
        let result = calculate_market_price("sell", 800_000, &bids, &[], 100).unwrap();
        assert_eq!(result.depth_consumed, 800_000);
        assert_eq!(result.levels_consumed, 3);
        // Worst price is 0.50 (third/lowest bid level)
        assert!((result.worst_price - 0.50).abs() < 1e-10);
    }

    // --- Insufficient depth ---

    #[test]
    fn market_buy_insufficient_depth() {
        let asks = make_asks(&[(0.5, 100_000)]);
        let err = calculate_market_price("buy", 500_000, &[], &asks, 100).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Insufficient depth"), "got: {}", msg);
        assert!(msg.contains("100000"), "got: {}", msg);
    }

    #[test]
    fn market_sell_insufficient_depth() {
        let bids = make_bids(&[(0.5, 200_000)]);
        let err = calculate_market_price("sell", 1_000_000, &bids, &[], 100).unwrap_err();
        assert!(err.to_string().contains("Insufficient depth"));
    }

    // --- Empty book ---

    #[test]
    fn market_buy_empty_asks() {
        let err = calculate_market_price("buy", 100_000, &[], &[], 100).unwrap_err();
        assert!(err.to_string().contains("No sell orders"));
    }

    #[test]
    fn market_sell_empty_bids() {
        let err = calculate_market_price("sell", 100_000, &[], &[], 100).unwrap_err();
        assert!(err.to_string().contains("No buy orders"));
    }

    // --- Slippage variations ---

    #[test]
    fn zero_slippage() {
        let asks = make_asks(&[(1.0, 1_000_000)]);
        let result = calculate_market_price("buy", 500_000, &[], &asks, 0).unwrap();
        assert!((result.final_price - 1.0).abs() < 1e-10);
        assert!((result.worst_price - result.final_price).abs() < 1e-10);
    }

    #[test]
    fn high_slippage_500bps() {
        let asks = make_asks(&[(2.0, 1_000_000)]);
        let result = calculate_market_price("buy", 500_000, &[], &asks, 500).unwrap();
        // 2.0 * 1.05 = 2.1
        assert!((result.final_price - 2.1).abs() < 1e-10);
    }

    #[test]
    fn sell_slippage_decreases_price() {
        let bids = make_bids(&[(2.0, 1_000_000)]);
        let result = calculate_market_price("sell", 500_000, &bids, &[], 200).unwrap();
        // 2.0 * 0.98 = 1.96
        assert!((result.final_price - 1.96).abs() < 1e-10);
    }

    // --- Edge cases ---

    #[test]
    fn exact_single_level_match() {
        let asks = make_asks(&[(0.123456, 999)]);
        let result = calculate_market_price("buy", 999, &[], &asks, 100).unwrap();
        assert_eq!(result.depth_consumed, 999);
        assert_eq!(result.levels_consumed, 1);
    }

    #[test]
    fn invalid_side() {
        let err = calculate_market_price("hold", 100, &[], &[], 100).unwrap_err();
        assert!(err.to_string().contains("Invalid side"));
    }

    #[test]
    fn very_small_amount() {
        let asks = make_asks(&[(1.0, 1)]);
        let result = calculate_market_price("buy", 1, &[], &asks, 100).unwrap();
        assert_eq!(result.depth_consumed, 1);
    }

    #[test]
    fn large_amount_across_many_levels() {
        let asks: Vec<DepthLevel> = (1..=100)
            .map(|i| DepthLevel { price: 0.5 + (i as f64 * 0.01), quantity: 10_000 })
            .collect();
        let result = calculate_market_price("buy", 500_000, &[], &asks, 50).unwrap();
        assert_eq!(result.depth_consumed, 500_000);
        assert_eq!(result.levels_consumed, 50);
        // Worst price = 0.5 + 50*0.01 = 1.0
        assert!((result.worst_price - 1.0).abs() < 1e-10);
    }

    // --- float_to_ratio ---

    #[test]
    fn ratio_simple_integer() {
        let (n, d) = float_to_ratio(2.0);
        assert_eq!(n, 2);
        assert_eq!(d, 1);
    }

    #[test]
    fn ratio_half() {
        let (n, d) = float_to_ratio(0.5);
        assert_eq!(n, 1);
        assert_eq!(d, 2);
    }

    #[test]
    fn ratio_zero() {
        let (n, d) = float_to_ratio(0.0);
        assert_eq!(n, 0);
        assert_eq!(d, 1);
    }

    #[test]
    fn ratio_negative() {
        let (n, d) = float_to_ratio(-1.0);
        assert_eq!(n, 0);
        assert_eq!(d, 1);
    }

    #[test]
    fn ratio_small_decimal() {
        let (n, d) = float_to_ratio(0.00000001);
        // 0.00000001 * 10^8 = 1, so 1/100000000
        assert_eq!(n, 1);
        assert_eq!(d, 100_000_000);
    }

    #[test]
    fn ratio_precise_decimal() {
        let (n, d) = float_to_ratio(0.505);
        // 0.505 * 10^8 = 50500000, gcd(50500000, 100000000) = 500000
        // -> 101/200
        assert_eq!(n, 101);
        assert_eq!(d, 200);
    }

    // --- GCD ---

    #[test]
    fn gcd_basic() {
        assert_eq!(gcd(12, 8), 4);
        assert_eq!(gcd(100, 1), 1);
        assert_eq!(gcd(17, 13), 1);
        assert_eq!(gcd(0, 5), 5);
    }

    // --- parse_levels ---

    #[test]
    fn parse_levels_valid() {
        let raw = vec![
            ["0.500000".to_string(), "1000000".to_string()],
            ["0.550000".to_string(), "2000000".to_string()],
        ];
        let levels = parse_levels(&raw).unwrap();
        assert_eq!(levels.len(), 2);
        assert!((levels[0].price - 0.5).abs() < 1e-10);
        assert_eq!(levels[0].quantity, 1_000_000);
        assert!((levels[1].price - 0.55).abs() < 1e-10);
        assert_eq!(levels[1].quantity, 2_000_000);
    }

    #[test]
    fn parse_levels_invalid_price() {
        let raw = vec![["notanumber".to_string(), "1000".to_string()]];
        assert!(parse_levels(&raw).is_err());
    }

    #[test]
    fn parse_levels_invalid_qty() {
        let raw = vec![["0.5".to_string(), "abc".to_string()]];
        assert!(parse_levels(&raw).is_err());
    }

    #[test]
    fn parse_levels_empty() {
        let raw: Vec<[String; 2]> = vec![];
        let levels = parse_levels(&raw).unwrap();
        assert!(levels.is_empty());
    }

    // --- decode_chunked ---

    #[test]
    fn decode_chunked_simple() {
        let input = "5\r\nhello\r\n0\r\n";
        let result = decode_chunked(input).unwrap();
        assert_eq!(result, "hello");
    }

    #[test]
    fn decode_chunked_multi() {
        let input = "5\r\nhello\r\n6\r\n world\r\n0\r\n";
        let result = decode_chunked(input).unwrap();
        assert_eq!(result, "hello world");
    }

    #[test]
    fn decode_chunked_empty() {
        let input = "0\r\n";
        let result = decode_chunked(input).unwrap();
        assert_eq!(result, "");
    }
}
