//! Spot trading domain: order book, matching, routing, and derivative order types
//! (stop, DCA, swap, IFD, trailing-stop).

#[allow(dead_code)]
pub mod order_book;
#[allow(dead_code)]
pub mod stop_book;
#[allow(dead_code)]
pub mod dca_book;
#[allow(dead_code)]
pub mod swap_book;
#[allow(dead_code)]
pub mod matching;
#[allow(dead_code)]
pub mod routing;
#[allow(dead_code)]
pub mod batch;
#[allow(dead_code)]
pub mod time_planner;
#[allow(dead_code)]
pub mod ifd;
#[allow(dead_code)]
pub mod trailing_stop;
