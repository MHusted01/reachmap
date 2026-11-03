//! reachmap shows which services on a host can be reached, from where, and why.
//!
//! Layout: `parse` holds pure parsers (text in, values out), `collect` reads
//! from the running system, `scan` joins the two, and `table` prints results.

pub mod collect;
pub mod errors;
pub mod parse;
pub mod scan;
pub mod socket;
pub mod table;
