//! Dev tool: run a WQL query and print the row count and the first row.
fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match hideout_win::wmi::query(&a[0], &a[1], 100_000) {
        Ok(r) => println!("{} rows; first: {:?}", r.len(), r.first()),
        Err(e) => println!("ERR {e}"),
    }
}
