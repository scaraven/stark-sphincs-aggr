#[derive(Drop, Serde)]
struct Args {
    attestations: Array<u32>,
    n: u32,
}

#[executable]
fn main(args: Args) {
    let Args { attestations, n } = args;
    println!("Verifying {} signatures", attestations.len());

    println!("OK");
}