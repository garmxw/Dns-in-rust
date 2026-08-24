mod dns;

use std::io::{self, BufRead};

use dns::{DnsHeader, ProgError};

fn main() -> Result<(), ProgError> {
    let stdin = io::stdin();

    // Every line on stdin is treated as one independent header
    for line in stdin.lock().lines() {
        let l = line?;

        // Skip blank lines instead of trying to parse them
        if l.is_empty() {
            continue;
        }

        // Turn the twenty four hex characters into a structured header
        let dns_header = DnsHeader::from_hex(&l)?;

        // Split the packed flags field into its individual named fields
        let dns_flags = DnsHeader::parse_flags(dns_header.flags);

        // Small helper so booleans print as a single digit
        let bit = |value: bool| if value { 1 } else { 0 };

        println!(
            "id={id:04x} qr={qr} opcode={opcode} aa={aa} tc={tc} rd={rd} ra={ra} rcode={rcode} qd={qd} an={an} ns={ns} ar={ar}",
            id = dns_header.id,
            qr = bit(dns_flags.qr),
            opcode = dns_flags.opcode,
            aa = bit(dns_flags.aa),
            tc = bit(dns_flags.tc),
            rd = bit(dns_flags.rd),
            ra = bit(dns_flags.ra),
            rcode = dns_flags.rcode,
            qd = dns_header.qdcount,
            an = dns_header.ancount,
            ns = dns_header.nscount,
            ar = dns_header.arcount,
        );
    }

    Ok(())
}
