use std::io;

// This enum represents every error that main can return
#[derive(Debug)]
pub enum ProgError {
    Io(io::Error),
    DnsHeader(String),
}

impl From<io::Error> for ProgError {
    fn from(error: io::Error) -> Self {
        ProgError::Io(error)
    }
}

impl From<String> for ProgError {
    fn from(error: String) -> Self {
        ProgError::DnsHeader(error)
    }
}

// This struct holds the six fixed size fields of a DNS header
#[derive(Debug, Clone, Copy)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16, // Holds every one bit and four bit field packed together
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

// This struct holds the flags field once it has been split into its individual pieces
#[derive(Debug, Clone, Copy)]
pub struct DnsFlags {
    pub qr: bool,   // Query or Response
    pub opcode: u8, //type Opcode just for testing we will do u8
    pub aa: bool,   // Authoritative Answer
    pub tc: bool,   // Truncated
    pub rd: bool,   // Recursion Desired
    pub ra: bool,   // Recursion Available
    pub ad: bool,   // Authenticated Data
    pub cd: bool,   // Checking Disabled
    pub rcode: u8,  //type Rcode just for testing we will do u8
}

impl DnsHeader {
    // Parses a twelve byte header written as twenty four hex characters
    pub fn from_hex(input: &str) -> Result<Self, String> {
        let input = input.strip_prefix("0x").unwrap_or(input);
        if input.len() != 24 {
            return Err("Input lenght must be 24 hex chars".to_string());
        }

        if input.len() % 2 != 0 {
            return Err("hex string must contain an even number of digits".to_string());
        }

        Ok(DnsHeader {
            id: parse_hex_u16(&input[..4])?,
            flags: parse_hex_u16(&input[4..8])?,
            qdcount: parse_hex_u16(&input[8..12])?,
            ancount: parse_hex_u16(&input[12..16])?,
            nscount: parse_hex_u16(&input[16..20])?,
            arcount: parse_hex_u16(&input[20..])?,
        })
    }

    // Takes the raw flags field and unpacks it into individual named fields
    pub fn parse_flags(value: u16) -> DnsFlags {
        DnsFlags {
            qr: value & 0x8000 != 0,
            // The real version should use Opcode::from(((value >> 11) & 0x0f) as u8), this is just for testing
            // gonna switch it later
            opcode: ((value >> 11) & 0x0f) as u8,
            aa: value & 0x0400 != 0,
            tc: value & 0x0200 != 0,
            rd: value & 0x0100 != 0,
            ra: value & 0x0080 != 0,
            ad: value & 0x0020 != 0,
            cd: value & 0x0010 != 0,
            // The real version should Rcode::from((value & 0x000f) as u8), this is just for testing
            // gonna switch it later
            rcode: (value & 0x000f) as u8,
        }
    }

    pub fn is_response(&self) -> bool {
        (self.flags & (1 << 15)) != 0
    }

    pub fn opcode(self) -> u8 {
        ((self.flags >> 11) & 0x0F) as u8
    }

    pub fn authoritative_answer(&self) -> bool {
        (self.flags & (1 << 10)) != 0
    }

    pub fn truncated(&self) -> bool {
        (self.flags & (1 << 9)) != 0
    }

    pub fn recursion_desired(&self) -> bool {
        (self.flags & (1 << 8)) != 0
    }

    pub fn recursion_available(&self) -> bool {
        (self.flags & (1 << 7)) != 0
    }

    // Reserved bits, normally zero
    pub fn z(&self) -> u8 {
        ((self.flags >> 4) & 0x07) as u8
    }

    pub fn rcode(&self) -> u8 {
        (self.flags & 0x0F) as u8
    }
}

// A named version of the rcode field, not wired in yet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rcode {
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
    Other(u8),
}

impl From<u8> for Rcode {
    fn from(value: u8) -> Self {
        match value {
            0 => Rcode::NoError,
            1 => Rcode::FormErr,
            2 => Rcode::ServFail,
            3 => Rcode::NxDomain,
            4 => Rcode::NotImp,
            5 => Rcode::Refused,
            other => Rcode::Other(other),
        }
    }
}

// A named version of the opcode field, not wired in yet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Query,
    IQuery,
    Status,
    Notify,
    Update,
    Other(u8),
}

impl From<u8> for Opcode {
    fn from(value: u8) -> Self {
        match value {
            0 => Opcode::Query,
            1 => Opcode::IQuery,
            2 => Opcode::Status,
            4 => Opcode::Notify,
            5 => Opcode::Update,
            other => Opcode::Other(other),
        }
    }
}

// Reads four hex characters and turns them into a u16
fn parse_hex_u16(text: &str) -> Result<u16, String> {
    u16::from_str_radix(text, 16)
        .map_err(|error| format!("invalid hexadecimal value '{text}': {error}"))
}
