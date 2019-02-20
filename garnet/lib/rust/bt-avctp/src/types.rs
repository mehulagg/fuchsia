// Copyright 2018 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use {
    failure::Fail,
    fuchsia_syslog::fx_log_warn,
    fuchsia_zircon as zx,
    std::{
        convert::TryFrom, result,
    }
};

/// Result type for AVCTP, using avctp::Error
pub type Result<T> = result::Result<T, Error>;

/// The error type of the AVCTP library.
#[derive(Fail, Debug, PartialEq)]
pub enum Error {
    /// The value that was sent on the wire was out of range.
    #[fail(display = "Value was out of range")]
    OutOfRange,

    /// The profile identifier sent was returned as invalid by the peer.
    #[fail(display = "Invalid profile id for {:?}", _0)]
    InvalidProfileId(TxLabel),

    /// The header was invalid when parsing a message from the peer.
    #[fail(display = "Invalid Header for a AVCTP message")]
    InvalidHeader,

    /// The body format was invalid when parsing a message from the peer.
    #[fail(display = "Failed to parse AVCTP message contents")]
    InvalidMessage,

    /// The remote end failed to respond to this command in time.
    #[fail(display = "Command timed out")]
    Timeout,

    #[fail(display = "Peer sent unsupported fragmented AVCTP header")]
    FragmentedPacket(TxLabel),

    /// The distant peer has disconnected.
    #[fail(display = "Peer has disconnected")]
    PeerDisconnected,

    /// Sent if a Command Future is polled after it's already completed
    #[fail(display = "Command Response has already been received")]
    AlreadyReceived,

    /// Encountered an IO error reading from the peer.
    #[fail(display = "Encountered an IO error reading from the peer: {}", _0)]
    PeerRead(#[cause] zx::Status),

    /// Encountered an IO error reading from the peer.
    #[fail(display = "Encountered an IO error writing to the peer: {}", _0)]
    PeerWrite(#[cause] zx::Status),

    /// A message couldn't be encoded.
    #[fail(display = "Encontered an error encoding a message")]
    Encoding,

    /// An error has been detected, and the request that is being handled
    /// should be rejected with the error code given.
    #[fail(display = "Invalid request detected")]
    RequestInvalid,

    #[doc(hidden)]
    #[fail(display = "__Nonexhaustive error should never be created.")]
    __Nonexhaustive,
}

/// Generates an enum value where each variant can be converted into a constant in the given
/// raw_type.  For example:
/// decodable_enum! {
///     Color<u8> {
///        Red => 1,
///        Blue => 2,
///        Green => 3,
///     }
/// }
/// Then Color::try_from(2) returns Color::Red, and u8::from(Color::Red) returns 1.
macro_rules! decodable_enum {
    ($(#[$meta:meta])* $name:ident<$raw_type:ty> {
        $($variant:ident => $val:expr),*,
    }) => {
        $(#[$meta])*
        #[derive(Debug, PartialEq, Copy, Clone)]
        pub(crate) enum $name {
            $($variant),*
        }

        tofrom_decodable_enum! {
            $name<$raw_type> {
                $($variant => $val),*,
            }
        }
    }
}

/// The same as decodable_enum, but the struct is public.
macro_rules! pub_decodable_enum {
    ($(#[$meta:meta])* $name:ident<$raw_type:ty> {
        $($variant:ident => $val:expr),*,
    }) => {
        $(#[$meta])*
        #[derive(Debug, PartialEq, Copy, Clone)]
        pub enum $name {
            $($variant),*
        }

        tofrom_decodable_enum! {
            $name<$raw_type> {
                $($variant => $val),*,
            }
        }
    }
}

/// A From<&$name> for $raw_type implementation and
/// TryFrom<$raw_type> for $name implementation, used by (pub_)decodable_enum
macro_rules! tofrom_decodable_enum {
    ($name:ident<$raw_type:ty> {
        $($variant:ident => $val:expr),*,
    }) => {
        impl From<&$name> for $raw_type {
            fn from(v: &$name) -> $raw_type {
                match v {
                    $($name::$variant => $val),*,
                }
            }
        }

        impl TryFrom<$raw_type> for $name {
            type Error = Error;
            fn try_from(value: $raw_type) -> Result<Self> {
                match value {
                    $($val => Ok($name::$variant)),*,
                    _ => Err(Error::OutOfRange),
                }
            }
        }
    }
}

/// A decodable type can be created from a byte buffer.
/// The type returned is separate (copied) from the buffer once decoded.
pub(crate) trait Decodable: Sized {
    /// Decodes into a new object, or returns an error.
    fn decode(buf: &[u8]) -> Result<Self>;
}

/// A encodable type can write itself into a byte buffer.
pub(crate) trait Encodable: Sized {
    /// Returns the number of bytes necessary to encode |self|
    fn encoded_len(&self) -> usize;

    /// Writes the encoded version of |self| at the start of |buf|
    /// |buf| must be at least size() length.
    fn encode(&self, buf: &mut [u8]) -> Result<()>;
}

/// AV/C Command and Response types.
/// See AV/C Generial Specification Section 5.3.1 and 5.3.2
pub_decodable_enum! {
    CommandType<u8> {
        // Commands
        Control => 0x00,
        Status => 0x01,
        SpecificInquiry => 0x02,
        Notify => 0x03,
        GeneralInquiry => 0x04, // Unused with bt?
        // Responses
        NotImplemented => 0x08,
        Accepted => 0x09,
        Rejected => 0x0a,
        InTransition => 0x0b, // Unused with bt?
        ImplementedStable => 0x0c,
        Changed => 0x0d,
        Interim => 0x0f,
    }
}

/// AV/C Op Codes
/// See AV/C Generial Specification Section 5.3.1
pub_decodable_enum! {
    AvOpCode<u8> {
        VendorDependent => 0x00,
        UnitInfo => 0x30,
        SubUnitInfo => 0x31,
        Passthrough => 0x7c,
    }
}

/// An AVCTP Transaction Label
/// Not used outside the library. Public as part of some internal Error variants.
/// See Section 6.1.1
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TxLabel(u8);

// Transaction labels are only 4 bits.
const MAX_TX_LABEL: u8 = 0xF;

impl TryFrom<u8> for TxLabel {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        if value > MAX_TX_LABEL {
            fx_log_warn!("TxLabel out of range: {}", value);
            Err(Error::OutOfRange)
        } else {
            Ok(TxLabel(value))
        }
    }
}

impl From<&TxLabel> for u8 {
    fn from(v: &TxLabel) -> u8 {
        v.0
    }
}

impl From<&TxLabel> for usize {
    fn from(v: &TxLabel) -> usize {
        v.0 as usize
    }
}

/// Most common subunits for AVRCP
pub(crate) const PANEL_SUBUNIT: u8 = 0x09;
pub(crate) const UNIT_SUBUNIT: u8 = 0x1F;

/// An AVCTP Profile Identifer
/// The type indicates the how the command/request frame is encoded. It should be identical to the
/// 16bit UUID of the service class for this profile.
/// See Section 6.1.1
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct ProfileId([u8; 2]);

pub(crate) const AV_REMOTE_PROFILE: ProfileId = ProfileId([0x11, 0x0e]);

impl From<[u8; 2]> for ProfileId {
    fn from(value: [u8; 2]) -> Self {
        Self(value)
    }
}

/// An AVCTP Profile Identifer
/// The type indicates the how the command/request frame is encoded. It should be identical to the
/// 16bit UUID of the service class for this profile.
/// See Section 6.1.1
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct CompanyId([u8; 3]);

pub(crate) const BT_SIG_COMPANY_ID: CompanyId = CompanyId([0x00, 0x19, 0x58]);

impl From<[u8; 3]> for CompanyId {
    fn from(value: [u8; 3]) -> Self {
        Self(value)
    }
}

decodable_enum! {
    /// Indicated whether this paket is part of a fragmented packet set.
    /// See Section 6.1
    PacketType<u8> {
        Single => 0x00,
        Start => 0x01,
        Continue => 0x02,
        End => 0x03,
    }
}

decodable_enum! {
    /// Specifies the type of the packet as being either Command or Response
    /// See Section 6.1.1
    MessageType<u8> {
        Command => 0x00,
        Response => 0x01,
    }
}

#[derive(Debug)]
pub(crate) struct AvctHeader {
    pub label: TxLabel,        // byte 0, bit 7..4
    packet_type: PacketType,   // byte 0, bit 3..2
    message_type: MessageType, // byte 0, bit 1
    invalid_profile_id: bool,  // byte 0, bit 0
    num_packets: u8,           // byte 1 if packet type == start
    pub profile_id: ProfileId, // byte 1..2 (byte 2..3 if packet type is start)
}

impl AvctHeader {
    pub fn new(
        label: TxLabel,
        profile_id: ProfileId,
        message_type: MessageType,
        invalid_profile_id: bool,
    ) -> AvctHeader {
        AvctHeader {
            label: label.clone(),
            profile_id: profile_id.clone(),
            message_type: message_type.clone(),
            packet_type: PacketType::Single,
            invalid_profile_id: invalid_profile_id,
            num_packets: 1,
        }
    }

    /// Creates a new header from this header with it's message type set to response.
    pub fn create_response(&self) -> AvctHeader {
        AvctHeader {
            label: self.label.clone(),
            profile_id: self.profile_id.clone(),
            message_type: MessageType::Response,
            packet_type: PacketType::Single,
            invalid_profile_id: false,
            num_packets: 1,
        }
    }

    /// Creates a new header from this header with it's message type set to response
    /// and with the ipid (invalid profile id) bit set to true.
    pub fn create_invalid_profile_id_response(&self) -> AvctHeader {
        AvctHeader {
            label: self.label,
            profile_id: self.profile_id,
            message_type: MessageType::Response,
            packet_type: PacketType::Single,
            invalid_profile_id: true,
            num_packets: 1,
        }
    }

    pub fn label(&self) -> TxLabel {
        self.label
    }

    pub fn profile_id(&self) -> ProfileId {
        self.profile_id
    }

    pub fn is_type(&self, other: MessageType) -> bool {
        self.message_type == other
    }

    pub fn is_command(&self) -> bool {
        self.is_type(MessageType::Command)
    }

    pub fn is_single(&self) -> bool {
        self.packet_type == PacketType::Single
    }

    pub fn is_invalid_profile_id(&self) -> bool {
        self.invalid_profile_id
    }
}

impl Decodable for AvctHeader {
    fn decode(bytes: &[u8]) -> Result<AvctHeader> {
        if bytes.len() < 3 {
            return Err(Error::OutOfRange);
        }
        let label = TxLabel::try_from(bytes[0] >> 4)?;
        let packet_type = PacketType::try_from((bytes[0] >> 2) & 0x3)?;
        let (id_offset, num_packets) = match packet_type {
            PacketType::Start => {
                if bytes.len() < 4 {
                    return Err(Error::OutOfRange);
                }
                (2, bytes[1])
            }
            _ => (1, 1),
        };

        let id = ProfileId::from([bytes[id_offset], bytes[id_offset + 1]]);
        let invalid_profile_id = bytes[0] & 0x1 == 1;
        let header = AvctHeader {
            label: label,
            profile_id: id,
            message_type: MessageType::try_from(bytes[0] >> 1 & 0x1)?,
            packet_type: packet_type,
            invalid_profile_id: invalid_profile_id,
            num_packets: num_packets,
        };
        Ok(header)
    }
}

impl Encodable for AvctHeader {
    fn encoded_len(&self) -> usize {
        match self.packet_type {
            PacketType::Start => 4,
            _ => 3,
        }
    }

    fn encode(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < self.encoded_len() {
            return Err(Error::Encoding);
        }
        let invalid_profile_id: u8 = if self.invalid_profile_id { 1 } else { 0 };
        buf[0] = u8::from(&self.label) << 4
            | u8::from(&self.packet_type) << 2
            | u8::from(&self.message_type) << 1
            | invalid_profile_id;
        let mut buf_i = 1;
        if self.packet_type == PacketType::Start {
            buf[buf_i] = self.num_packets;
            buf_i = 2;
        }
        let profile_id = self.profile_id.0;
        buf[buf_i] = profile_id[0];
        buf[buf_i + 1] = profile_id[1];
        Ok(())
    }
}

/// AVC Command and Response frames use the same layout with different command values
#[derive(Debug)]
pub(crate) struct AvcHeader {
    command_type: CommandType,     // byte 0, bit 3..0
    subunit_type: u8,              // byte 1, bit 7..3
    subunit_id: u8,                // byte 1, bit 2..0
    op_code: AvOpCode,             // byte 2
    company_id: Option<CompanyId>, // byte 3-5 (only vendor depedent packets)
}

impl AvcHeader {
    pub fn new(
        command_type: CommandType,
        subunit_type: u8,
        subunit_id: u8,
        op_code: AvOpCode,
        company_id: Option<CompanyId>,
    ) -> AvcHeader {
        AvcHeader {
            command_type: command_type,
            subunit_type: subunit_type,
            subunit_id: subunit_id,
            op_code: op_code,
            company_id: company_id,
        }
    }

    /// Creates a new AvcHeader with all the same fields but with a new response command type
    pub fn create_response(&self, command_type: CommandType) -> AvcHeader {
        AvcHeader {
            command_type: command_type,
            subunit_type: self.subunit_type,
            subunit_id: self.subunit_id,
            op_code: self.op_code,
            company_id: self.company_id,
        }
    }

    pub fn command_type(&self) -> CommandType {
        self.command_type
    }

    pub fn op_code(&self) -> AvOpCode {
        self.op_code
    }

    pub fn is_panel_subunit(&self) -> bool {
        self.subunit_type == PANEL_SUBUNIT
    }

    pub fn is_unit_subunit(&self) -> bool {
        self.subunit_type == UNIT_SUBUNIT
    }

    pub fn is_op_code(&self, op_code: AvOpCode) -> bool {
        self.op_code == op_code
    }
}

impl Encodable for AvcHeader {
    fn encoded_len(&self) -> usize {
        if self.op_code == AvOpCode::VendorDependent {
            6
        } else {
            3
        }
    }

    fn encode(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < self.encoded_len() {
            return Err(Error::Encoding);
        }
        buf[0] = u8::from(&self.command_type);
        buf[1] = (self.subunit_type << 3) | (self.subunit_id & 0x7);
        buf[2] = u8::from(&self.op_code);
        if self.op_code == AvOpCode::VendorDependent {
            if self.company_id.is_none() {
                return Err(Error::InvalidHeader);
            }
            let company_id = <[u8; 3]>::from(self.company_id.unwrap().0);
            buf[3] = company_id[0];
            buf[4] = company_id[1];
            buf[5] = company_id[2];
        }
        Ok(())
    }
}

impl Decodable for AvcHeader {
    fn decode(bytes: &[u8]) -> Result<AvcHeader> {
        if bytes.len() < 3 {
            return Err(Error::InvalidHeader);
        }
        if bytes[0] >> 4 != 0 {
            // Upper 4 bits should be zero.
            return Err(Error::InvalidHeader);
        }
        let command_type = CommandType::try_from(bytes[0])?;
        let subunit_type = bytes[1] >> 3;
        let subunit_id = bytes[1] & 0x7;
        let op_code = AvOpCode::try_from(bytes[2])?;
        let company_id = if op_code == AvOpCode::VendorDependent {
            if bytes.len() < 6 {
                return Err(Error::InvalidHeader);
            }
            Some(CompanyId::from([bytes[3], bytes[4], bytes[5]]))
        } else {
            None
        };
        Ok(AvcHeader { command_type, subunit_type, subunit_id, op_code, company_id })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    decodable_enum! {
        TestEnum<u16> {
            One => 1,
            Two => 2,
            Max => 65535,
        }
    }

    #[test]
    fn try_from_success() {
        let one = TestEnum::try_from(1);
        assert!(one.is_ok());
        assert_eq!(TestEnum::One, one.unwrap());
        let two = TestEnum::try_from(2);
        assert!(two.is_ok());
        assert_eq!(TestEnum::Two, two.unwrap());
        let max = TestEnum::try_from(65535);
        assert!(max.is_ok());
        assert_eq!(TestEnum::Max, max.unwrap());
    }

    #[test]
    fn try_from_error() {
        let err = TestEnum::try_from(5);
        assert_eq!(Some(Error::OutOfRange), err.err());
    }

    #[test]
    fn into_rawtype() {
        let raw = u16::from(&TestEnum::One);
        assert_eq!(1, raw);
        let raw = u16::from(&TestEnum::Two);
        assert_eq!(2, raw);
        let raw = u16::from(&TestEnum::Max);
        assert_eq!(65535, raw);
    }

    #[test]
    fn txlabel_tofrom_u8() {
        let mut label: Result<TxLabel> = TxLabel::try_from(15);
        assert!(label.is_ok());
        assert_eq!(15, u8::from(&label.unwrap()));
        label = TxLabel::try_from(16);
        assert_eq!(Err(Error::OutOfRange), label);
    }

    #[test]
    fn txlabel_to_usize() {
        let label = TxLabel::try_from(1).unwrap();
        assert_eq!(1, usize::from(&label));
    }
}
