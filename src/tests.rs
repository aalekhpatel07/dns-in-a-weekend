use crate::*;
use bytes::Bytes;

#[test]
fn test_header_to_bytes() {
    let header = DNSHeader {
        id: 0x1314,
        flags: DNSHeaderFlag::None,
        num_questions: 1,
        num_additionals: 0,
        num_authorities: 0,
        num_answers: 0,
    };
    let observed = header.to_bytes().unwrap();
    let expected = b"\x13\x14\0\0\0\x01\0\0\0\0\0\0";
    assert_eq!(observed, Bytes::copy_from_slice(expected));
}

#[test]
fn test_encode_dns_name() {
    let observed = encode::dns_name("google.com").unwrap();
    let expected = b"\x06google\x03com\0";
    assert_eq!(observed, Bytes::from_static(expected));
}

#[test]
fn test_dns_question_to_bytes() {
    let question = DNSQuestion {
        name: encode::dns_name("google.com").unwrap(),
        r#type: DNSRecordType::A,
        class: DNSRecordClass::IN,
    };

    let observed = question.to_bytes().unwrap();
    let expected = Bytes::from_static(b"\x06google\x03com\0\0\x01\0\x01");
    assert_eq!(observed, expected);
    // let expected = Bytes::from(b"a");
}

#[test]
fn test_dns_question_new() {
    let question = DNSQuestion::new("google.com", DNSRecordType::A, DNSRecordClass::IN).unwrap();
    let observed = question.to_bytes().unwrap();
    let expected = Bytes::from_static(b"\x06google\x03com\0\0\x01\0\x01");
    assert_eq!(observed, expected);
}

#[test]
fn test_dns_query_new() {
    let query = DNSQuery::new("example.com", DNSRecordType::A, DNSRecordClass::IN).unwrap();

    let observed = query.to_bytes().unwrap();
    // except for the random id in the first two bytes,
    // everything should be fixed.
    let expected_tail =
        Bytes::from_static(b"\x01\0\0\x01\0\0\0\0\0\0\x07example\x03com\0\0\x01\0\x01");
    assert!(observed.ends_with(&expected_tail));
}

#[test]
fn test_dns_query_roundtrip() {
    let query = DNSQuery::new("www.example.com", DNSRecordType::A, DNSRecordClass::IN).unwrap();
    let response = query.send_to_8_8_8_8().unwrap();
    assert!(response.ends_with(&[93, 184, 216, 34]));
}
