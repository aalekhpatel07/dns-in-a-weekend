use crate::*;
use std::io::Cursor;
use test_case::test_case;

#[test]
fn test_header_serde() {
    let header = DNSHeader {
        id: 0x1314,
        flags: DNSHeaderFlag::None,
        num_questions: 1,
        num_additionals: 0,
        num_authorities: 0,
        num_answers: 0,
    };

    let mut observed = vec![];
    header.to_bytes(&mut observed).unwrap();
    let expected = b"\x13\x14\0\0\0\x01\0\0\0\0\0\0";
    assert_eq!(observed, expected.to_vec());

    let mut cursor = Cursor::new(observed);
    let deserialized = DNSHeader::from_bytes(&mut cursor).unwrap();
    assert_eq!(deserialized, header);
}

#[test]
fn test_encode_and_decode_dns_name() {
    let initial = "google.com";
    let mut writer = vec![];
    encode::dns_name(&mut writer, initial).unwrap();
    let expected = b"\x06google\x03com\0".to_vec();
    assert_eq!(writer, expected);

    let mut reader = Cursor::new(expected);
    let (decoded, _) = decode::dns_name(&mut reader).unwrap();
    assert_eq!(decoded, initial);
}

#[test]
fn test_dns_question_serde() {
    let question = DNSQuestion::new("google.com", DNSRecordType::A, DNSRecordClass::IN);

    let mut writer = vec![];
    question.to_bytes(&mut writer).unwrap();
    let expected = b"\x06google\x03com\0\0\x01\0\x01".to_vec();
    assert_eq!(writer, expected);

    let mut cursor = Cursor::new(expected);
    let deserialized = DNSQuestion::from_bytes(&mut cursor).unwrap();
    assert_eq!(deserialized, question);
}

#[test]
fn test_dns_query_new() {
    let query = DNSQuery::new(
        "example.com",
        DNSRecordType::A,
        DNSRecordClass::IN,
        DNSHeaderFlag::RecursionDesired,
    );

    let mut observed = vec![];

    query.to_bytes(&mut observed).unwrap();
    // except for the random id in the first two bytes,
    // everything should be fixed.
    let expected_tail = b"\x01\0\0\x01\0\0\0\0\0\0\x07example\x03com\0\0\x01\0\x01".to_vec();
    assert!(observed.ends_with(&expected_tail));
}

#[test]
fn test_dns_query_roundtrip() {
    let query = DNSQuery::new(
        "www.example.com",
        DNSRecordType::A,
        DNSRecordClass::IN,
        DNSHeaderFlag::RecursionDesired,
    );
    let response = query.send_to_8_8_8_8().unwrap();
    assert!(response.ends_with(&[93, 184, 216, 34]));
    let response = response.to_vec();

    let mut cursor = Cursor::new(&response[0..12]);
    let response_header = DNSHeader::from_bytes(&mut cursor).unwrap();
    assert_eq!(response_header.flags, DNSHeaderFlag::Other(33152));
    assert_eq!(response_header.num_questions, 1);
    assert_eq!(response_header.num_answers, 1);
}

#[test]
fn test_dns_query_record_parsing_roundtrip() {
    let query = DNSQuery::new(
        "www.example.com",
        DNSRecordType::A,
        DNSRecordClass::IN,
        DNSHeaderFlag::RecursionDesired,
    );
    let response = query.send_to_8_8_8_8().unwrap();
    assert!(response.ends_with(&[93, 184, 216, 34]));
    let response = response.to_vec();

    assert_eq!(response.len(), 49);
}

#[test]
fn test_dns_name_simple() {
    let query = DNSQuery::new(
        "www.example.com",
        DNSRecordType::A,
        DNSRecordClass::IN,
        DNSHeaderFlag::RecursionDesired,
    );
    let response = query.send_to_8_8_8_8().unwrap();

    let mut cursor = Cursor::new(&response[..]);
    let header = DNSHeader::from_bytes(&mut cursor).unwrap();
    let question = DNSQuestion::from_bytes(&mut cursor).unwrap();

    assert_eq!(question.class, DNSRecordClass::IN);
    assert_eq!(question.r#type, DNSRecordType::A);
    assert_eq!(question.name, "www.example.com".to_string());

    assert_eq!(header.flags, DNSHeaderFlag::Other(33152));
    assert_eq!(header.num_questions, 1);
    assert_eq!(header.num_answers, 1);
}

#[test]
fn test_dns_record_parsing() {
    let response = vec![
        96, 86, 129, 128, 0, 1, 0, 1, 0, 0, 0, 0, 3, 119, 119, 119, 7, 101, 120, 97, 109, 112, 108,
        101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 192, 12, 0, 1, 0, 1, 0, 0, 82, 155, 0, 4, 93, 184,
        216, 34,
    ];

    let mut cursor = Cursor::new(&response[..]);

    let header = DNSHeader::from_bytes(&mut cursor).unwrap();
    let question = DNSQuestion::from_bytes(&mut cursor).unwrap();

    assert_eq!(cursor.position(), 33);
    assert_eq!(
        question,
        DNSQuestion {
            name: "www.example.com".into(),
            r#type: DNSRecordType::A,
            class: DNSRecordClass::IN
        }
    );
    assert_eq!(header.flags, DNSHeaderFlag::Other(33152));
    assert_eq!(header.num_questions, 1);
    assert_eq!(header.num_answers, 1);
    assert_eq!(header.num_authorities, 0);
    assert_eq!(header.num_additionals, 0);

    let record = DNSRecord::from_bytes(&mut cursor).unwrap();

    assert_eq!(
        record,
        DNSRecord {
            name: "www.example.com".into(),
            r#type: DNSRecordType::A,
            class: DNSRecordClass::IN,
            ttl: 21147,
            data: b"]\xb8\xd8\"".to_vec()
        }
    );
}

#[test]
fn test_parse_dns_packet() {
    let query = DNSQuery::new(
        "www.example.com",
        DNSRecordType::A,
        DNSRecordClass::IN,
        DNSHeaderFlag::RecursionDesired,
    );
    let response = query.send_to_8_8_8_8().unwrap();

    let mut cursor = Cursor::new(&response[..]);
    let packet = DNSPacket::from_bytes(&mut cursor).unwrap();

    assert_eq!(packet.additionals.len(), 0);
    assert_eq!(packet.authorities.len(), 0);
    assert_eq!(packet.questions.len(), 1);
    assert_eq!(packet.answers.len(), 1);

    assert_eq!(
        packet.questions[0],
        DNSQuestion {
            name: "www.example.com".into(),
            r#type: DNSRecordType::A,
            class: DNSRecordClass::IN
        }
    );

    assert_eq!(packet.answers[0].class, DNSRecordClass::IN);
    assert_eq!(packet.answers[0].r#type, DNSRecordType::A);
    assert_eq!(packet.answers[0].name, "www.example.com".to_string());
    assert_eq!(packet.answers[0].data, b"]\xb8\xd8\"".to_vec());

    let header = packet.header;
    assert_eq!(header.flags, DNSHeaderFlag::Other(33152));
    assert_eq!(header.num_questions, 1);
    assert_eq!(header.num_answers, 1);
    assert_eq!(header.num_authorities, 0);
    assert_eq!(header.num_additionals, 0);

    assert_eq!(packet.ip(), Some("93.184.216.34".to_string()));
}

#[test]
fn test_parse_dns_packet_metafilter() {
    let query = DNSQuery::new(
        "www.metafilter.com",
        DNSRecordType::A,
        DNSRecordClass::IN,
        DNSHeaderFlag::RecursionDesired,
    );
    let response = query.send_to_8_8_8_8().unwrap();

    let mut cursor = Cursor::new(&response[..]);
    let packet = DNSPacket::from_bytes(&mut cursor).unwrap();

    assert_eq!(packet.additionals.len(), 0);
    assert_eq!(packet.authorities.len(), 0);
    assert_eq!(packet.questions.len(), 1);
    assert_eq!(packet.answers.len(), 2);

    assert_eq!(
        packet.questions[0],
        DNSQuestion {
            name: "www.metafilter.com".into(),
            r#type: DNSRecordType::A,
            class: DNSRecordClass::IN
        }
    );

    assert_eq!(packet.answers[0].class, DNSRecordClass::IN);
    assert_eq!(packet.answers[0].r#type, DNSRecordType::CNAME);
    assert_eq!(packet.answers[0].name, "www.metafilter.com".to_string());
    assert_eq!(packet.answers[1].data, [54, 203, 56, 158]);

    let header = packet.header;
    assert_eq!(header.flags, DNSHeaderFlag::Other(33152));
    assert_eq!(header.num_questions, 1);
    assert_eq!(header.num_answers, 2);
    assert_eq!(header.num_authorities, 0);
    assert_eq!(header.num_additionals, 0);

    assert_eq!(packet.ip(), Some("54.203.56.158".to_string()));
}

#[test_case("www.metafilter.com", "54.203.56.158"; "another broken one?")]
#[test_case("www.example.com", "93.184.216.34"; "check example.com")]
fn test_lookup_domain(domain_name: &str, expected: &str) {
    let observed = lookup_domain(domain_name).unwrap();
    assert_eq!(observed, expected.to_string());
}

#[test]
fn test_resolve() {
    use env_logger::init;
    init();

    let resolved = resolve("facebook.com", DNSRecordType::A).unwrap();
    println!("{:#?}", resolved);
}

#[test]
fn foo() {
    let record = DNSRecord {
        r#type: DNSRecordType::CNAME,
        name: "visit-before.wizard107.messwithdns.com".to_string(),
        class: DNSRecordClass::IN,
        ttl: 100,
        data: vec![
            6, 111, 114, 97, 110, 103, 101, 4, 106, 118, 110, 115, 2, 99, 97, 0,
        ],
    };

    assert_eq!(
        record.try_get_data_as_string(),
        Some("orange.jvns.ca".to_string())
    );
}
