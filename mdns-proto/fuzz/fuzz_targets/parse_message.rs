#![no_main]
use libfuzzer_sys::fuzz_target;
use mdns_proto::wire::MessageReader;

fuzz_target!(|data: &[u8]| {
    if let Ok(reader) = MessageReader::try_parse(data) {
        for q in reader.questions() {
            let _ = q;
        }
        for r in reader.answers() {
            if let Ok(r) = r {
                let _ = r.rdata_view();
            }
        }
    }
});
