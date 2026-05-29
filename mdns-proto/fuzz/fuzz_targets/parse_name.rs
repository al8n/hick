#![no_main]
use libfuzzer_sys::fuzz_target;
use mdns_proto::wire::NameRef;

fuzz_target!(|data: &[u8]| {
    if let Ok((name, _)) = NameRef::try_parse(data, 0) {
        // Walk labels — must not panic, must terminate.
        for label in name.labels().take(4096) {
            let _ = label;
        }
    }
});
