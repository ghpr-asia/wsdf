use wsdf::version;

version!("0.0.1", 4, 0);

fn main() {
    assert_eq!(
        plugin_version,
        ['0' as i8, '.' as i8, '0' as i8, '.' as i8, '1' as i8, 0_i8]
    );
    assert_eq!(plugin_want_major, 4_i32);
    assert_eq!(plugin_want_minor, 0_i32);
}
