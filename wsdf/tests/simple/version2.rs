use wsdf::version;

version!("5.10.01", 10, 100);

fn main() {
    assert_eq!(
        plugin_version,
        ['5' as i8, '.' as i8, '1' as i8, '0' as i8, '.' as i8, '0' as i8, '1' as i8, 0_i8]
    );
    assert_eq!(plugin_want_major, 10_i32);
    assert_eq!(plugin_want_minor, 100_i32);
}
