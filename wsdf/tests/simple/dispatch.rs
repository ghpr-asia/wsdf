#[derive(wsdf::Dispatch)]
pub enum Foo {
    Bar,
    Baz(usize),
    Qux { eggs: u64 },
}

fn main() {
    assert_eq!(FooDispatch::Bar as usize, 0);
    assert_eq!(FooDispatch::Baz as usize, 1);
    assert_eq!(FooDispatch::Qux as usize, 2);
}
