Rust FFI bindings to the epan module of libwireshark.

This module is used to write Wireshark dissectors. As such, the user is
expected to have libwireshark.so and Wireshark's header files installed on
their system. In the event that libwireshark.so cannot be found, this crate
will build a dynamic library from source to link against, for the sake of
compilation.

**License**

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>
