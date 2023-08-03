Rust FFI bindings to the epan module of libwireshark.

This module is used to write Wireshark dissectors. As such, the user is
expected to have libwireshark.so and Wireshark's header files installed on
their system. In the event that libwireshark.so cannot be found, this crate
will build a dynamic library from source to link against, for the sake of
compilation.

By default, pre-generated bindings are used. To produce the bindings at build
time via bindgen, build this crate with the `bindgen` feature.

In case pkg-config cannot tell us where to find libwireshark.so, a path to the
directory containing the dynamic library can be set via the `WIRESHARK_LIB_DIR`
environment variable.

