// Lehen Edge — Tauri v2 binary entrypoint.
//
// All real wiring lives in the library (``lehen_edge_lib``); this binary
// just hands control to it. Splitting binary from library keeps the test
// surface for the deep-link handler and keyring commands sane.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    lehen_edge_lib::run();
}
