use lacre_core::access::{ContentView, NoContent};
use lacre_core::frame::LacreFrame;

fn read(view: &ContentView<NoContent>) -> usize {
    view.content_bytes().len()
}

fn main() {
    let _ = read;
    let _: Option<LacreFrame> = None;
}
