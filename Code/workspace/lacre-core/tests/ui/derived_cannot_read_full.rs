use lacre_core::access::{ContentView, DerivedContent};

fn read(view: &ContentView<DerivedContent>) -> usize {
    view.content_bytes().len()
}

fn main() {
    let _ = read;
}
