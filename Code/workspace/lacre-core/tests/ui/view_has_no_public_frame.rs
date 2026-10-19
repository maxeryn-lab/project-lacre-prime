use lacre_core::access::{ContentView, NoContent};

fn peek(view: &ContentView<NoContent>) -> usize {
    view.frame.payload.len()
}

fn main() {
    let _ = peek;
}
