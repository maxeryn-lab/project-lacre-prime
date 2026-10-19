use lacre_core::access::VerifiedFrame;
use lacre_core::frame::LacreFrame;
use lacre_core::session::SessionId;

fn main() {
    let frame = LacreFrame {
        session_id: SessionId([0u8; 16]),
        index: 0,
        total_fragments: Some(1),
        is_last: true,
        payload: vec![1, 2, 3],
    };
    let _forged = VerifiedFrame::new(&frame);
}
