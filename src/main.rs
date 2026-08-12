#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(target_os = "windows")]
fn main() -> eframe::Result {
    const INITIAL_WINDOW_SIZE: [f32; 2] = [1280.0, 720.0];
    const MINIMUM_WINDOW_SIZE: [f32; 2] = [480.0, 420.0];

    let _single_instance = match rust_vpn_splitter::windows::acquire_single_instance() {
        Ok(Some(guard)) => guard,
        Ok(None) => return Ok(()),
        Err(error) => {
            eprintln!("{error}");
            return Ok(());
        }
    };

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("VPN 分流管理器")
            .with_icon(
                eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon.png"))
                    .expect("bundled application icon must be valid PNG"),
            )
            .with_inner_size(INITIAL_WINDOW_SIZE)
            .with_min_inner_size(MINIMUM_WINDOW_SIZE)
            .with_resizable(true)
            .with_maximized(false),
        centered: true,
        persist_window: false,
        ..Default::default()
    };

    eframe::run_native(
        "VPN 分流管理器",
        options,
        Box::new(|creation_context| {
            Ok(Box::new(rust_vpn_splitter::app::SplitterApp::new(
                creation_context,
            )))
        }),
    )
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("rust-vpn-splitter currently supports Windows only.");
}
