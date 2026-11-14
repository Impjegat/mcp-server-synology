//! The tray icon: its state, its tooltip and its menu.

use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::AppHandle;

use crate::alerts::{tooltip, tray_state, Attention, TrayState};
use crate::{commands, show_main};

const STOPPED: &[u8] = include_bytes!("../icons/tray-stopped.png");
const RUNNING: &[u8] = include_bytes!("../icons/tray-running.png");
const ATTENTION: &[u8] = include_bytes!("../icons/tray-attention.png");

pub const TRAY_ID: &str = "main";

fn icon(state: TrayState) -> Image<'static> {
    let bytes = match state {
        TrayState::Stopped => STOPPED,
        TrayState::Running => RUNNING,
        TrayState::Attention => ATTENTION,
    };
    Image::from_bytes(bytes).expect("the tray icons are valid PNG files")
}

pub fn build(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open broker", true, None::<&str>)?;
    let sign_in = MenuItem::with_id(app, "sign-in-all", "Sign in all clients", true, None::<&str>)?;
    let show = MenuItem::with_id(app, "show", "Show app", true, None::<&str>)?;
    let stop = MenuItem::with_id(app, "stop", "Stop broker", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&open, &sign_in, &show, &separator, &stop, &quit])?;

    TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon(TrayState::Stopped))
        .tooltip(tooltip(false, None))
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => commands::spawn_open(app, "/"),
            "sign-in-all" => commands::spawn_open(app, "/login-all"),
            "show" => show_main(app),
            "stop" => commands::spawn_stop(app),
            "quit" => commands::quit(app),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } =
                event
            {
                show_main(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

/// Bring the icon and tooltip in line with what the broker is doing.
pub fn update(app: &AppHandle, running: bool, attention: Option<&Attention>) {
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_icon(Some(icon(tray_state(running, attention))));
        let _ = tray.set_tooltip(Some(tooltip(running, attention)));
    }
}
