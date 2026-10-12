//! GPUI desktop shell. Secrets remain in the OS vault and privileged broker input.
use crate::service::{self, Phase, Request, Status};
use anyhow::{Context as _, Result, bail};
use gpui::{
    AnyWindowHandle, Application, Bounds, Context, Div, Entity, FontWeight, IntoElement, Render,
    Stateful, Task, TitlebarOptions, Window, WindowBounds, WindowOptions, div, prelude::*, px, rgb,
    size,
};
use gpui_component::{
    Root, Sizable, Theme, ThemeMode,
    input::{Input, InputState},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(target_os = "macos")]
use std::process::Command;
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tray_icon::{
    TrayIcon, TrayIconBuilder,
    menu::{Menu, MenuEvent, MenuItem},
};
use zeroize::Zeroizing;

mod password;
mod updates;
use updates::UpdateState;
const AUTHOR: &str = "野漫横江";
gpui::actions!(
    easy_connect,
    [
        ShowMain,
        ConnectVpn,
        DisconnectVpn,
        ShowLogs,
        ShowAbout,
        ShowPassword,
        CheckUpdates,
        QuitApp
    ]
);

#[derive(Clone, Copy)]
enum MenuCommand {
    Show,
    Connect,
    Disconnect,
    Logs,
    About,
    Password,
    Updates,
    Quit,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Preferences {
    gateway: String,
    username: String,
    remember: bool,
    cert_sha256: String,
    #[serde(default = "enabled")]
    auto_login: bool,
    #[serde(default = "enabled")]
    auto_update: bool,
}
fn enabled() -> bool {
    true
}
impl Default for Preferences {
    fn default() -> Self {
        Self {
            gateway: "https://166.111.77.32:4430/".into(),
            username: String::new(),
            remember: true,
            cert_sha256: String::new(),
            auto_login: true,
            auto_update: true,
        }
    }
}
fn preferences_path() -> Result<PathBuf> {
    Ok(dirs::config_dir()
        .context("configuration directory unavailable")?
        .join("easy-connect")
        .join("desktop.json"))
}
fn vault(preferences: &Preferences) -> Result<keyring::Entry> {
    let key = hex::encode(Sha256::digest(format!(
        "{}\0{}",
        preferences.gateway.trim_end_matches('/'),
        preferences.username
    )));
    Ok(keyring::Entry::new("com.easy-connect.desktop", &key)?)
}
fn save(preferences: &Preferences, password: &str) -> Result<()> {
    if preferences.remember {
        if !preferences.username.trim().is_empty() && !password.is_empty() {
            vault(preferences)?.set_password(password)?;
        }
    } else {
        match vault(preferences)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(error) => return Err(error.into()),
        }
    }
    let path = preferences_path()?;
    std::fs::create_dir_all(path.parent().context("missing configuration directory")?)?;
    let temp = path.with_extension("tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    let mut file = options.open(&temp)?;
    file.write_all(&serde_json::to_vec_pretty(preferences)?)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(temp, path)?;
    Ok(())
}
fn cli_path() -> Result<PathBuf> {
    let path = std::env::current_exe()?.with_file_name(if cfg!(windows) {
        "easy-connect.exe"
    } else {
        "easy-connect"
    });
    if !path.is_file() {
        bail!("the CLI executable is missing beside the desktop app");
    }
    Ok(path)
}

#[cfg(target_os = "windows")]
fn show_window(window: &Window, visible: bool) {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    if let Ok(handle) = HasWindowHandle::window_handle(window)
        && let RawWindowHandle::Win32(handle) = handle.as_raw()
    {
        // SAFETY: the native handle belongs to this retained GPUI window.
        unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::ShowWindow(
                handle.hwnd.get() as _,
                if visible { 9 } else { 0 },
            );
        }
    }
}
fn install_service() -> Result<()> {
    let binary = cli_path()?;
    let owner = service::current_owner()?;
    #[cfg(target_os = "macos")]
    {
        let quote = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
        let command = format!(
            "{} install-service --owner {}",
            quote(&binary.to_string_lossy()),
            quote(&owner)
        );
        let script = format!(
            "do shell script {} with administrator privileges",
            serde_json::to_string(&command)?
        );
        let output = Command::new("/usr/bin/osascript")
            .args(["-e", &script])
            .output()?;
        if !output.status.success() {
            bail!(
                "安装失败或管理员授权被取消：{}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::ffi::OsStrExt;
        let wide = |s: &std::ffi::OsStr| s.encode_wide().chain(Some(0)).collect::<Vec<_>>();
        let operation = wide(std::ffi::OsStr::new("runas"));
        let file = wide(binary.as_os_str());
        let arguments = wide(std::ffi::OsStr::new(&format!(
            "install-service --owner {owner}"
        )));
        // SAFETY: all UTF-16 buffers are NUL-terminated and live for the complete call.
        let result = unsafe {
            windows_sys::Win32::UI::Shell::ShellExecuteW(
                std::ptr::null_mut(),
                operation.as_ptr(),
                file.as_ptr(),
                arguments.as_ptr(),
                std::ptr::null(),
                1,
            )
        };
        if result as usize <= 32 {
            bail!("安装程序未启动或管理员授权被取消");
        }
    }
    Ok(())
}

#[derive(Default)]
struct Live {
    status: Option<Status>,
    notice: Option<String>,
    installed: bool,
    busy: bool,
    quit_ready: bool,
    replacement_password: Option<Zeroizing<String>>,
}
struct Controller {
    live: Arc<Mutex<Live>>,
    stop: Arc<AtomicBool>,
}
impl Controller {
    fn new() -> Self {
        let live = Arc::new(Mutex::new(Live::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let state = live.clone();
        let closed = stop.clone();
        std::thread::spawn(move || {
            while !closed.load(Ordering::Relaxed) {
                let result = service::request(Request::Status);
                if let Ok(mut state) = state.lock() {
                    state.installed = service::installed();
                    if let Ok(status) = result {
                        state.status = Some(status);
                    } else {
                        state.status = None;
                    }
                }
                std::thread::sleep(Duration::from_millis(750));
            }
        });
        Self { live, stop }
    }
    fn action(&self, work: impl FnOnce() -> Result<()> + Send + 'static) {
        if let Ok(mut state) = self.live.lock() {
            if state.busy {
                return;
            }
            state.busy = true;
            state.notice = None;
        }
        let live = self.live.clone();
        std::thread::spawn(move || {
            let result = work();
            if let Ok(mut state) = live.lock() {
                state.busy = false;
                state.notice = result.err().map(|error| error.to_string());
            }
        });
    }
    fn disconnect(&self) {
        self.action(|| {
            service::request(Request::Disconnect)?;
            Ok(())
        });
    }
}
impl Drop for Controller {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

struct Desktop {
    gateway: Entity<InputState>,
    username: Entity<InputState>,
    password: Entity<InputState>,
    pin: Entity<InputState>,
    remember: bool,
    auto_login: bool,
    auto_update: bool,
    advanced: bool,
    startup_pending: bool,
    updates: Arc<Mutex<UpdateState>>,
    last_update: Instant,
    commands: Arc<Mutex<Vec<MenuCommand>>>,
    log_window: Option<AnyWindowHandle>,
    about_window: Option<AnyWindowHandle>,
    password_window: Option<AnyWindowHandle>,
    logs_item: MenuItem,
    updates_item: MenuItem,
    controller: Controller,
    tray: TrayIcon,
    show: MenuItem,
    disconnect: MenuItem,
    quit: MenuItem,
    poll: Option<Task<()>>,
}
fn tray_icon(connected: bool) -> Result<tray_icon::Icon> {
    let mut pixels = vec![0_u8; 18 * 18 * 4];
    for y in 2..16 {
        for x in 2..16 {
            if x == 2
                || x == 15
                || y == 2
                || y == 15
                || (y == 8 && x > 4 && x < 13)
                || (connected && y >= 11 && (6..=11).contains(&x))
            {
                let i = (y * 18 + x) * 4;
                pixels[i..i + 4].copy_from_slice(if cfg!(windows) {
                    if connected {
                        &[34, 211, 176, 255]
                    } else {
                        &[130, 152, 174, 255]
                    }
                } else {
                    &[20, 20, 20, 255]
                });
            }
        }
    }
    Ok(tray_icon::Icon::from_rgba(pixels, 18, 18)?)
}
impl Desktop {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Result<Self> {
        let preferences = preferences_path()
            .ok()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice::<Preferences>(&b).ok())
            .unwrap_or_default();
        let gateway =
            cx.new(|cx| InputState::new(window, cx).placeholder("https://vpn.example.com:443"));
        let username = cx.new(|cx| InputState::new(window, cx).placeholder("VPN 账号"));
        let password = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("VPN 密码")
                .masked(true)
        });
        let pin = cx.new(|cx| InputState::new(window, cx).placeholder("可选"));
        gateway.update(cx, |s, cx| {
            s.set_value(preferences.gateway.clone(), window, cx)
        });
        username.update(cx, |s, cx| {
            s.set_value(preferences.username.clone(), window, cx)
        });
        pin.update(cx, |s, cx| {
            s.set_value(preferences.cert_sha256.clone(), window, cx)
        });
        if preferences.remember
            && let Ok(entry) = vault(&preferences)
            && let Ok(secret) = entry.get_password()
        {
            let secret = Zeroizing::new(secret);
            password.update(cx, |s, cx| s.set_value(secret.to_string(), window, cx));
        }
        let commands = Arc::new(Mutex::new(Vec::new()));
        install_menus(commands.clone(), cx);
        let updates = Arc::new(Mutex::new(UpdateState::Idle));
        if preferences.auto_update {
            updates::check(updates.clone());
        }
        let menu = Menu::new();
        let show = MenuItem::new("显示 EasyConnect", true, None);
        let disconnect = MenuItem::new("断开隧道", true, None);
        let quit = MenuItem::new("退出", true, None);
        let logs_item = MenuItem::new("事件日志", true, None);
        let updates_item = MenuItem::new("检查更新", true, None);
        menu.append_items(&[&show, &disconnect, &logs_item, &updates_item, &quit])?;
        let tray = TrayIconBuilder::new()
            .with_icon(tray_icon(false)?)
            .with_icon_as_template(cfg!(target_os = "macos"))
            .with_tooltip("EasyConnect · 未连接")
            .with_menu(Box::new(menu))
            .build()?;
        let window_handle = window.window_handle();
        window.on_window_should_close(cx, |window, _cx| {
            #[cfg(target_os = "macos")]
            _cx.hide();
            #[cfg(target_os = "windows")]
            show_window(window, false);
            #[cfg(target_os = "macos")]
            let _ = window;
            false
        });
        let mut view = Self {
            gateway,
            username,
            password,
            pin,
            remember: preferences.remember,
            auto_login: preferences.auto_login && preferences.remember,
            auto_update: preferences.auto_update,
            advanced: false,
            startup_pending: preferences.auto_login && preferences.remember,
            updates,
            last_update: Instant::now(),
            commands,
            log_window: None,
            about_window: None,
            password_window: None,
            logs_item,
            updates_item,
            controller: Controller::new(),
            tray,
            show,
            disconnect,
            quit,
            poll: None,
        };
        view.poll = Some(cx.spawn(async move |view, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(250))
                    .await;
                if view
                    .upgrade()
                    .ok_or_else(|| anyhow::anyhow!("window closed"))
                    .and_then(|view| {
                        window_handle.update(cx, |_, window, cx| {
                            view.update(cx, |view, cx| {
                                view.tick(window, cx);
                                cx.notify();
                            });
                        })
                    })
                    .is_err()
                {
                    break;
                }
            }
        }));
        Ok(view)
    }
    fn tick(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let changed = self
            .controller
            .live
            .lock()
            .ok()
            .and_then(|mut s| s.replacement_password.take());
        if let Some(secret) = changed {
            self.password
                .update(cx, |s, cx| s.set_value(secret.to_string(), window, cx));
            if let Some(handle) = self.password_window.take() {
                let _ = handle.update(cx, |_, window, _| window.remove_window());
            }
        }

        if self
            .controller
            .live
            .lock()
            .ok()
            .is_some_and(|s| s.quit_ready)
        {
            cx.quit();
            return;
        }
        if self.auto_update && self.last_update.elapsed() >= Duration::from_secs(12 * 60 * 60) {
            updates::check(self.updates.clone());
            self.last_update = Instant::now();
        }
        if self.startup_pending {
            let status = self
                .controller
                .live
                .lock()
                .ok()
                .and_then(|s| s.status.clone());
            if let Some(status) = status {
                self.startup_pending = false;
                if self.auto_login
                    && self.remember
                    && status.phase == Phase::Disconnected
                    && !self.username.read(cx).value().is_empty()
                    && !self.password.read(cx).value().is_empty()
                {
                    self.connect(window, cx);
                }
            }
        }
        let commands = self
            .commands
            .lock()
            .map(|mut q| std::mem::take(&mut *q))
            .unwrap_or_default();
        for command in commands {
            self.menu_command(command, window, cx);
        }
        if let Some(handle) = self.password_window {
            let _ = handle.update(cx, |_, window, _| window.refresh());
        }
        if let Some(logs) = self.log_window {
            let _ = logs.update(cx, |_, _, cx| cx.refresh_windows());
        }

        let connected = self
            .controller
            .live
            .lock()
            .ok()
            .and_then(|s| s.status.as_ref().map(|s| s.phase == Phase::Connected))
            .unwrap_or(false);
        let _ = self.tray.set_icon(Some(
            tray_icon(connected).unwrap_or_else(|_| self.tray_icon_fallback()),
        ));
        let _ = self.tray.set_tooltip(Some(if connected {
            "EasyConnect · 已连接"
        } else {
            "EasyConnect · 未连接"
        }));
        self.disconnect.set_enabled(connected);
        while let Ok(event) = MenuEvent::receiver().try_recv() {
            let command = if event.id == *self.show.id() {
                Some(MenuCommand::Show)
            } else if event.id == *self.disconnect.id() {
                Some(MenuCommand::Disconnect)
            } else if event.id == *self.logs_item.id() {
                Some(MenuCommand::Logs)
            } else if event.id == *self.updates_item.id() {
                Some(MenuCommand::Updates)
            } else if event.id == *self.quit.id() {
                Some(MenuCommand::Quit)
            } else {
                None
            };
            if let Some(command) = command {
                self.menu_command(command, window, cx);
            }
        }
    }
    fn tray_icon_fallback(&self) -> tray_icon::Icon {
        tray_icon(false).expect("static tray icon dimensions are valid")
    }
    fn connect(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let preferences = Preferences {
            gateway: self.gateway.read(cx).value().to_string(),
            username: self.username.read(cx).value().to_string(),
            remember: self.remember,
            auto_login: self.auto_login,
            auto_update: self.auto_update,
            cert_sha256: self.pin.read(cx).value().to_string(),
        };
        let password = Zeroizing::new(self.password.read(cx).value().to_string());
        if !service::installed() {
            if let Ok(mut s) = self.controller.live.lock() {
                s.notice = Some("请先安装后台服务".into());
            }
            cx.notify();
            return;
        }
        self.controller.action(move || {
            crate::cli::validate_gateway(&preferences.gateway)?;
            if preferences.username.is_empty() || password.is_empty() {
                bail!("请填写 VPN 账号与密码");
            }
            let status = service::request(Request::Connect {
                gateway: preferences.gateway.clone(),
                username: preferences.username.clone(),
                password: password.to_string(),
                cert_sha256: (!preferences.cert_sha256.trim().is_empty())
                    .then(|| preferences.cert_sha256.trim().to_owned()),
            })?;
            save(&preferences, &password)?;
            if status.phase == Phase::Failed {
                bail!("连接失败，请查看事件日志");
            }
            Ok(())
        });
        self.password.update(cx, |s, cx| {
            if !self.remember {
                s.set_value("", window, cx);
            }
        });
        cx.notify();
    }
}

// Input::h only affects multiline editors; use Styled::h for a single-line field.
fn field(title: &'static str, state: &Entity<InputState>) -> Div {
    div()
        .w_full()
        .flex_shrink_0()
        .flex()
        .flex_col()
        .gap(px(6.))
        .child(
            div()
                .h(px(16.))
                .text_size(px(12.))
                .text_color(rgb(0x91a2b4))
                .child(title),
        )
        .child(
            gpui::Styled::h(Input::new(state).small().rounded_none(), px(36.))
                .w_full()
                .flex_shrink_0()
                .px(px(10.))
                .py(px(6.))
                .text_size(px(14.)),
        )
}
fn button(id: &'static str, text: &str, primary: bool) -> Stateful<Div> {
    div()
        .id(id)
        .h(px(30.))
        .px(px(10.))
        .flex()
        .items_center()
        .justify_center()
        .border_1()
        .border_color(rgb(if primary { 0x52849e } else { 0x303e4e }))
        .bg(rgb(if primary { 0x243e50 } else { 0x202c39 }))
        .text_color(rgb(if primary { 0xc0eaff } else { 0xdce6ee }))
        .text_size(px(12.))
        .cursor_pointer()
        .hover(|s| s.bg(rgb(0x304458)).border_color(rgb(0x5b829d)))
        .active(|s| s.bg(rgb(0x172633)))
        .child(text.to_owned())
}
fn install_menus(queue: Arc<Mutex<Vec<MenuCommand>>>, cx: &mut gpui::App) {
    macro_rules! register {
        ($action:ty, $command:expr) => {{
            let queue = queue.clone();
            cx.on_action(move |_: &$action, _| {
                if let Ok(mut q) = queue.lock() {
                    q.push($command);
                }
            });
        }};
    }
    register!(ShowMain, MenuCommand::Show);
    register!(ShowAbout, MenuCommand::About);
    register!(ShowPassword, MenuCommand::Password);
    register!(ConnectVpn, MenuCommand::Connect);
    register!(DisconnectVpn, MenuCommand::Disconnect);
    register!(ShowLogs, MenuCommand::Logs);
    register!(CheckUpdates, MenuCommand::Updates);
    register!(QuitApp, MenuCommand::Quit);
    cx.bind_keys([gpui::KeyBinding::new("secondary-q", QuitApp, None)]);
    #[cfg(target_os = "macos")]
    cx.set_menus(vec![
        gpui::Menu {
            name: "EasyConnect".into(),
            items: vec![
                gpui::MenuItem::action("关于 EasyConnect", ShowAbout),
                gpui::MenuItem::action("显示主窗口", ShowMain),
                gpui::MenuItem::action("检查更新…", CheckUpdates),
                gpui::MenuItem::separator(),
                gpui::MenuItem::action("退出 EasyConnect", QuitApp),
            ],
        },
        gpui::Menu {
            name: "连接".into(),
            items: vec![
                gpui::MenuItem::action("连接", ConnectVpn),
                gpui::MenuItem::action("断开", DisconnectVpn),
                gpui::MenuItem::separator(),
                gpui::MenuItem::action("修改 VPN 密码…", ShowPassword),
            ],
        },
        gpui::Menu {
            name: "编辑".into(),
            items: vec![
                gpui::MenuItem::action("撤销", gpui_component::input::Undo),
                gpui::MenuItem::action("重做", gpui_component::input::Redo),
                gpui::MenuItem::separator(),
                gpui::MenuItem::action("剪切", gpui_component::input::Cut),
                gpui::MenuItem::action("复制", gpui_component::input::Copy),
                gpui::MenuItem::action("粘贴", gpui_component::input::Paste),
                gpui::MenuItem::action("全选", gpui_component::input::SelectAll),
            ],
        },
        gpui::Menu {
            name: "窗口".into(),
            items: vec![
                gpui::MenuItem::action("主窗口", ShowMain),
                gpui::MenuItem::action("事件日志", ShowLogs),
            ],
        },
    ]);
}

impl Desktop {
    fn preferences(&self, cx: &Context<Self>) -> Preferences {
        Preferences {
            gateway: self.gateway.read(cx).value().to_string(),
            username: self.username.read(cx).value().to_string(),
            remember: self.remember,
            cert_sha256: self.pin.read(cx).value().to_string(),
            auto_login: self.auto_login,
            auto_update: self.auto_update,
        }
    }
    fn persist(&self, cx: &Context<Self>) {
        let preferences = self.preferences(cx);
        let password = Zeroizing::new(self.password.read(cx).value().to_string());
        self.controller
            .action(move || save(&preferences, &password));
    }
    fn menu_command(&mut self, command: MenuCommand, window: &mut Window, cx: &mut Context<Self>) {
        match command {
            MenuCommand::Show => {
                cx.activate(true);
                #[cfg(target_os = "windows")]
                show_window(window, true);
                window.activate_window();
            }
            MenuCommand::Connect => self.connect(window, cx),
            MenuCommand::Disconnect => {
                self.startup_pending = false;
                self.controller.disconnect();
            }
            MenuCommand::Updates => {
                self.last_update = Instant::now();
                updates::check(self.updates.clone());
                cx.activate(true);
                #[cfg(target_os = "windows")]
                show_window(window, true);
                window.activate_window();
            }
            MenuCommand::Logs => self.open_logs(cx),
            MenuCommand::About => self.open_about(cx),
            MenuCommand::Password => self.open_password(cx),
            MenuCommand::Quit => {
                self.startup_pending = false;
                let live = self.controller.live.clone();
                std::thread::spawn(move || {
                    let _ = service::request(Request::Disconnect);
                    if let Ok(mut s) = live.lock() {
                        s.quit_ready = true;
                    }
                });
            }
        }
    }
    fn open_logs(&mut self, cx: &mut Context<Self>) {
        cx.activate(true);
        if let Some(handle) = self.log_window
            && handle
                .update(cx, |_, window, _| window.activate_window())
                .is_ok()
        {
            return;
        }
        let live = self.controller.live.clone();
        let bounds = Bounds::centered(None, size(px(700.), px(420.)), cx);
        match cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                window_min_size: Some(size(px(420.), px(390.))),
                titlebar: Some(TitlebarOptions {
                    title: Some("EasyConnect · 事件日志".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            |window, cx| {
                let logs = cx.new(|_| LogView { live });
                cx.new(|cx| Root::new(logs, window, cx))
            },
        ) {
            Ok(handle) => self.log_window = Some(handle.into()),
            Err(error) => {
                if let Ok(mut live) = self.controller.live.lock() {
                    live.notice = Some(error.to_string());
                }
            }
        }
    }
}

fn phase_style(phase: Option<Phase>) -> (&'static str, u32) {
    match phase {
        Some(Phase::Connected) => ("已连接", 0x72cfa7),
        Some(Phase::Connecting) => ("连接中", 0xe1ad68),
        Some(Phase::Stopping) => ("正在断开", 0xe1ad68),
        Some(Phase::Failed) => ("连接失败", 0xf87171),
        _ => ("未连接", 0x91a2b4),
    }
}
fn toggle(id: &'static str, text: &'static str, checked: bool) -> Stateful<Div> {
    div()
        .id(id)
        .flex()
        .items_center()
        .gap(px(7.))
        .h(px(26.))
        .cursor_pointer()
        .hover(|s| s.text_color(rgb(0x6bc9f3)))
        .child(
            div()
                .size(px(12.))
                .border_1()
                .border_color(rgb(if checked { 0x6bc9f3 } else { 0x546475 }))
                .flex()
                .items_center()
                .justify_center()
                .when(checked, |s| s.child(div().size(px(6.)).bg(rgb(0x6bc9f3)))),
        )
        .child(text)
}
struct LogView {
    live: Arc<Mutex<Live>>,
}
impl Render for LogView {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        let logs = self
            .live
            .lock()
            .ok()
            .and_then(|s| s.status.as_ref().map(|s| s.logs.clone()))
            .unwrap_or_default();
        div()
            .size_full()
            .bg(rgb(0x10161e))
            .text_color(rgb(0xdce6ee))
            .child(
                div()
                    .id("event-log")
                    .size_full()
                    .overflow_y_scroll()
                    .p(px(12.))
                    .font_family(if cfg!(windows) { "Consolas" } else { "Menlo" })
                    .text_size(px(12.))
                    .when(logs.is_empty(), |s| s.child("暂无日志"))
                    .children(logs.into_iter().map(|line| div().mb(px(5.)).child(line))),
            )
    }
}
impl Render for Desktop {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let live = self.controller.live.lock().ok();
        let status = live.as_ref().and_then(|s| s.status.clone());
        let policy = status.as_ref().and_then(|s| {
            s.password_policy.clone().or_else(|| {
                s.logs
                    .iter()
                    .rev()
                    .find_map(|line| ec_compat::password::PasswordPolicy::from_log(line))
            })
        });
        let busy = live.as_ref().is_some_and(|s| s.busy);
        let installed = live.as_ref().is_some_and(|s| s.installed);
        let notice = live.as_ref().and_then(|s| s.notice.clone());
        drop(live);
        let (state, color) = phase_style(status.as_ref().map(|s| s.phase));
        let connected = status
            .as_ref()
            .is_some_and(|s| matches!(s.phase, Phase::Connected | Phase::Connecting));
        let update = self.updates.lock().map(|s| s.clone()).unwrap_or_default();
        let update_label = match &update {
            UpdateState::Available { version, .. } => format!("下载 v{version}"),
            UpdateState::Checking => "检查中…".into(),
            UpdateState::Current => "已是最新版".into(),
            _ => format!("v{} · 检查更新", env!("CARGO_PKG_VERSION")),
        };
        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(rgb(0x10161e))
            .text_color(rgb(0xdce6ee))
            .text_size(px(12.))
            .child(
                div()
                    .h(px(46.))
                    .flex_shrink_0()
                    .px(px(16.))
                    .flex()
                    .items_center()
                    .justify_between()
                    .bg(rgb(0x18212c))
                    .border_b_1()
                    .border_color(rgb(0x303e4e))
                    .child(
                        div()
                            .text_size(px(18.))
                            .font_weight(FontWeight::BOLD)
                            .child("EasyConnect"),
                    )
                    .child(
                        button(
                            "updates",
                            &update_label,
                            matches!(update, UpdateState::Available { .. }),
                        )
                        .on_click(cx.listener(|view, _, _, cx| {
                            let state = view.updates.lock().map(|s| s.clone()).unwrap_or_default();
                            if let UpdateState::Available { url, .. } = state {
                                cx.open_url(&url);
                            } else {
                                updates::check(view.updates.clone());
                                view.last_update = Instant::now();
                            }
                        })),
                    ),
            )
            .child(
                div()
                    .id("connection-form")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .p(px(16.))
                    .child(
                        div()
                            .w_full()
                            .flex()
                            .flex_col()
                            .gap(px(12.))
                            .child(field("网关 URL", &self.gateway))
                            .child(field("账号", &self.username))
                            .child(field("密码", &self.password))
                            .child(
                                div()
                                    .flex()
                                    .gap(px(22.))
                                    .child(toggle("remember", "记住密码", self.remember).on_click(
                                        cx.listener(|view, _, _, cx| {
                                            if view
                                                .controller
                                                .live
                                                .lock()
                                                .ok()
                                                .is_some_and(|s| s.busy)
                                            {
                                                return;
                                            }
                                            view.remember = !view.remember;
                                            if !view.remember {
                                                view.auto_login = false;
                                                view.startup_pending = false;
                                            }
                                            view.persist(cx);
                                            cx.notify();
                                        }),
                                    ))
                                    .child(
                                        toggle("auto-login", "启动时自动登录", self.auto_login)
                                            .on_click(cx.listener(|view, _, _, cx| {
                                                if view
                                                    .controller
                                                    .live
                                                    .lock()
                                                    .ok()
                                                    .is_some_and(|s| s.busy)
                                                {
                                                    return;
                                                }
                                                view.auto_login = !view.auto_login;
                                                if view.auto_login {
                                                    view.remember = true;
                                                }
                                                view.persist(cx);
                                                cx.notify();
                                            })),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .gap(px(8.))
                                    .child(
                                        button(
                                            "connect",
                                            if busy {
                                                "处理中…"
                                            } else if connected {
                                                "断开连接"
                                            } else {
                                                "连接"
                                            },
                                            true,
                                        )
                                        .flex_1()
                                        .on_click(
                                            cx.listener(move |view, _, window, cx| {
                                                if connected {
                                                    view.startup_pending = false;
                                                    view.controller.disconnect();
                                                } else {
                                                    view.connect(window, cx);
                                                }
                                            }),
                                        ),
                                    )
                                    .child(button("logs", "日志", false).on_click(
                                        cx.listener(|view, _, _, cx| view.open_logs(cx)),
                                    )),
                            )
                            .when_some(policy, |s, policy| {
                                s.child(
                                    div()
                                        .flex()
                                        .flex_col()
                                        .gap(px(8.))
                                        .text_color(rgb(0xe1ad68))
                                        .child(policy.message())
                                        .child(
                                            button("change-password", "修改密码", true).on_click(
                                                cx.listener(|view, _, _, cx| {
                                                    view.open_password(cx)
                                                }),
                                            ),
                                        ),
                                )
                            })
                            .when(!installed, |s| {
                                s.child(button("install", "安装后台服务", false).on_click(
                                    cx.listener(|view, _, _, _| {
                                        view.controller.action(install_service)
                                    }),
                                ))
                            })
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .child(
                                        toggle("auto-update", "自动检查更新", self.auto_update)
                                            .on_click(cx.listener(|view, _, _, cx| {
                                                if view
                                                    .controller
                                                    .live
                                                    .lock()
                                                    .ok()
                                                    .is_some_and(|s| s.busy)
                                                {
                                                    return;
                                                }
                                                view.auto_update = !view.auto_update;
                                                if view.auto_update {
                                                    updates::check(view.updates.clone());
                                                }
                                                view.persist(cx);
                                                cx.notify();
                                            })),
                                    )
                                    .child(
                                        button(
                                            "advanced",
                                            if self.advanced {
                                                "收起高级设置"
                                            } else {
                                                "高级设置"
                                            },
                                            false,
                                        )
                                        .on_click(
                                            cx.listener(|view, _, _, cx| {
                                                view.advanced = !view.advanced;
                                                cx.notify();
                                            }),
                                        ),
                                    ),
                            )
                            .when(self.advanced, |s| {
                                s.child(
                                    div()
                                        .flex()
                                        .flex_col()
                                        .gap(px(12.))
                                        .border_t_1()
                                        .border_color(rgb(0x303e4e))
                                        .pt(px(12.))
                                        .child(field("证书 SHA-256", &self.pin))
                                        .child(
                                            button(
                                                "manual-change-password",
                                                "修改 VPN 密码",
                                                false,
                                            )
                                            .on_click(
                                                cx.listener(|view, _, _, cx| {
                                                    view.open_password(cx)
                                                }),
                                            ),
                                        )
                                        .child(button("save-settings", "保存设置", false).on_click(
                                            cx.listener(|view, _, _, cx| view.persist(cx)),
                                        ))
                                        .when(installed, |s| {
                                            s.child(
                                                button("update-service", "更新后台服务", false)
                                                    .on_click(cx.listener(|view, _, _, _| {
                                                        view.controller.action(install_service)
                                                    })),
                                            )
                                        }),
                                )
                            })
                            .when_some(notice, |s, notice| {
                                s.child(div().text_color(rgb(0xe1ad68)).child(notice))
                            })
                            .when(matches!(update, UpdateState::Failed(_)), |s| {
                                if let UpdateState::Failed(message) = update {
                                    s.child(div().text_color(rgb(0xe1ad68)).child(message))
                                } else {
                                    s
                                }
                            }),
                    ),
            )
            .child(
                div()
                    .h(px(32.))
                    .flex_shrink_0()
                    .px(px(12.))
                    .flex()
                    .items_center()
                    .justify_between()
                    .bg(rgb(0x18212c))
                    .border_t_1()
                    .border_color(rgb(0x303e4e))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(8.))
                            .child(div().size(px(7.)).bg(rgb(color)))
                            .child(div().text_color(rgb(color)).child(state))
                            .when_some(status.and_then(|s| s.address), |s, address| {
                                s.child(address)
                            }),
                    )
                    .child(
                        button("about", "关于", false)
                            .on_click(cx.listener(|view, _, _, cx| view.open_about(cx))),
                    ),
            )
    }
}

struct AboutView;
impl Render for AboutView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .size_full()
            .bg(rgb(0x10161e))
            .text_color(rgb(0xdce6ee))
            .p(px(20.))
            .flex()
            .flex_col()
            .gap(px(14.))
            .child(
                div()
                    .text_size(px(20.))
                    .font_weight(FontWeight::BOLD)
                    .child("EasyConnect Rust"),
            )
            .child(format!("版本 {} · CLI + GUI", env!("CARGO_PKG_VERSION")))
            .child(format!("开发者：{AUTHOR} / class-undefined"))
            .child(
                button("project", "项目主页", false).on_click(cx.listener(|_, _, _, cx| {
                    cx.open_url("https://github.com/class-undefined/easy-connect")
                })),
            )
    }
}
impl Desktop {
    fn open_about(&mut self, cx: &mut Context<Self>) {
        cx.activate(true);
        if let Some(handle) = self.about_window
            && handle
                .update(cx, |_, window, _| window.activate_window())
                .is_ok()
        {
            return;
        }
        let bounds = Bounds::centered(None, size(px(350.), px(220.)), cx);
        match cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                titlebar: Some(TitlebarOptions {
                    title: Some("关于 EasyConnect".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            |window, cx| {
                let view = cx.new(|_| AboutView);
                cx.new(|cx| Root::new(view, window, cx))
            },
        ) {
            Ok(handle) => self.about_window = Some(handle.into()),
            Err(error) => {
                if let Ok(mut live) = self.controller.live.lock() {
                    live.notice = Some(error.to_string());
                }
            }
        }
    }
}

pub fn run() -> Result<()> {
    Application::new().run(|cx| {
        gpui_component::init(cx);
        Theme::change(ThemeMode::Dark, None, cx);
        let theme = Theme::global_mut(cx);
        theme.radius = px(0.);
        theme.radius_lg = px(0.);
        theme.shadow = false;
        theme.font_size = px(12.);
        theme.colors.background = rgb(0x10161e).into();
        theme.colors.foreground = rgb(0xdce6ee).into();
        theme.colors.border = rgb(0x303e4e).into();
        theme.colors.input = rgb(0x405064).into();
        theme.colors.primary = rgb(0x6bc9f3).into();
        theme.colors.ring = rgb(0x6bc9f3).into();
        theme.colors.caret = rgb(0x6bc9f3).into();
        theme.colors.muted_foreground = rgb(0x91a2b4).into();
        let bounds = Bounds::centered(None, size(px(440.), px(440.)), cx);
        let result = cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                window_min_size: Some(size(px(420.), px(390.))),
                titlebar: Some(TitlebarOptions {
                    title: Some("EasyConnect".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            |window, cx| {
                let view = cx
                    .new(|cx| Desktop::new(window, cx).expect("desktop UI initialization failed"));
                cx.new(|cx| Root::new(view, window, cx))
            },
        );
        if let Err(error) = result {
            eprintln!("Cannot open EasyConnect: {error}");
            cx.quit();
        }
        cx.activate(true);
    });
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preferences_never_serialize_passwords() {
        let value = serde_json::to_value(Preferences::default()).unwrap();
        assert!(value.get("password").is_none());
        assert!(serde_json::from_str::<Preferences>(r#"{"gateway":"https://example.com","username":"u","remember":true,"cert_sha256":"","password":"secret"}"#).is_err());
    }
    #[test]
    fn old_preferences_preserve_credentials_choices_and_gain_update_detection() {
        let preferences: Preferences = serde_json::from_str(r#"{"gateway":"https://example.com","username":"user","remember":false,"cert_sha256":""}"#).unwrap();
        assert!(!preferences.remember);
        assert!(preferences.auto_login);
        assert!(preferences.auto_update);
        let defaults = Preferences::default();
        assert!(defaults.remember);
        assert!(defaults.auto_login);
        assert!(defaults.auto_update);
    }
}
