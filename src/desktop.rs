//! GPUI desktop shell. Secrets remain in the OS vault and privileged broker input.
use crate::service::{self, Phase, Request, Status};
use anyhow::{Context as _, Result, bail};
use gpui::{
    AnyWindowHandle, Application, Bounds, Context, Div, Entity, FontWeight, IntoElement, Render,
    Stateful, Task, TitlebarOptions, Window, WindowBounds, WindowOptions, div, prelude::*, px, rgb,
    size,
};
use gpui_component::{
    Disableable, Root, Sizable, Theme, ThemeMode,
    button::{Button, ButtonVariants},
    input::{Input, InputState},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(target_os = "macos")]
use std::process::Command;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tray_icon::{
    TrayIcon, TrayIconBuilder,
    menu::{Menu, MenuEvent, MenuItem},
};
use zeroize::Zeroizing;

mod controller;
mod password;
mod resources;
mod tailscale;
mod updates;
use controller::{Controller, Live, Readiness};
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
    #[serde(default, skip_serializing_if = "String::is_empty")]
    cert_sha256: String,
    #[serde(default = "enabled")]
    auto_login: bool,
    #[serde(default = "enabled")]
    auto_update: bool,
    #[serde(default)]
    tailscale_client: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    tailscale_router: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tailscale_routes_before: Option<bool>,
}
fn enabled() -> bool {
    true
}
impl Default for Preferences {
    fn default() -> Self {
        Self {
            gateway: String::new(),
            username: String::new(),
            remember: true,
            cert_sha256: String::new(),
            auto_login: true,
            auto_update: true,
            tailscale_client: false,
            tailscale_router: String::new(),
            tailscale_routes_before: None,
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
        use windows_sys::Win32::{
            Foundation::{CloseHandle, WAIT_OBJECT_0},
            System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject},
            UI::Shell::{
                SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
            },
        };
        let mut info = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
            lpVerb: operation.as_ptr(),
            lpFile: file.as_ptr(),
            lpParameters: arguments.as_ptr(),
            nShow: 0,
            ..Default::default()
        };
        // SAFETY: all UTF-16 buffers live for this call, and cbSize matches info.
        if unsafe { ShellExecuteExW(&mut info) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("安装程序未启动或管理员授权被取消");
        }
        if info.hProcess.is_null() {
            bail!("无法确认后台安装程序的运行状态");
        }
        let mut code = 0;
        // SAFETY: ShellExecuteExW returned an owned process handle. Wait on the
        // controller thread, inspect its exit code, then close the handle once.
        let success = unsafe {
            let success = WaitForSingleObject(info.hProcess, INFINITE) == WAIT_OBJECT_0
                && GetExitCodeProcess(info.hProcess, &mut code) != 0;
            CloseHandle(info.hProcess);
            success
        };
        if !success || code != 0 {
            bail!("后台安装失败（退出码 {code}），请重试");
        }
    }
    Ok(())
}

enum TailOutcome {
    Mode {
        enabled: bool,
        before: Option<bool>,
        summary: Option<tailscale::Summary>,
    },
    Checked(tailscale::Summary),
}
struct Desktop {
    gateway: Entity<InputState>,
    username: Entity<InputState>,
    password: Entity<InputState>,
    cert_sha256: Entity<InputState>,
    remember: bool,
    auto_login: bool,
    auto_update: bool,
    advanced: bool,
    tailscale_client: bool,
    tailscale_router: Entity<InputState>,
    tailscale_routes_before: Option<bool>,
    tailscale_summary: Option<tailscale::Summary>,
    tailscale_outcome: Arc<Mutex<Option<TailOutcome>>>,
    startup_pending: bool,
    updates: Arc<Mutex<UpdateState>>,
    last_update: Instant,
    commands: Arc<Mutex<Vec<MenuCommand>>>,
    log_window: Option<AnyWindowHandle>,
    about_window: Option<AnyWindowHandle>,
    password_window: Option<AnyWindowHandle>,
    logs_item: MenuItem,
    about_item: MenuItem,
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
        gateway.update(cx, |s, cx| {
            s.set_value(preferences.gateway.clone(), window, cx)
        });
        username.update(cx, |s, cx| {
            s.set_value(preferences.username.clone(), window, cx)
        });
        if preferences.remember
            && !preferences.tailscale_client
            && let Ok(entry) = vault(&preferences)
            && let Ok(secret) = entry.get_password()
        {
            let secret = Zeroizing::new(secret);
            password.update(cx, |s, cx| s.set_value(secret.to_string(), window, cx));
        }
        let cert_sha256 = cx.new(|cx| {
            InputState::new(window, cx).placeholder("SHA-256 指纹，留空使用系统证书校验")
        });
        cert_sha256.update(cx, |s, cx| {
            s.set_value(preferences.cert_sha256.clone(), window, cx)
        });
        let tailscale_router = cx.new(|cx| {
            InputState::new(window, cx).placeholder("出口主机名或 Tailscale IP，留空自动检测")
        });
        tailscale_router.update(cx, |s, cx| {
            s.set_value(preferences.tailscale_router.clone(), window, cx)
        });
        let commands = Arc::new(Mutex::new(Vec::new()));
        install_menus(commands.clone(), cx);
        let initial_update = updates::initial_state();
        let should_check =
            preferences.auto_update && !matches!(initial_update, UpdateState::Failed { .. });
        let updates = Arc::new(Mutex::new(initial_update));
        if should_check {
            updates::check(updates.clone());
        }
        let menu = Menu::new();
        let show = MenuItem::new("显示 EasyConnect", true, None);
        let disconnect = MenuItem::new("断开隧道", true, None);
        let quit = MenuItem::new("退出", true, None);
        let logs_item = MenuItem::new("事件日志", true, None);
        let about_item = MenuItem::new("关于 EasyConnect", true, None);
        let updates_item = MenuItem::new("检查更新", true, None);
        menu.append_items(&[
            &show,
            &disconnect,
            &logs_item,
            &updates_item,
            &about_item,
            &quit,
        ])?;
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
            cert_sha256,
            remember: preferences.remember,
            auto_login: preferences.auto_login
                && preferences.remember
                && !preferences.tailscale_client,
            auto_update: preferences.auto_update,
            advanced: false,
            tailscale_client: preferences.tailscale_client,
            tailscale_router,
            tailscale_routes_before: preferences.tailscale_routes_before,
            tailscale_summary: None,
            tailscale_outcome: Arc::new(Mutex::new(None)),
            startup_pending: preferences.auto_login
                && preferences.remember
                && !preferences.tailscale_client,
            updates,
            last_update: Instant::now(),
            commands,
            log_window: None,
            about_window: None,
            password_window: None,
            logs_item,
            about_item,
            updates_item,
            controller: if preferences.tailscale_client {
                Controller::for_tailscale()
            } else {
                Controller::new()
            },
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
        if view.tailscale_client {
            view.check_tailscale(cx);
        }
        Ok(view)
    }
    fn tick(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let outcome = self
            .tailscale_outcome
            .lock()
            .ok()
            .and_then(|mut value| value.take());
        match outcome {
            Some(TailOutcome::Mode {
                enabled,
                before,
                summary,
            }) => {
                self.tailscale_client = enabled;
                self.tailscale_routes_before = before;
                self.tailscale_summary = summary;
                self.startup_pending = false;
                if enabled {
                    self.auto_login = false;
                    self.controller = Controller::for_tailscale();
                } else {
                    self.controller = Controller::new();
                    if self.remember
                        && let Ok(entry) = vault(&self.preferences(cx))
                        && let Ok(password) = entry.get_password()
                    {
                        let password = Zeroizing::new(password);
                        self.password
                            .update(cx, |s, cx| s.set_value(password.to_string(), window, cx));
                    }
                }
            }
            Some(TailOutcome::Checked(summary)) => self.tailscale_summary = Some(summary),
            None => {}
        }

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

        if updates::install_if_ready(&self.updates, &self.controller) {
            self.startup_pending = false;
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
            let status = self.controller.live.lock().ok().and_then(|s| {
                (s.readiness == Readiness::Ready && !s.busy && !s.quitting)
                    .then(|| s.status.clone())
                    .flatten()
            });
            if let Some(status) = status {
                self.startup_pending = false;
                if self.auto_login
                    && self.remember
                    && status.phase == Phase::Disconnected
                    && status.session_end.is_none()
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

        let (phase, can_disconnect) = self
            .controller
            .live
            .lock()
            .map(|s| (s.phase(), s.can_disconnect()))
            .unwrap_or_default();
        let _ = self.tray.set_icon(Some(
            tray_icon(phase == Some(Phase::Connected))
                .unwrap_or_else(|_| self.tray_icon_fallback()),
        ));
        let _ = self
            .tray
            .set_tooltip(Some(format!("EasyConnect · {}", phase_style(phase).0)));
        self.disconnect.set_enabled(can_disconnect);
        while let Ok(event) = MenuEvent::receiver().try_recv() {
            let command = if event.id == *self.show.id() {
                Some(MenuCommand::Show)
            } else if event.id == *self.disconnect.id() {
                Some(MenuCommand::Disconnect)
            } else if event.id == *self.logs_item.id() {
                Some(MenuCommand::Logs)
            } else if event.id == *self.about_item.id() {
                Some(MenuCommand::About)
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
        if self.tailscale_client {
            self.check_tailscale(cx);
            return;
        }
        let preferences = Preferences {
            gateway: self.gateway.read(cx).value().to_string(),
            username: self.username.read(cx).value().to_string(),
            remember: self.remember,
            auto_login: self.auto_login,
            auto_update: self.auto_update,
            tailscale_client: self.tailscale_client,
            tailscale_router: self.tailscale_router.read(cx).value().trim().to_owned(),
            tailscale_routes_before: self.tailscale_routes_before,
            cert_sha256: self.cert_sha256.read(cx).value().trim().to_owned(),
        };
        let password = Zeroizing::new(self.password.read(cx).value().to_string());
        let accepted = self.controller.connect(move || {
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
            if accepted && !self.remember {
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
    fn check_tailscale(&mut self, cx: &mut Context<Self>) {
        let router = self.tailscale_router.read(cx).value().trim().to_owned();
        let outcome = self.tailscale_outcome.clone();
        self.controller.action(move || {
            let summary = tailscale::check(&router)?;
            *outcome
                .lock()
                .map_err(|_| anyhow::anyhow!("Tailscale 状态锁异常"))? =
                Some(TailOutcome::Checked(summary));
            Ok(())
        });
    }
    fn switch_tailscale(&mut self, cx: &mut Context<Self>) {
        let eligible = self.controller.live.lock().is_ok_and(|live| {
            !live.busy
                && !live.quitting
                && !matches!(
                    live.phase(),
                    Some(Phase::Connecting | Phase::Connected | Phase::Stopping)
                )
        });
        if !eligible {
            if let Ok(mut live) = self.controller.live.lock() {
                live.notice = Some("请先断开本机 VPN 或等待当前操作完成，再切换模式".into());
            }
            return;
        }
        let enabled = !self.tailscale_client;
        let mut preferences = self.preferences(cx);
        let password = Zeroizing::new(self.password.read(cx).value().to_string());
        let outcome = self.tailscale_outcome.clone();
        self.controller.action(move || {
            let (summary, before) = if enabled {
                let (summary, before) = tailscale::activate(&preferences.tailscale_router)?;
                (Some(summary), Some(before))
            } else {
                if let Some(before) = preferences.tailscale_routes_before {
                    tailscale::restore(before)?;
                }
                (None, None)
            };
            preferences.tailscale_client = enabled;
            preferences.tailscale_routes_before = before;
            if enabled {
                preferences.auto_login = false;
            }
            if let Err(error) = save(&preferences, &password) {
                if enabled && let Some(before) = before {
                    let _ = tailscale::restore(before);
                } else if !enabled {
                    let _ = tailscale::check(&preferences.tailscale_router);
                }
                return Err(error);
            }
            *outcome
                .lock()
                .map_err(|_| anyhow::anyhow!("Tailscale 状态锁异常"))? = Some(TailOutcome::Mode {
                enabled,
                before,
                summary,
            });
            Ok(())
        });
    }
    fn preferences(&self, cx: &Context<Self>) -> Preferences {
        Preferences {
            gateway: self.gateway.read(cx).value().to_string(),
            username: self.username.read(cx).value().to_string(),
            remember: self.remember,
            cert_sha256: self.cert_sha256.read(cx).value().trim().to_owned(),
            auto_login: self.auto_login,
            auto_update: self.auto_update,
            tailscale_client: self.tailscale_client,
            tailscale_router: self.tailscale_router.read(cx).value().trim().to_owned(),
            tailscale_routes_before: self.tailscale_routes_before,
        }
    }
    fn persist(&self, cx: &Context<Self>) {
        let preferences = self.preferences(cx);
        let password = Zeroizing::new(self.password.read(cx).value().to_string());
        self.controller.action(move || {
            if preferences.tailscale_client {
                tailscale::check(&preferences.tailscale_router)?;
            }
            save(&preferences, &password)
        });
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
                self.controller.quit();
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
        let readiness = live.as_ref().map(|s| s.readiness).unwrap_or_default();
        let phase = live.as_ref().and_then(|s| s.phase());
        let can_connect = live.as_ref().is_some_and(|s| s.can_connect());
        let can_disconnect = live.as_ref().is_some_and(|s| s.can_disconnect());
        let connect_label = if self.tailscale_client {
            "检查 Tailscale 连接"
        } else {
            live.as_ref()
                .map(|s| s.connect_label())
                .unwrap_or("正在准备…")
        };
        // gpui-component disables click handlers on loading buttons. Keep the
        // connecting action clickable so the same button can cancel it.
        let loading =
            live.as_ref().is_some_and(|s| s.loading()) && phase != Some(Phase::Connecting);
        let notice = live.as_ref().and_then(|s| s.notice.clone());
        drop(live);
        let session_end = status
            .as_ref()
            .filter(|_| !matches!(phase, Some(Phase::Connecting | Phase::Stopping)))
            .and_then(|s| s.session_end.as_ref());
        let show_resources = status.as_ref().is_some_and(resources::visible);
        let (state, color) = if self.tailscale_client {
            ("Tailscale 子网模式", 0x8bb8e8)
        } else if session_end.is_some() {
            ("连接已结束", 0xe1ad68)
        } else {
            phase_style(phase)
        };
        let update = self.updates.lock().map(|s| s.clone()).unwrap_or_default();
        let update_label = update.label();
        let manual_update_url = update.manual_url();
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
                        Button::new("updates")
                            .label(update_label)
                            .small()
                            .rounded_none()
                            .when(update.can_install(), |button| button.primary())
                            .disabled(update.busy())
                            .on_click(cx.listener(|view, _, _, _| {
                                updates::activate(view.updates.clone());
                                view.last_update = Instant::now();
                            })),
                    ),
            )
            .child(
                div()
                    .id(if show_resources {
                        "resource-content"
                    } else if session_end.is_some() {
                        "session-ended-content"
                    } else {
                        "connection-content"
                    })
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .p(px(16.))
                    .when_some(session_end, |s, reason| {
                        s.child(
                            div()
                                .id("session-ended")
                                .mb(px(12.))
                                .p(px(10.))
                                .border_1()
                                .border_color(rgb(0x725734))
                                .bg(rgb(0x30271e))
                                .text_color(rgb(0xe1ad68))
                                .child(reason.message()),
                        )
                    })
                    .when(show_resources, |s| {
                        s.child(
                            div()
                                .flex()
                                .flex_col()
                                .gap(px(14.))
                                .child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .justify_between()
                                        .child(
                                            div()
                                                .text_size(px(16.))
                                                .font_weight(FontWeight::BOLD)
                                                .child("可用资源"),
                                        )
                                        .child(
                                            Button::new("disconnect")
                                                .label(if phase == Some(Phase::Stopping) {
                                                    "正在断开…"
                                                } else {
                                                    "断开连接"
                                                })
                                                .rounded_none()
                                                .disabled(!can_disconnect)
                                                .on_click(cx.listener(|view, _, _, cx| {
                                                    view.startup_pending = false;
                                                    view.controller.disconnect();
                                                    cx.notify();
                                                })),
                                        ),
                                )
                                .child(resources::catalog(
                                    &status.as_ref().expect("connected status").resource_catalog,
                                )),
                        )
                    })
                    .when(!show_resources, |s| {
                        s.child(
                            div()
                                .id("connection-form")
                                .w_full()
                                .flex()
                                .flex_col()
                                .gap(px(12.))
                                .when(!self.tailscale_client,|s|{s
                                .child(field("网关 URL", &self.gateway))
                                .child(field("账号", &self.username))
                                .child(field("密码", &self.password))
                                .child(
                                    div()
                                        .flex()
                                        .gap(px(22.))
                                        .child(
                                            toggle("remember", "记住密码", self.remember).on_click(
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
                                            ),
                                        )
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
                                })
                                .child(
                                    div().flex().gap(px(8.)).child(
                                        Button::new("connect")
                                            .label(connect_label)
                                            .primary()
                                            .rounded_none()
                                            .h(px(36.))
                                            .flex_1()
                                            .loading(loading)
                                            .disabled(!can_connect && !can_disconnect)
                                            .on_click(cx.listener(|view, _, window, cx| {
                                                view.startup_pending = false;
                                                let can_disconnect = view
                                                    .controller
                                                    .live
                                                    .lock()
                                                    .is_ok_and(|s| s.can_disconnect());
                                                if can_disconnect {
                                                    view.controller.disconnect();
                                                    cx.notify();
                                                } else {
                                                    view.connect(window, cx);
                                                }
                                            })),
                                    ),
                                )
                                .when(self.tailscale_client,|s| {
                                    s.child(div().text_color(rgb(0x91a2b4)).child("使用已部署的 Tailscale 子网出口；请先安装并登录 Tailscale。"))
                                      .when_some(self.tailscale_summary.clone(),|s,summary|s.child(format!("最近检查：{} 个在线出口，{} 条已批准 IPv4 路由",summary.routers,summary.routes)))
                                })
                                .when_some(policy, |s, policy| {
                                    s.child(
                                        div()
                                            .flex()
                                            .flex_col()
                                            .gap(px(8.))
                                            .text_color(rgb(0xe1ad68))
                                            .child(policy.message())
                                            .child(
                                                button("change-password", "修改密码", true)
                                                    .on_click(cx.listener(|view, _, _, cx| {
                                                        view.open_password(cx)
                                                    })),
                                            ),
                                    )
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
                                            .child(toggle("tailscale-client","Tailscale 客户端模式",self.tailscale_client)
                                                .on_click(cx.listener(|view,_,_,cx|view.switch_tailscale(cx))))
                                            .child(field("Tailscale 子网出口（可选）",&self.tailscale_router))
                                            .child(div().text_color(rgb(0x91a2b4)).child("开启后接收已批准的 IPv4 子网路由，并停用本机 VPN 自动登录。关闭时恢复原来的路由接收设置。"))
                                            .when(!self.tailscale_client,|s|s.child(field("证书 SHA-256",&self.cert_sha256)))
                                            .child(
                                                button(
                                                    "manual-change-password",
                                                    "修改 VPN 密码",
                                                    false,
                                                )
                                                .on_click(cx.listener(|view, _, _, cx| {
                                                    view.open_password(cx)
                                                })),
                                            )
                                            .child(
                                                button("save-settings", "保存设置", false)
                                                    .on_click(cx.listener(|view, _, _, cx| {
                                                        view.persist(cx)
                                                    })),
                                            ),
                                    )
                                }),
                        )
                    })
                    .when(update.can_install(), |s| {
                        s.child(
                            div()
                                .mt(px(12.))
                                .text_color(rgb(0x91a2b4))
                                .child("一键更新会下载新版、断开 VPN，并安装重启应用。"),
                        )
                    })
                    .when_some(notice, |s, notice| {
                        s.child(div().mt(px(12.)).text_color(rgb(0xe1ad68)).child(notice))
                    })
                    .when(matches!(update, UpdateState::Failed { .. }), |s| {
                        if let UpdateState::Failed { message, .. } = update {
                            s.child(div().mt(px(12.)).text_color(rgb(0xe1ad68)).child(message))
                        } else {
                            s
                        }
                    })
                    .when_some(manual_update_url, |s, url| {
                        s.child(
                            button("manual-update", "手动下载安装包", false)
                                .on_click(cx.listener(move |_, _, _, cx| cx.open_url(&url))),
                        )
                    }),
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
                            .child(
                                div()
                                    .text_color(rgb(0x9babb9))
                                    .child(format!("v{}", env!("CARGO_PKG_VERSION"))),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(8.))
                            .text_color(rgb(if readiness == Readiness::Ready {
                                0x72cfa7
                            } else {
                                0xe1ad68
                            }))
                            .child(readiness.label())
                            .when(readiness == Readiness::Failed, |s| {
                                s.child(
                                    Button::new("retry-prepare")
                                        .label("重试")
                                        .small()
                                        .rounded_none()
                                        .on_click(cx.listener(|view, _, _, cx| {
                                            view.controller.retry();
                                            cx.notify();
                                        })),
                                )
                            }),
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

struct DesktopAssets;
impl gpui::AssetSource for DesktopAssets {
    fn load(&self, path: &str) -> Result<Option<std::borrow::Cow<'static, [u8]>>> {
        Ok((path == "icons/loader.svg")
            .then(|| std::borrow::Cow::Borrowed(include_bytes!("../assets/loader.svg").as_slice())))
    }
    fn list(&self, path: &str) -> Result<Vec<gpui::SharedString>> {
        Ok(if "icons/loader.svg".starts_with(path) {
            vec!["icons/loader.svg".into()]
        } else {
            vec![]
        })
    }
}

pub fn run() -> Result<()> {
    Application::new().with_assets(DesktopAssets).run(|cx| {
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
    fn preferences_roundtrip_preserves_existing_certificate_trust() {
        let fresh = serde_json::to_string(&Preferences::default()).unwrap();
        assert!(!fresh.contains("cert_sha256"));
        assert!(serde_json::from_str::<Preferences>(&fresh).is_ok());
        let legacy: Preferences = serde_json::from_str(r#"{"gateway":"https://example.com","username":"user","remember":true,"cert_sha256":"saved-pin"}"#).unwrap();
        let saved = serde_json::to_string(&legacy).unwrap();
        assert_eq!(
            serde_json::from_str::<Preferences>(&saved)
                .unwrap()
                .cert_sha256,
            "saved-pin"
        );
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
    #[test]
    fn legacy_settings_do_not_enable_tailscale_or_restore_unowned_route_preferences() {
        let legacy: Preferences = serde_json::from_str(
            r#"{"gateway":"https://vpn.example.com","username":"user","remember":true}"#,
        )
        .unwrap();
        assert!(!legacy.tailscale_client);
        assert!(legacy.tailscale_routes_before.is_none());
        assert!(legacy.tailscale_router.is_empty());
        let defaults = Preferences::default();
        assert!(defaults.gateway.is_empty());
    }
}
