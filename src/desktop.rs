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
    time::Duration,
};
use tray_icon::{
    TrayIcon, TrayIconBuilder,
    menu::{Menu, MenuEvent, MenuItem},
};
use zeroize::Zeroizing;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Preferences {
    gateway: String,
    username: String,
    remember: bool,
    cert_sha256: String,
}
impl Default for Preferences {
    fn default() -> Self {
        Self {
            gateway: "https://166.111.77.32:4430/".into(),
            username: String::new(),
            remember: false,
            cert_sha256: String::new(),
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
        vault(preferences)?.set_password(password)?;
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
                state.notice = Some(match result {
                    Ok(()) => "操作已提交".into(),
                    Err(error) => error.to_string(),
                });
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
    controller: Controller,
    tray: TrayIcon,
    show: MenuItem,
    disconnect: MenuItem,
    quit: MenuItem,
    poll: Option<Task<()>>,
    window: AnyWindowHandle,
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
        let pin = cx.new(|cx| {
            InputState::new(window, cx).placeholder("默认校验证书；自签名网关可填写 SHA-256")
        });
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
        let menu = Menu::new();
        let show = MenuItem::new("显示 EasyConnect", true, None);
        let disconnect = MenuItem::new("断开隧道", true, None);
        let quit = MenuItem::new("退出", true, None);
        menu.append_items(&[&show, &disconnect, &quit])?;
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
            controller: Controller::new(),
            tray,
            show,
            disconnect,
            quit,
            poll: None,
            window: window_handle,
        };
        view.poll = Some(cx.spawn(async move |view, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(250))
                    .await;
                if view
                    .update(cx, |view, cx| {
                        view.tick(cx);
                        cx.notify();
                    })
                    .is_err()
                {
                    break;
                }
            }
        }));
        Ok(view)
    }
    fn tick(&mut self, cx: &mut Context<Self>) {
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
            if event.id == *self.show.id() {
                cx.activate(true);
                let _ = self.window.update(cx, |_, window, _| {
                    #[cfg(target_os = "windows")]
                    show_window(window, true);
                    window.activate_window();
                });
            } else if event.id == *self.disconnect.id() {
                self.controller.disconnect();
            } else if event.id == *self.quit.id() {
                let _ = service::request(Request::Disconnect);
                cx.quit();
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
            cert_sha256: self.pin.read(cx).value().to_string(),
        };
        let password = Zeroizing::new(self.password.read(cx).value().to_string());
        if !service::installed() {
            if let Ok(mut s) = self.controller.live.lock() {
                s.notice = Some("请先安装后台服务；管理员授权仅用于首次安装或服务更新".into());
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

fn label(text: &str) -> Div {
    div()
        .text_size(px(11.))
        .text_color(rgb(0x83909e))
        .mb(px(4.))
        .child(text.to_owned())
}
fn metric(key: &str, value: String) -> Div {
    div()
        .flex_1()
        .border_1()
        .border_color(rgb(0x2d3745))
        .p(px(10.))
        .child(label(key))
        .child(
            div()
                .text_size(px(17.))
                .text_color(rgb(0xe9eef5))
                .child(value),
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
        .border_color(rgb(if primary { 0x22d3b0 } else { 0x3c4858 }))
        .bg(rgb(if primary { 0x22d3b0 } else { 0x1a222d }))
        .text_color(rgb(if primary { 0x071414 } else { 0xd9e1eb }))
        .text_size(px(12.))
        .cursor_pointer()
        .child(text.to_owned())
}
impl Render for Desktop {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let live = self.controller.live.lock().ok();
        let status = live.as_ref().and_then(|s| s.status.clone());
        let busy = live.as_ref().is_some_and(|s| s.busy);
        let installed = live.as_ref().is_some_and(|s| s.installed);
        let notice = live.as_ref().and_then(|s| s.notice.clone());
        drop(live);
        let phase = status.as_ref().map(|s| s.phase);
        let (text, color) = match phase {
            Some(Phase::Connected) => ("已连接", 0x22d3b0),
            Some(Phase::Connecting) => ("连接中", 0xe8b64c),
            Some(Phase::Stopping) => ("正在断开", 0xe8b64c),
            Some(Phase::Failed) => ("连接失败", 0xf87171),
            _ => ("未连接", 0x8a98a8),
        };
        let log = status
            .as_ref()
            .map(|s| s.logs.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        div()
            .size_full()
            .bg(rgb(0x101720))
            .text_color(rgb(0xd9e1eb))
            .text_size(px(12.))
            .flex()
            .flex_col()
            .child(
                div()
                    .h(px(46.))
                    .px(px(16.))
                    .border_b_1()
                    .border_color(rgb(0x2d3745))
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .flex()
                            .gap(px(10.))
                            .child(
                                div()
                                    .text_size(px(17.))
                                    .font_weight(FontWeight::BOLD)
                                    .child("EasyConnect"),
                            )
                            .child(div().text_color(rgb(0x6f8297)).child("/ PRIVATE NETWORK")),
                    )
                    .child(div().text_color(rgb(color)).child(format!("■ {text}"))),
            )
            .child(
                div()
                    .flex()
                    .flex_1()
                    .min_h_0()
                    .child(
                        div()
                            .w(px(300.))
                            .flex_shrink_0()
                            .p(px(14.))
                            .border_r_1()
                            .border_color(rgb(0x2d3745))
                            .flex()
                            .flex_col()
                            .gap(px(12.))
                            .child(
                                div()
                                    .child(label("网关 URL"))
                                    .child(Input::new(&self.gateway).small().rounded_none()),
                            )
                            .child(
                                div()
                                    .child(label("账号"))
                                    .child(Input::new(&self.username).small().rounded_none()),
                            )
                            .child(
                                div()
                                    .child(label("密码"))
                                    .child(Input::new(&self.password).small().rounded_none()),
                            )
                            .child(
                                div()
                                    .id("remember")
                                    .cursor_pointer()
                                    .on_click(cx.listener(|view, _, _, cx| {
                                        if view.controller.live.lock().ok().is_some_and(|s| s.busy)
                                        {
                                            return;
                                        }
                                        view.remember = !view.remember;
                                        if !view.remember {
                                            view.controller.action(|| {
                                                if let Ok(path) = preferences_path()
                                                    && let Ok(bytes) = std::fs::read(path)
                                                    && let Ok(mut preferences) =
                                                        serde_json::from_slice::<Preferences>(
                                                            &bytes,
                                                        )
                                                {
                                                    preferences.remember = false;
                                                    save(&preferences, "")?;
                                                }
                                                Ok(())
                                            });
                                        }
                                        cx.notify();
                                    }))
                                    .child(format!(
                                        "{} 记住密码 · 系统凭据存储",
                                        if self.remember { "[■]" } else { "[ ]" }
                                    )),
                            )
                            .child(
                                div()
                                    .child(label("证书 SHA-256（可选）"))
                                    .child(Input::new(&self.pin).small().rounded_none()),
                            )
                            .child(
                                div()
                                    .flex()
                                    .gap(px(6.))
                                    .child(
                                        button(
                                            "connect",
                                            if busy { "处理中…" } else { "连接隧道" },
                                            true,
                                        )
                                        .flex_1()
                                        .on_click(
                                            cx.listener(|view, _, window, cx| {
                                                view.connect(window, cx)
                                            }),
                                        ),
                                    )
                                    .child(button("disconnect", "断开", false).on_click(
                                        cx.listener(|view, _, _, _| view.controller.disconnect()),
                                    )),
                            )
                            .child(
                                div()
                                    .border_t_1()
                                    .border_color(rgb(0x2d3745))
                                    .pt(px(12.))
                                    .child(label("权限服务"))
                                    .child(div().mb(px(8.)).child(if installed {
                                        "已安装 · 后续连接无需提权"
                                    } else {
                                        "未安装 · 首次需管理员授权"
                                    }))
                                    .child(
                                        button(
                                            "install",
                                            if installed {
                                                "更新后台服务"
                                            } else {
                                                "安装后台服务"
                                            },
                                            false,
                                        )
                                        .on_click(
                                            cx.listener(|view, _, _, _| {
                                                view.controller.action(install_service)
                                            }),
                                        ),
                                    ),
                            )
                            .child(
                                div()
                                    .mt_auto()
                                    .text_color(rgb(0x718298))
                                    .text_size(px(11.))
                                    .child(
                                        "TUN / IPv4 / TCP · UDP · ICMP\n资源网段与 DNS 从网关获取",
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .p(px(14.))
                            .flex()
                            .flex_col()
                            .gap(px(10.))
                            .child(
                                div()
                                    .flex()
                                    .gap(px(8.))
                                    .child(metric(
                                        "虚拟地址",
                                        status
                                            .as_ref()
                                            .and_then(|s| s.address.clone())
                                            .unwrap_or_else(|| "—".into()),
                                    ))
                                    .child(metric(
                                        "网络接口",
                                        status
                                            .as_ref()
                                            .and_then(|s| s.interface.clone())
                                            .unwrap_or_else(|| "—".into()),
                                    )),
                            )
                            .child(
                                div()
                                    .flex()
                                    .gap(px(8.))
                                    .child(metric(
                                        "资源 / 组",
                                        status
                                            .as_ref()
                                            .map(|s| format!("{} / {}", s.resources, s.groups))
                                            .unwrap_or_else(|| "0 / 0".into()),
                                    ))
                                    .child(metric(
                                        "路由",
                                        status
                                            .as_ref()
                                            .map(|s| s.routes.to_string())
                                            .unwrap_or_else(|| "0".into()),
                                    )),
                            )
                            .child(
                                div()
                                    .text_color(rgb(if notice.is_some() {
                                        0xe8b64c
                                    } else {
                                        0x83909e
                                    }))
                                    .child(notice.unwrap_or_else(|| {
                                        "首次安装后台服务后，使用 URL 和账号密码即可连接。".into()
                                    })),
                            )
                            .child(
                                div()
                                    .border_1()
                                    .border_color(rgb(0x2d3745))
                                    .flex_1()
                                    .min_h_0()
                                    .flex()
                                    .flex_col()
                                    .child(
                                        div()
                                            .px(px(10.))
                                            .py(px(6.))
                                            .border_b_1()
                                            .border_color(rgb(0x2d3745))
                                            .child("事件日志 / LIVE"),
                                    )
                                    .child(
                                        div()
                                            .id("logs")
                                            .flex_1()
                                            .min_h_0()
                                            .overflow_y_scroll()
                                            .p(px(10.))
                                            .font_family(if cfg!(windows) {
                                                "Consolas"
                                            } else {
                                                "Menlo"
                                            })
                                            .text_size(px(11.))
                                            .children(
                                                log.into_iter().map(|s| div().mb(px(4.)).child(s)),
                                            ),
                                    ),
                            ),
                    ),
            )
            .child(
                div()
                    .h(px(24.))
                    .px(px(12.))
                    .border_t_1()
                    .border_color(rgb(0x2d3745))
                    .flex()
                    .items_center()
                    .justify_between()
                    .text_size(px(10.))
                    .text_color(rgb(0x83909e))
                    .child(format!(
                        "{}  /  第三方 VPN 客户端",
                        if cfg!(windows) { "WINDOWS" } else { "macOS" }
                    ))
                    .child(format!(
                        "v{}  ·  关闭窗口保持连接  ·  托盘退出会断开",
                        env!("CARGO_PKG_VERSION")
                    )),
            )
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
        let bounds = Bounds::centered(None, size(px(780.), px(560.)), cx);
        let result = cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
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
}
