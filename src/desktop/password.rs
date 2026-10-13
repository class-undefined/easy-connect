use super::*;

struct PasswordView {
    parent: gpui::WeakEntity<Desktop>,
    live: Arc<Mutex<Live>>,
    old: Entity<InputState>,
    new: Entity<InputState>,
    confirm: Entity<InputState>,
    error: Option<String>,
}
impl Render for PasswordView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let notice = self.live.lock().ok().and_then(|s| s.notice.clone());
        div()
            .size_full()
            .bg(rgb(0x10161e))
            .text_color(rgb(0xdce6ee))
            .p(px(16.))
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(field("当前密码", &self.old))
            .child(field("新密码", &self.new))
            .child(field("确认新密码", &self.confirm))
            .when_some(self.error.clone().or(notice), |s, e| {
                s.child(div().text_size(px(12.)).text_color(rgb(0xe1ad68)).child(e))
            })
            .child(
                button("submit-password", "修改密码", true).on_click(cx.listener(
                    |view, _, window, cx| {
                        let old = Zeroizing::new(view.old.read(cx).value().to_string());
                        let new = Zeroizing::new(view.new.read(cx).value().to_string());
                        if new.as_str() != view.confirm.read(cx).value().as_ref() {
                            view.error = Some("两次输入的新密码不一致".into());
                            cx.notify();
                            return;
                        }
                        if old.is_empty() || new.is_empty() {
                            view.error = Some("请填写当前密码和新密码".into());
                            cx.notify();
                            return;
                        }
                        let _ = view.parent.update(cx, |parent, cx| {
                            let preferences = parent.preferences(cx);
                            let live = parent.controller.live.clone();
                            parent.controller.action(move || {
                                if service::request(Request::Status).ok().is_some_and(|s| {
                                    matches!(
                                        s.phase,
                                        Phase::Connected | Phase::Connecting | Phase::Stopping
                                    )
                                }) {
                                    bail!("请先断开连接，再修改密码");
                                }
                                let config = crate::cli::profile(
                                    &preferences.gateway,
                                    (!preferences.cert_sha256.is_empty())
                                        .then_some(preferences.cert_sha256.as_str()),
                                )?;
                                ec_compat::password::change_password(
                                    &config,
                                    &preferences.username,
                                    &old,
                                    &new,
                                )?;
                                let saved = save(&preferences, &new);
                                if let Ok(mut state) = live.lock() {
                                    state.replacement_password = Some(new);
                                }
                                saved.context("密码已修改，但本地保存失败；请用新密码连接")?;
                                Ok(())
                            });
                        });
                        view.error = None;
                        view.new.update(cx, |s, cx| s.set_value("", window, cx));
                        view.confirm.update(cx, |s, cx| s.set_value("", window, cx));
                        cx.notify();
                    },
                )),
            )
    }
}
impl Desktop {
    pub(super) fn open_password(&mut self, cx: &mut Context<Self>) {
        if self.tailscale_client {
            if let Ok(mut live) = self.controller.live.lock() {
                live.notice = Some("切换到 VPN 模式后才能修改 VPN 账号密码".into());
            }
            return;
        }
        self.startup_pending = false;
        if let Some(handle) = self.password_window
            && handle
                .update(cx, |_, window, _| window.activate_window())
                .is_ok()
        {
            return;
        }
        let parent = cx.weak_entity();
        let live = self.controller.live.clone();
        let old = Zeroizing::new(self.password.read(cx).value().to_string());
        let bounds = Bounds::centered(None, size(px(400.), px(350.)), cx);
        match cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                titlebar: Some(TitlebarOptions {
                    title: Some("修改 VPN 密码".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            |window, cx| {
                let old = cx.new(|cx| {
                    let mut s = InputState::new(window, cx).masked(true);
                    s.set_value(old.to_string(), window, cx);
                    s
                });
                let new = cx.new(|cx| InputState::new(window, cx).masked(true));
                let confirm = cx.new(|cx| InputState::new(window, cx).masked(true));
                let view = cx.new(|_| PasswordView {
                    parent,
                    live,
                    old,
                    new,
                    confirm,
                    error: None,
                });
                cx.new(|cx| Root::new(view, window, cx))
            },
        ) {
            Ok(handle) => self.password_window = Some(handle.into()),
            Err(error) => {
                if let Ok(mut live) = self.controller.live.lock() {
                    live.notice = Some(error.to_string());
                }
            }
        }
    }
}
