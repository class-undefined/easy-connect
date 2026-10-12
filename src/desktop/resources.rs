use super::*;
use crate::resources::{ResourceCatalog, ResourceEntry};
use std::collections::BTreeMap;

pub(super) fn visible(status: &Status) -> bool {
    status.session_end.is_none()
        && (status.phase == Phase::Connected
            || (status.phase == Phase::Stopping && status.address.is_some()))
}

struct Section<'a> {
    name: String,
    entries: Vec<&'a ResourceEntry>,
}

fn sections(catalog: &ResourceCatalog) -> Vec<Section<'_>> {
    let mut entries = BTreeMap::<&str, Vec<&ResourceEntry>>::new();
    for entry in &catalog.entries {
        entries.entry(&entry.group_id).or_default().push(entry);
    }
    let mut result = Vec::new();
    for group in &catalog.groups {
        if let Some(entries) = entries.remove(group.id.as_str()) {
            result.push(Section {
                name: if !group.name.is_empty() {
                    group.name.clone()
                } else if group.id.is_empty() {
                    "未分组".into()
                } else {
                    format!("资源组 {}", group.id)
                },
                entries,
            });
        }
    }
    if let Some(entries) = entries.remove("") {
        result.push(Section {
            name: "未分组".into(),
            entries,
        });
    }
    // A missing group definition must never hide an otherwise valid resource.
    let other: Vec<_> = catalog
        .entries
        .iter()
        .filter(|entry| entries.contains_key(entry.group_id.as_str()))
        .collect();
    if !other.is_empty() {
        result.push(Section {
            name: "其他资源".into(),
            entries: other,
        });
    }
    result
}

fn resource_name(entry: &ResourceEntry) -> &str {
    if !entry.name.is_empty() {
        &entry.name
    } else if !entry.host.is_empty() {
        &entry.host
    } else {
        "未命名资源"
    }
}

pub(super) fn catalog(catalog: &ResourceCatalog) -> Div {
    div()
        .w_full()
        .flex()
        .flex_col()
        .gap(px(14.))
        .child(div().text_color(rgb(0x91a2b4)).child(if catalog.truncated {
            format!("显示 {} 项服务器资源", catalog.entries.len())
        } else {
            format!("服务器发布了 {} 项资源", catalog.entries.len())
        }))
        .when(catalog.entries.is_empty(), |s| {
            s.child(
                div()
                    .p(px(16.))
                    .border_1()
                    .border_color(rgb(0x303e4e))
                    .bg(rgb(0x18212c))
                    .text_color(rgb(0x91a2b4))
                    .child("连接已建立，服务器未发布可展示的资源。"),
            )
        })
        .children(sections(catalog).into_iter().map(|section| {
            div()
                .w_full()
                .flex()
                .flex_col()
                .gap(px(7.))
                .child(
                    div()
                        .text_color(rgb(0x91a2b4))
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(format!("{} · {}", section.name, section.entries.len())),
                )
                .children(section.entries.into_iter().map(|entry| {
                    let is_default =
                        !entry.id.is_empty() && entry.id == catalog.default_resource_id;
                    div()
                        .w_full()
                        .p(px(10.))
                        .flex()
                        .flex_col()
                        .gap(px(6.))
                        .bg(rgb(0x18212c))
                        .border_1()
                        .border_color(rgb(0x303e4e))
                        .child(
                            div()
                                .flex()
                                .items_start()
                                .gap(px(8.))
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w_0()
                                        .text_size(px(14.))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .child(resource_name(entry).to_owned()),
                                )
                                .when(is_default, |s| {
                                    s.child(
                                        div()
                                            .flex_shrink_0()
                                            .text_size(px(11.))
                                            .text_color(rgb(0x72cfa7))
                                            .child("默认资源"),
                                    )
                                }),
                        )
                        .child(
                            div()
                                .text_color(rgb(0x91a2b4))
                                .child(if entry.host.is_empty() {
                                    "地址：服务器未提供".into()
                                } else {
                                    format!("地址：{}", entry.host)
                                }),
                        )
                        .when(!entry.port.is_empty(), |s| {
                            s.child(
                                div()
                                    .text_color(rgb(0x91a2b4))
                                    .child(format!("端口：{}", entry.port)),
                            )
                        })
                }))
        }))
        .when(catalog.truncated, |s| {
            s.child(
                div()
                    .text_color(rgb(0xe1ad68))
                    .child("资源目录已简化显示，部分资源或字段未完整展示。"),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::ResourceGroup;

    fn entry(id: &str, group: &str) -> ResourceEntry {
        ResourceEntry {
            id: id.into(),
            group_id: group.into(),
            ..Default::default()
        }
    }

    #[test]
    fn grouping_preserves_published_order_and_keeps_unmatched_resources() {
        let catalog = ResourceCatalog {
            groups: vec![
                ResourceGroup {
                    id: "b".into(),
                    name: "办公".into(),
                },
                ResourceGroup {
                    id: "a".into(),
                    name: "研发".into(),
                },
                ResourceGroup {
                    id: "b".into(),
                    name: "重复分组".into(),
                },
                ResourceGroup {
                    id: "empty".into(),
                    name: "空分组".into(),
                },
            ],
            entries: vec![
                entry("a1", "a"),
                entry("b1", "b"),
                entry("a2", "a"),
                entry("u1", ""),
                entry("o1", "missing"),
                entry("o2", "unknown"),
            ],
            ..Default::default()
        };
        let sections = sections(&catalog);
        assert_eq!(
            sections.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
            ["办公", "研发", "未分组", "其他资源"]
        );
        assert_eq!(
            sections
                .iter()
                .map(|s| s.entries.iter().map(|e| e.id.as_str()).collect::<Vec<_>>())
                .collect::<Vec<_>>(),
            [vec!["b1"], vec!["a1", "a2"], vec!["u1"], vec!["o1", "o2"]]
        );
    }

    #[test]
    fn missing_names_use_host_or_explicit_fallback() {
        let mut entry = entry("", "");
        assert_eq!(resource_name(&entry), "未命名资源");
        entry.host = "portal.example.com".into();
        assert_eq!(resource_name(&entry), "portal.example.com");
        entry.name = "工作门户".into();
        assert_eq!(resource_name(&entry), "工作门户");
    }

    #[test]
    fn resources_replace_form_only_for_an_established_connection() {
        let mut status = Status::default();
        assert!(!visible(&status));
        status.phase = Phase::Connecting;
        assert!(!visible(&status));
        status.phase = Phase::Stopping;
        assert!(!visible(&status));
        status.phase = Phase::Connected;
        assert!(visible(&status)); // An empty catalog still has a connected view.
        status.address = Some("10.0.0.2".into());
        status.phase = Phase::Stopping;
        assert!(visible(&status));
        status.phase = Phase::Failed;
        status.session_end = Some(ec_compat::session_status::SessionEndReason::PrivateKick);
        assert!(!visible(&status));
    }
}
