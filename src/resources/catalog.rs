use super::PublishedResources;
use serde::{Deserialize, Serialize};
use std::io::Write;

const EVENT_PREFIX: &str = "EC_RESOURCE ";
const CATALOG_BYTE_LIMIT: usize = 384 * 1024;
const GROUP_BYTE_LIMIT: usize = 64 * 1024;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResourceEntry {
    pub id: String,
    pub name: String,
    pub group_id: String,
    pub host: String,
    pub port: String,
    pub resource_type: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResourceGroup {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResourceCatalog {
    pub entries: Vec<ResourceEntry>,
    pub groups: Vec<ResourceGroup>,
    pub default_resource_id: String,
    pub truncated: bool,
    #[serde(skip)]
    pub(crate) encoded_bytes: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ResourceEvent {
    Reset {
        default_resource_id: String,
        truncated: bool,
    },
    Group {
        group: ResourceGroup,
    },
    Entry {
        entry: ResourceEntry,
    },
}

fn bounded_text(value: &str, limit: usize, truncated: &mut bool) -> String {
    let mut result = String::new();
    for c in value.chars() {
        if c.is_control() {
            *truncated = true;
            continue;
        }
        if result.len() + c.len_utf8() > limit {
            *truncated = true;
            break;
        }
        result.push(c);
    }
    result
}

impl ResourceCatalog {
    pub fn from_published(published: &PublishedResources) -> Self {
        let mut catalog = Self::default();
        catalog.default_resource_id =
            bounded_text(&published.default_resource, 128, &mut catalog.truncated);
        for value in &published.groups {
            let group = ResourceGroup {
                id: bounded_text(
                    value["id"].as_str().unwrap_or(""),
                    128,
                    &mut catalog.truncated,
                ),
                name: bounded_text(
                    value["name"].as_str().unwrap_or(""),
                    256,
                    &mut catalog.truncated,
                ),
            };
            let bytes = serde_json::to_vec(&ResourceEvent::Group {
                group: group.clone(),
            })
            .expect("resource strings serialize")
            .len();
            if catalog.encoded_bytes + bytes > GROUP_BYTE_LIMIT {
                catalog.truncated = true;
                break;
            }
            catalog.encoded_bytes += bytes;
            catalog.groups.push(group);
        }
        for value in &published.entries {
            let mut field = |name: &str, limit| {
                bounded_text(
                    value[name].as_str().unwrap_or(""),
                    limit,
                    &mut catalog.truncated,
                )
            };
            let entry = ResourceEntry {
                id: field("id", 128),
                name: field("name", 256),
                group_id: field("group_id", 128),
                host: field("host", 2048),
                port: field("port", 256),
                resource_type: field("type", 32),
            };
            let bytes = serde_json::to_vec(&ResourceEvent::Entry {
                entry: entry.clone(),
            })
            .expect("resource strings serialize")
            .len();
            if catalog.encoded_bytes + bytes > CATALOG_BYTE_LIMIT - 1024 {
                catalog.truncated = true;
                break;
            }
            catalog.encoded_bytes += bytes;
            catalog.entries.push(entry);
        }
        catalog
    }

    // One bounded event per line: a catalog can exceed the worker's 8 KiB line
    // limit, while the RPC status (including logs and JSON escaping) stays <2 MiB.
    pub fn write_events(&self, mut output: impl Write) -> std::io::Result<()> {
        let events = std::iter::once(ResourceEvent::Reset {
            default_resource_id: self.default_resource_id.clone(),
            truncated: self.truncated,
        })
        .chain(
            self.groups
                .iter()
                .cloned()
                .map(|group| ResourceEvent::Group { group }),
        )
        .chain(
            self.entries
                .iter()
                .cloned()
                .map(|entry| ResourceEvent::Entry { entry }),
        );
        for event in events {
            output.write_all(EVENT_PREFIX.as_bytes())?;
            serde_json::to_writer(&mut output, &event)?;
            output.write_all(b"\n")?;
        }
        output.flush()
    }

    pub fn consume_event(&mut self, line: &str) -> bool {
        let Some(json) = line.strip_prefix(EVENT_PREFIX) else {
            return false;
        };
        // Do not expose malformed machine events as user-facing log lines.
        let Ok(event) = serde_json::from_str::<ResourceEvent>(json) else {
            return true;
        };
        if let ResourceEvent::Reset {
            default_resource_id,
            truncated,
        } = event
        {
            *self = Self {
                default_resource_id,
                truncated,
                encoded_bytes: json.len(),
                ..Default::default()
            };
        } else if self.encoded_bytes + json.len() > CATALOG_BYTE_LIMIT {
            self.truncated = true;
        } else {
            self.encoded_bytes += json.len();
            match event {
                ResourceEvent::Group { group } => self.groups.push(group),
                ResourceEvent::Entry { entry } => self.entries.push(entry),
                ResourceEvent::Reset { .. } => unreachable!(),
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_larger_than_a_worker_line_round_trips_with_groups() {
        let rows = (0..150).map(|id| format!(r#"<Rc id="{id}" name="资源 {id}" rc_grp_id="g1" host="10.1.0.{id}" port="443" type="1"/>"#)).collect::<String>();
        let published = PublishedResources::parse(format!(r#"<Resource><RcGroup id="g1" name="办公系统"/>{rows}<Other defaultRcId="2"/></Resource>"#).as_bytes()).unwrap();
        let catalog = ResourceCatalog::from_published(&published);
        let mut output = Vec::new();
        catalog.write_events(&mut output).unwrap();
        assert!(output.len() > 8192);
        let mut received = ResourceCatalog::default();
        for line in std::str::from_utf8(&output).unwrap().lines() {
            assert!(line.len() < 8192);
            assert!(received.consume_event(line));
        }
        assert_eq!(received.entries.len(), 150);
        assert_eq!(received.entries[2].name, "资源 2");
        assert_eq!(received.entries[2].port, "443");
        assert_eq!(received.entries[2].resource_type, "1");
        assert_eq!(received.groups[0].name, "办公系统");
        assert_eq!(received.default_resource_id, "2");
        assert!(!received.truncated);
    }

    #[test]
    fn oversized_fields_and_catalog_stay_within_transport_budget() {
        let mut published = PublishedResources::parse(b"<Resource/>").unwrap();
        let entry =
            serde_json::json!({"id":"x", "name":"测试\n".repeat(1000), "host":"\\\"".repeat(2000)});
        published.entries = vec![entry; 10_000];
        let catalog = ResourceCatalog::from_published(&published);
        assert!(catalog.truncated);
        assert!(catalog.entries.len() < 10_000);
        assert!(catalog.entries[0].name.len() <= 256);
        assert!(!catalog.entries[0].name.contains('\n'));
        let mut output = Vec::new();
        catalog.write_events(&mut output).unwrap();
        for line in std::str::from_utf8(&output).unwrap().lines() {
            assert!(line.len() < 8192);
        }
        assert!(serde_json::to_vec(&catalog).unwrap().len() < CATALOG_BYTE_LIMIT);
    }
}
