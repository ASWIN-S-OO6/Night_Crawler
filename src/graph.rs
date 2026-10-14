use crate::types::{GEdge, GNode, GraphData};
use std::collections::HashMap;

/// Maltego-style entity/relationship graph builder.
#[derive(Default)]
pub struct GraphBuilder {
    nodes: Vec<GNode>,
    edges: Vec<GEdge>,
    index: HashMap<(String, String), usize>,
}

impl GraphBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, kind: &str, label: &str) -> usize {
        let key = (kind.to_string(), label.to_string());
        if let Some(&id) = self.index.get(&key) {
            return id;
        }
        let id = self.nodes.len();
        self.nodes.push(GNode {
            id,
            kind: kind.to_string(),
            label: label.to_string(),
        });
        self.index.insert(key, id);
        id
    }

    pub fn add_edge(&mut self, from: usize, to: usize, label: &str) {
        self.edges.push(GEdge {
            from,
            to,
            label: label.to_string(),
        });
    }

    pub fn relate(&mut self, from_kind: &str, from_label: &str, edge: &str, to_kind: &str, to_label: &str) {
        let f = self.add_node(from_kind, from_label);
        let t = self.add_node(to_kind, to_label);
        self.add_edge(f, t, edge);
    }

    pub fn data(&self) -> GraphData {
        GraphData {
            nodes: self.nodes.clone(),
            edges: self.edges.clone(),
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Top hub entities by degree — the "most connected" transforms.
    pub fn hubs(&self, limit: usize) -> Vec<(String, String, usize)> {
        let mut degree: HashMap<usize, usize> = HashMap::new();
        for e in &self.edges {
            *degree.entry(e.from).or_insert(0) += 1;
            *degree.entry(e.to).or_insert(0) += 1;
        }
        let mut hubs: Vec<(String, String, usize)> = self
            .nodes
            .iter()
            .map(|n| {
                let d = degree.get(&n.id).copied().unwrap_or(0);
                (n.kind.clone(), n.label.clone(), d)
            })
            .filter(|(_, _, d)| *d > 0)
            .collect();
        hubs.sort_by(|a, b| b.2.cmp(&a.2));
        hubs.truncate(limit);
        hubs
    }

    /// Render a Mermaid diagram (viewable in any Markdown renderer).
    pub fn to_mermaid(&self, max_nodes: usize) -> String {
        // Pick most important nodes when over budget: prefer higher-degree
        let mut degree: HashMap<usize, usize> = HashMap::new();
        for e in &self.edges {
            *degree.entry(e.from).or_insert(0) += 1;
            *degree.entry(e.to).or_insert(0) += 1;
        }

        let include_all = self.nodes.len() <= max_nodes;
        let mut chosen: Vec<usize> = if include_all {
            self.nodes.iter().map(|n| n.id).collect()
        } else {
            let mut ranked: Vec<(usize, usize)> = self
                .nodes
                .iter()
                .map(|n| (n.id, degree.get(&n.id).copied().unwrap_or(0)))
                .collect();
            ranked.sort_by(|a, b| b.1.cmp(&a.1));
            ranked.into_iter().map(|(id, _)| id).take(max_nodes).collect()
        };
        chosen.sort();

        let mut lines: Vec<String> = vec!["graph LR".into()];
        lines.push("    classDef domain fill:#4c6ef5,stroke:#1e2a5a,color:#fff".into());
        lines.push("    classDef ip fill:#12b886,stroke:#0b5d3f,color:#fff".into());
        lines.push("    classDef service fill:#e8590c,stroke:#7a2f0b,color:#fff".into());
        lines.push("    classDef email fill:#d6336c,stroke:#5c1030,color:#fff".into());
        lines.push("    classDef org fill:#9c36b5,stroke:#3d1052,color:#fff".into());
        lines.push("    classDef url fill:#3b5bdb,stroke:#16215c,color:#fff".into());

        let id_of: HashMap<usize, String> = chosen
            .iter()
            .enumerate()
            .map(|(i, &id)| (id, format!("N{}", i)))
            .collect();

        for (i, &id) in chosen.iter().enumerate() {
            if let Some(node) = self.nodes.get(id) {
                let label = crate::util::sanitize_label(&node.label);
                let shape = match node.kind.as_str() {
                    "domain" | "subdomain" | "org" => format!("N{}([\"{}\"])", i, label),
                    "email" => format!("N{}((\"{}\"))", i, label),
                    "service" => format!("N{}{{{{\"{}\"}}}}", i, label),
                    _ => format!("N{}[\"{}\"]", i, label),
                };
                lines.push(format!("    {}", shape));
                let class = match node.kind.as_str() {
                    "domain" | "subdomain" => "domain",
                    "ip" => "ip",
                    "service" => "service",
                    "email" => "email",
                    "org" => "org",
                    "url" => "url",
                    _ => "",
                };
                if !class.is_empty() {
                    lines.push(format!("    class N{} {}", i, class));
                }
            }
        }

        for e in &self.edges {
            if let (Some(a), Some(b)) = (id_of.get(&e.from), id_of.get(&e.to)) {
                let lbl = crate::util::sanitize_label(&e.label);
                if lbl.is_empty() {
                    lines.push(format!("    {} --> {}", a, b));
                } else {
                    lines.push(format!("    {} -->|{}| {}", a, b, lbl));
                }
            }
        }

        if !include_all {
            lines.push(format!(
                "    %% graph truncated to {} of {} nodes",
                max_nodes,
                self.nodes.len()
            ));
        }
        lines.join("\n")
    }
}
