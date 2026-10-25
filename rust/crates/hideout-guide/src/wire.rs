//! The conversation, and the one value a transport may send: an [`Outbound`].
//!
//! What can go into the conversation is fixed by type:
//!   - the person's words and every tool result are [`Clean`] (only the redactor makes one)
//!   - the model's own replies are kept exactly as it sent them ([`ModelBlock`], made only
//!     here, from a transport's answer)
//!   - tool-call ids come from the model ([`ModelId`])
//!
//! An [`Outbound`] is made only by [`Outbound::seal`], which runs the redactor one last
//! time over every string in the request; if anything it would remove is still there,
//! nothing is sent. A transport's `turn` takes an `&Outbound`, so there is no way to hand
//! it anything else.

use hideout_redact::{Clean, Redactor};
use serde_json::{json, Value};

/// A tool-call id the model gave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelId(String);

impl ModelId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One content block of a model reply, kept byte-for-byte (thinking blocks and their
/// signatures must go back unchanged).
#[derive(Clone, Debug, PartialEq)]
pub struct ModelBlock(Value);

impl ModelBlock {
    pub(crate) fn from_model(v: Value) -> ModelBlock {
        ModelBlock(v)
    }
    pub fn value(&self) -> &Value {
        &self.0
    }
    pub fn kind(&self) -> &str {
        self.0["type"].as_str().unwrap_or("")
    }
    /// For a tool_use block: (id, name, input).
    pub fn tool_use(&self) -> Option<(ModelId, &str, &Value)> {
        if self.kind() != "tool_use" {
            return None;
        }
        Some((ModelId(self.0["id"].as_str()?.to_string()), self.0["name"].as_str().unwrap_or(""), &self.0["input"]))
    }
}

#[derive(Clone, Debug)]
pub struct ToolResult {
    pub id: ModelId,
    pub content: Clean,
    pub is_error: bool,
}

#[derive(Clone, Debug)]
pub enum Turn {
    /// What the person typed, redacted.
    Said(Clean),
    /// Results of the tools the model asked for, redacted.
    Results(Vec<ToolResult>),
    /// The model's reply, as sent.
    Model(Vec<ModelBlock>),
}

impl Turn {
    fn to_json(&self) -> Value {
        match self {
            Turn::Said(c) => json!({"role": "user", "content": c}),
            Turn::Results(rs) => json!({"role": "user", "content": rs.iter().map(|r| {
                let mut b = json!({"type": "tool_result", "tool_use_id": r.id.0, "content": r.content});
                if r.is_error { b["is_error"] = json!(true); }
                b
            }).collect::<Vec<_>>()}),
            Turn::Model(blocks) => json!({"role": "assistant", "content": blocks.iter().map(|b| b.0.clone()).collect::<Vec<_>>()}),
        }
    }
}

/// Where the last check found something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leak {
    /// In the person's words or a tool result - the first layer missed it.
    FromPc,
    /// In something the model wrote.
    FromModel,
}

/// Keys whose values are the model's own opaque data (signatures, ids), not text.
const OPAQUE: [&str; 4] = ["signature", "data", "id", "tool_use_id"];

fn walk(v: &Value, r: &Redactor) -> bool {
    r.leaks_value(v, &OPAQUE)
}

/// The only thing a transport can send.
pub struct Outbound {
    messages: Value,
}

impl Outbound {
    pub fn seal(turns: &[Turn], r: &Redactor) -> Result<Outbound, Leak> {
        for t in turns {
            let j = t.to_json();
            if walk(&j["content"], r) {
                return Err(if matches!(t, Turn::Model(_)) { Leak::FromModel } else { Leak::FromPc });
            }
        }
        Ok(Outbound { messages: Value::Array(turns.iter().map(Turn::to_json).collect()) })
    }

    pub fn messages(&self) -> &Value {
        &self.messages
    }

    /// Gateway protocol: the conversation only; the gateway adds prompt, tools and model.
    pub fn gateway_body(&self) -> Vec<u8> {
        json!({"messages": self.messages}).to_string().into_bytes()
    }

    /// Direct mode: the full request, streamed (betas travel as a header instead).
    pub fn direct_body(&self) -> Vec<u8> {
        let mut p = crate::spec::request_params(self.messages.clone());
        if let Value::Object(o) = &mut p {
            o.remove("betas");
            o.insert("stream".into(), json!(true));
        }
        p.to_string().into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hideout_redact::Identity;

    fn red() -> Redactor {
        Redactor::new(&Identity { names: vec!["jdoe".into()], computer: "HOME-PC".into(), allowed_emails: vec![] })
    }

    #[test]
    fn seal_refuses_a_model_block_that_carries_personal_data() {
        let r = red();
        let ok = vec![Turn::Said(r.text("hi jdoe")), Turn::Model(vec![ModelBlock::from_model(json!({"type": "thinking", "thinking": "", "signature": "EqQBCkgIARABGAIiQL2xqZ7wXyLongSignature"}))])];
        let out = Outbound::seal(&ok, &r).expect("signatures are opaque, not text");
        assert!(!out.messages().to_string().contains("jdoe"));
        let bad = vec![Turn::Said(r.text("hi")), Turn::Model(vec![ModelBlock::from_model(json!({"type": "text", "text": "Call 18005550199 now"}))])];
        assert_eq!(Outbound::seal(&bad, &r).err(), Some(Leak::FromModel));
    }

    #[test]
    fn tool_results_and_bodies_have_the_gateway_shape() {
        let r = red();
        let t = vec![
            Turn::Said(r.text("x")),
            Turn::Model(vec![ModelBlock::from_model(json!({"type": "tool_use", "id": "toolu_01ABCDEFGHIJKLMNOPQRSTUVWXYZ", "name": "get_case_file", "input": {}}))]),
            Turn::Results(vec![ToolResult { id: ModelId("toolu_01ABCDEFGHIJKLMNOPQRSTUVWXYZ".into()), content: r.json(&json!({"caseFile": null})), is_error: false }]),
        ];
        let o = Outbound::seal(&t, &r).unwrap();
        let g: Value = serde_json::from_slice(&o.gateway_body()).unwrap();
        assert_eq!(g["messages"][2]["content"][0], json!({"type": "tool_result", "tool_use_id": "toolu_01ABCDEFGHIJKLMNOPQRSTUVWXYZ", "content": "{\"caseFile\":null}"}));
        let d: Value = serde_json::from_slice(&o.direct_body()).unwrap();
        assert_eq!(d["stream"], true);
        assert!(d.get("betas").is_none() && d["system"][0]["text"].as_str().unwrap().starts_with("You are the Hideout Guide"));
    }
}
