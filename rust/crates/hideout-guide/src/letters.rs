//! The letter builder: a company (and, when Hideout has them, its amounts and dates)
//! becomes a letter the person reviews and sends themselves. It works with no network
//! and no AI. Only facts Hideout shows go in; everything else is a [placeholder] or a
//! [Confirm: ...] line for the person to keep or delete - a letter to a bank is a
//! statement they sign. The address comes only from Hideout's directory, and only for a
//! company that officially takes cancellations by email.

use hideout_money::analyze::Recurring;
use serde_json::{json, Value};

fn usd(n: f64) -> String {
    format!("${n:.2}")
}

/// What the person typed into the letter form, when there is no statement to read from.
#[derive(Default)]
pub struct Typed {
    pub who: String,
    pub amount: String,
    pub date: String,
}

fn or(s: &str, placeholder: &str) -> String {
    let t = s.trim();
    if t.is_empty() { placeholder.to_string() } else { t.to_string() }
}

/// Build one letter card ({type:"letter", kind, merchant, name, to, subject, body}).
pub fn build(kind: &str, rec: Option<&Recurring>, cancel_by_email: Option<&str>, typed: &Typed) -> Value {
    let name = rec.map(|r| r.name.clone()).unwrap_or_else(|| or(&typed.who, "[Company name]"));
    let sign = "[Your name] · [Last 4 digits of card] · [Phone number]";
    let (subject, body, to) = match kind {
        "cancel_by_email" => {
            let to = cancel_by_email.map(String::from);
            let body = format!(
                "To {name}:\n\nPlease cancel my subscription, effective today, and stop all future charges.\n\nThe account is under [Email on the account].\n\nPlease confirm the cancellation in writing, with the date it takes effect.\n\n[Your name]"
            );
            (format!("Cancel my {name} subscription"), body, to)
        }
        "refund_request" => {
            let what = match rec {
                Some(r) if !r.after_cancel.is_empty() => {
                    let list: Vec<String> = r.after_cancel.iter().map(|a| format!("- {} on {}", usd(a.amount), a.date)).collect();
                    format!("I cancelled on {}. After that, you charged me:\n{}\n\n[Confirm: I did not sign up again or agree to any new charge after cancelling.]", r.canceled_on.clone().unwrap_or_else(|| "[Date you cancelled]".into()), list.join("\n"))
                }
                Some(r) => format!("I am asking for a refund of the {} charged on {}. [Confirm: the reason - for example, I cancelled on [Date you cancelled], or I did not use the service.]", usd(r.last_amount), r.last_date),
                None => format!("I am asking for a refund of the {} charged on {}. [Confirm: the reason.]", or(&typed.amount, "[$ amount]"), or(&typed.date, "[Date charged]")),
            };
            let body = format!("To {name}:\n\n{what}\n\nPlease refund it to the card it was charged to, and confirm in writing.\n\n{sign}");
            (format!("Refund request: {name}"), body, None)
        }
        _ => {
            // bank_dispute: the website guide's letter, filled from the statement.
            let what = match rec {
                Some(r) if !r.after_cancel.is_empty() => {
                    let list: Vec<String> = r.after_cancel.iter().map(|a| format!("- {} on {}", usd(a.amount), a.date)).collect();
                    format!(
                        "I am disputing charges from {name} taken after I cancelled on {}:\n{}\n\n[Confirm: I did not sign up again or agree to any new charge after cancelling.]",
                        r.canceled_on.clone().unwrap_or_else(|| "[Date you cancelled]".into()),
                        list.join("\n")
                    )
                }
                Some(r) => format!("I am disputing a charge of {} on {} from {name}. [Confirm: this charge was taken after I cancelled, or was not authorised by me.]", usd(r.last_amount), r.last_date),
                None => format!("I am disputing a charge of {} on {}. [Confirm: this charge was taken after I cancelled, or was not authorised by me.]", or(&typed.amount, "[$ amount]"), or(&typed.date, "[Date]")),
            };
            let body = format!("To [Bank or card company]:\n\n{what}\n\nPlease reverse this charge and block further charges from this merchant.\n\n{sign}");
            (format!("Dispute: {name}"), body, None)
        }
    };
    json!({
        "type": "letter", "kind": if crate::spec::LETTER_KINDS.contains(&kind) { kind } else { "bank_dispute" },
        "merchant": rec.map(|r| r.merchant.clone()), "name": rec.map(|r| r.name.clone()), "to": to, "subject": subject, "body": body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hideout_money::analyze::AfterCancel;

    fn rec() -> Recurring {
        Recurring {
            merchant: "netflix".into(),
            name: "Netflix".into(),
            known: true,
            ambiguous: false,
            category: None,
            sample: "NETFLIX.COM".into(),
            cadence: "monthly".into(),
            charges: 3,
            first_date: "2026-07-01".into(),
            last_date: "2026-09-01".into(),
            last_amount: 15.49,
            monthly: Some(15.49),
            price_up: None,
            status: "still-charging".into(),
            canceled_on: Some("2026-08-05".into()),
            after_cancel: vec![AfterCancel { date: "2026-09-01".into(), amount: 15.49, act_by: "2026-10-31".into() }],
            next_expected: None,
            refund_likelihood: "low".into(),
            refund_basis: None,
            has_cancel_page: true,
            cancel_by_email: None,
            on_this_pc: vec![],
        }
    }

    #[test]
    fn a_dispute_uses_only_hideouts_facts_and_brackets_the_rest() {
        let c = build("bank_dispute", Some(&rec()), None, &Typed::default());
        let b = c["body"].as_str().unwrap();
        assert!(b.contains("$15.49 on 2026-09-01") && b.contains("cancelled on 2026-08-05"), "{b}");
        assert!(b.contains("[Your name]") && b.contains("[Last 4 digits of card]") && b.contains("[Confirm: "));
        assert_eq!(c["to"], Value::Null, "a dispute is never addressed by Hideout");
        assert_eq!(c["name"], "Netflix");
    }

    #[test]
    fn typed_or_missing_facts_become_placeholders() {
        let c = build("bank_dispute", None, None, &Typed { who: "Tech Support LLC".into(), amount: "".into(), date: "Aug 14".into() });
        let b = c["body"].as_str().unwrap();
        assert!(b.contains("[$ amount] on Aug 14") && c["subject"].as_str().unwrap().contains("Tech Support LLC"), "{b}");
        assert!(build("refund_request", None, None, &Typed::default())["body"].as_str().unwrap().contains("To [Company name]"));
    }

    #[test]
    fn only_a_cancel_by_email_letter_gets_an_address_and_only_from_the_directory() {
        assert_eq!(build("cancel_by_email", Some(&rec()), Some("cancel@mailco.com"), &Typed::default())["to"], "cancel@mailco.com");
        assert_eq!(build("cancel_by_email", Some(&rec()), None, &Typed::default())["to"], Value::Null);
        assert_eq!(build("refund_request", Some(&rec()), Some("cancel@mailco.com"), &Typed::default())["to"], Value::Null);
    }
}
