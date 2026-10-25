//! Scheduled tasks, read through the Task Scheduler COM API. Read calls only: this
//! module never registers, edits, enables, disables, runs, stops or deletes a task.

use windows::core::{Interface, BSTR};
use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};
use windows::Win32::System::TaskScheduler::{
    IComHandlerAction, IExecAction, ITaskFolder, ITaskService, TaskScheduler, TASK_ACTION_COM_HANDLER,
    TASK_ACTION_EXEC, TASK_ACTION_TYPE,
};
use windows::Win32::System::Variant::VARIANT;

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Exec { path: String, args: String },
    ComHandler { class_id: String },
    /// E-mail / message actions (deprecated by Windows, still readable).
    Other,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Task {
    /// Folder path with trailing backslash, the way Get-ScheduledTask shows TaskPath
    /// ("\" for the root, "\Microsoft\Windows\Defrag\" ...).
    pub folder: String,
    pub name: String,
    /// Unknown, Disabled, Queued, Ready, Running.
    pub state: String,
    pub author: String,
    pub date: String,
    pub hidden: bool,
    pub user_id: String,
    /// Limited or Highest.
    pub run_level: String,
    /// Trigger kinds, named the way hunt.ps1 names them (Logon, Boot, Daily, ...).
    pub triggers: Vec<String>,
    /// OLE date of the last run (local time); None if never or unreadable.
    pub last_run: Option<f64>,
    pub last_result: Option<i32>,
    pub actions: Vec<Action>,
    /// False when the task's definition could not be read (access denied).
    pub definition_read: bool,
}

#[derive(Debug, Default)]
pub struct TaskList {
    pub tasks: Vec<Task>,
    /// Folders that could not be opened, with the reason. Not checked is not clean.
    pub unreadable_folders: Vec<String>,
}

const TASK_ENUM_HIDDEN: i32 = 1;

fn state_word(s: i32) -> &'static str {
    match s {
        1 => "Disabled",
        2 => "Queued",
        3 => "Ready",
        4 => "Running",
        _ => "Unknown",
    }
}

/// The CIM trigger class name with "MSFT_Task" and "Trigger" removed, as hunt.ps1 does.
/// Monthly and custom triggers have no class of their own in CIM (MSFT_TaskTrigger), so
/// they come out empty there too.
fn trigger_word(t: i32) -> &'static str {
    match t {
        0 => "Event",
        1 => "Time",
        2 => "Daily",
        3 => "Weekly",
        6 => "Idle",
        7 => "Registration",
        8 => "Boot",
        9 => "Logon",
        11 => "SessionStateChange",
        _ => "",
    }
}

/// Every task this user is allowed to see, in every folder, hidden ones included.
/// Err only when the Task Scheduler itself cannot be reached.
pub fn list() -> Result<TaskList, String> {
    crate::com::init();
    // SAFETY: standard COM activation of the in-box Task Scheduler class.
    let svc: ITaskService = unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }
        .map_err(|e| format!("could not reach the Task Scheduler: {e}"))?;
    let empty = VARIANT::default();
    // SAFETY: connect to the local machine as the current user.
    unsafe { svc.Connect(&empty, &empty, &empty, &empty) }.map_err(|e| format!("could not connect to the Task Scheduler: {e}"))?;
    let root = unsafe { svc.GetFolder(&BSTR::from("\\")) }.map_err(|e| format!("could not open the task list: {e}"))?;
    let mut out = TaskList::default();
    walk(&root, &mut out, 0);
    Ok(out)
}

fn walk(folder: &ITaskFolder, out: &mut TaskList, depth: u32) {
    // SAFETY: all calls below are COM property reads on live interface pointers.
    unsafe {
        let mut fpath = folder.Path().map(|b| b.to_string()).unwrap_or_else(|_| "\\".into());
        if !fpath.ends_with('\\') {
            fpath.push('\\');
        }
        match folder.GetTasks(TASK_ENUM_HIDDEN) {
            Ok(coll) => {
                let n = coll.Count().unwrap_or(0);
                for i in 1..=n {
                    let Ok(t) = coll.get_Item(&VARIANT::from(i)) else { continue };
                    let mut task = Task {
                        folder: fpath.clone(),
                        name: t.Name().map(|b| b.to_string()).unwrap_or_default(),
                        state: t.State().map(|s| state_word(s.0)).unwrap_or("Unknown").to_string(),
                        last_run: t.LastRunTime().ok().filter(|d| *d > 1.0),
                        last_result: t.LastTaskResult().ok(),
                        ..Default::default()
                    };
                    if let Ok(def) = t.Definition() {
                        task.definition_read = true;
                        if let Ok(ri) = def.RegistrationInfo() {
                            let mut b = BSTR::new();
                            if ri.Author(&mut b).is_ok() {
                                task.author = b.to_string();
                            }
                            let mut d = BSTR::new();
                            if ri.Date(&mut d).is_ok() {
                                task.date = d.to_string();
                            }
                        }
                        if let Ok(st) = def.Settings() {
                            let mut h = Default::default();
                            if st.Hidden(&mut h).is_ok() {
                                task.hidden = h.as_bool();
                            }
                        }
                        if let Ok(p) = def.Principal() {
                            let mut u = BSTR::new();
                            if p.UserId(&mut u).is_ok() {
                                task.user_id = u.to_string();
                            }
                            let mut rl = Default::default();
                            if p.RunLevel(&mut rl).is_ok() {
                                task.run_level = if rl.0 == 1 { "Highest" } else { "Limited" }.to_string();
                            }
                        }
                        if let Ok(tc) = def.Triggers() {
                            let mut c = 0i32;
                            if tc.Count(&mut c).is_ok() {
                                for j in 1..=c {
                                    if let Ok(tr) = tc.get_Item(j) {
                                        let mut ty = Default::default();
                                        if tr.Type(&mut ty).is_ok() {
                                            task.triggers.push(trigger_word(ty.0).to_string());
                                        }
                                    }
                                }
                            }
                        }
                        if let Ok(ac) = def.Actions() {
                            let mut c = 0i32;
                            if ac.Count(&mut c).is_ok() {
                                for j in 1..=c {
                                    let Ok(a) = ac.get_Item(j) else { continue };
                                    let mut ty = TASK_ACTION_TYPE::default();
                                    let _ = a.Type(&mut ty);
                                    if ty == TASK_ACTION_EXEC {
                                        if let Ok(e) = a.cast::<IExecAction>() {
                                            let (mut p, mut g) = (BSTR::new(), BSTR::new());
                                            let _ = e.Path(&mut p);
                                            let _ = e.Arguments(&mut g);
                                            task.actions.push(Action::Exec { path: p.to_string(), args: g.to_string() });
                                        }
                                    } else if ty == TASK_ACTION_COM_HANDLER {
                                        if let Ok(e) = a.cast::<IComHandlerAction>() {
                                            let mut c = BSTR::new();
                                            let _ = e.ClassId(&mut c);
                                            task.actions.push(Action::ComHandler { class_id: c.to_string() });
                                        }
                                    } else {
                                        task.actions.push(Action::Other);
                                    }
                                }
                            }
                        }
                    }
                    out.tasks.push(task);
                }
            }
            Err(e) => out.unreadable_folders.push(format!("{fpath}: {e}")),
        }
        if depth > 32 {
            return;
        }
        if let Ok(subs) = folder.GetFolders(0) {
            let n = subs.Count().unwrap_or(0);
            for i in 1..=n {
                if let Ok(f) = subs.get_Item(&VARIANT::from(i)) {
                    walk(&f, out, depth + 1);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_windows_tasks_with_actions() {
        let l = list().expect("task scheduler");
        assert!(l.tasks.len() > 20, "only {} tasks", l.tasks.len());
        assert!(l.tasks.iter().any(|t| t.folder.starts_with("\\Microsoft\\Windows\\")));
        assert!(l.tasks.iter().any(|t| t.actions.iter().any(|a| matches!(a, Action::Exec { .. }))));
        assert!(l.tasks.iter().all(|t| t.folder.ends_with('\\')));
    }
}
