//! Weekly time windows for device profiles: "weekdays 21:00–07:00". A profile
//! with windows applies only inside them; outside, its devices fall through to
//! the next profile that lists them, or to the network-wide rules.
//!
//! Everything is minutes of the week in the box's local time, Monday 00:00 =
//! 0. The DNS path never reads a clock: a background tick stores the current
//! minute, and a window check is a few integer comparisons.

use chrono::{Datelike, Local, Timelike};
use serde::{Deserialize, Serialize};

pub const MINUTES_PER_DAY: u32 = 24 * 60;
pub const MINUTES_PER_WEEK: u32 = 7 * MINUTES_PER_DAY;

/// Day names as configs spell them, Monday first.
pub const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

/// One window as configured.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ScheduleWindow {
    /// Days the window starts on (`mon`…`sun`). Empty means every day.
    #[serde(default)]
    pub days: Vec<String>,
    /// Start, local time `HH:MM`.
    pub from: String,
    /// End, local time `HH:MM` (`24:00` allowed). Earlier than `from` runs
    /// past midnight into the next day; equal to `from` covers the whole day.
    pub to: String,
}

impl ScheduleWindow {
    /// Trim and lowercase in place, so a saved config reads the same way the
    /// API was sent it.
    pub fn normalize(&mut self) {
        self.from = self.from.trim().to_string();
        self.to = self.to.trim().to_string();
        let mut days: Vec<String> = self
            .days
            .iter()
            .map(|d| d.trim().to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
        // Calendar order, once each — the order the panel shows them in.
        days.sort_by_key(|d| day_index(d).unwrap_or(u32::MAX));
        days.dedup();
        self.days = days;
    }

    /// The spans (start minute of the week, length) this window covers, one
    /// per day it starts on, or what is wrong with it.
    fn spans(&self) -> Result<Vec<(u32, u32)>, String> {
        let from = parse_time(&self.from)
            .filter(|m| *m < MINUTES_PER_DAY)
            .ok_or_else(|| format!("start '{}' is not a time (HH:MM)", self.from))?;
        let to = parse_time(&self.to)
            .ok_or_else(|| format!("end '{}' is not a time (HH:MM)", self.to))?;
        let len = match to.cmp(&from) {
            std::cmp::Ordering::Greater => to - from,
            std::cmp::Ordering::Less => MINUTES_PER_DAY - from + to,
            std::cmp::Ordering::Equal => MINUTES_PER_DAY,
        };
        let days: Vec<u32> = if self.days.is_empty() {
            (0..7).collect()
        } else {
            self.days
                .iter()
                .map(|d| day_index(d).ok_or_else(|| format!("'{d}' is not a day (mon…sun)")))
                .collect::<Result<_, _>>()?
        };
        Ok(days
            .into_iter()
            .map(|d| (d * MINUTES_PER_DAY + from, len))
            .collect())
    }
}

/// A profile's windows, compiled. No windows means always on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Schedule {
    spans: Vec<(u32, u32)>,
}

impl Schedule {
    /// Compile windows, or say which one is broken and why.
    pub fn compile(windows: &[ScheduleWindow]) -> Result<Self, String> {
        let mut spans = Vec::new();
        for (i, w) in windows.iter().enumerate() {
            spans.extend(
                w.spans()
                    .map_err(|e| format!("time window {}: {e}", i + 1))?,
            );
        }
        Ok(Self { spans })
    }

    /// Is the schedule on at `minute` of the week? Always, without windows.
    pub fn is_active(&self, minute: u32) -> bool {
        self.spans.is_empty()
            || self
                .spans
                .iter()
                .any(|&(start, len)| (minute + MINUTES_PER_WEEK - start) % MINUTES_PER_WEEK < len)
    }

    pub fn is_always(&self) -> bool {
        self.spans.is_empty()
    }

    /// A schedule that is never on — what a profile whose windows don't
    /// compile gets, so its devices fall back to the network-wide rules
    /// rather than to a restriction running around the clock.
    pub fn never() -> Self {
        Self {
            spans: vec![(0, 0)],
        }
    }
}

/// `HH:MM` → minutes since midnight; `24:00` is 1440.
fn parse_time(s: &str) -> Option<u32> {
    let (h, m) = s.split_once(':')?;
    if h.is_empty() || h.len() > 2 || m.len() != 2 {
        return None;
    }
    let (h, m): (u32, u32) = (h.parse().ok()?, m.parse().ok()?);
    match (h, m) {
        (24, 0) => Some(MINUTES_PER_DAY),
        (0..=23, 0..=59) => Some(h * 60 + m),
        _ => None,
    }
}

fn day_index(day: &str) -> Option<u32> {
    DAYS.iter().position(|d| *d == day).map(|i| i as u32)
}

/// The box's local time as a minute of the week.
pub fn local_minute_of_week() -> u32 {
    let now = Local::now();
    now.weekday().num_days_from_monday() * MINUTES_PER_DAY + now.hour() * 60 + now.minute()
}

/// The box's local UTC offset, `+02:00` style, for the panel to show what the
/// schedule's times are relative to.
pub fn local_utc_offset() -> String {
    Local::now().format("%:z").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(days: &[&str], from: &str, to: &str) -> ScheduleWindow {
        ScheduleWindow {
            days: days.iter().map(|d| d.to_string()).collect(),
            from: from.into(),
            to: to.into(),
        }
    }

    /// Minute of the week for `day` (0 = Monday) at `h:m`.
    fn at(day: u32, h: u32, m: u32) -> u32 {
        day * MINUTES_PER_DAY + h * 60 + m
    }

    #[test]
    fn no_windows_is_always_on() {
        let s = Schedule::compile(&[]).unwrap();
        assert!(s.is_always());
        assert!(s.is_active(0) && s.is_active(MINUTES_PER_WEEK - 1));
    }

    #[test]
    fn daytime_window_covers_start_but_not_end() {
        let s = Schedule::compile(&[w(&["mon"], "09:00", "17:30")]).unwrap();
        assert!(!s.is_active(at(0, 8, 59)));
        assert!(s.is_active(at(0, 9, 0)));
        assert!(s.is_active(at(0, 17, 29)));
        assert!(!s.is_active(at(0, 17, 30)));
        assert!(!s.is_active(at(1, 10, 0)));
    }

    #[test]
    fn overnight_window_runs_into_the_next_day() {
        // Weeknight bedtime: starts Sunday through Thursday evenings.
        let s = Schedule::compile(&[w(&["sun", "mon", "tue", "wed", "thu"], "21:00", "07:00")])
            .unwrap();
        assert!(s.is_active(at(0, 22, 0))); // Monday night
        assert!(s.is_active(at(1, 6, 59))); // Tuesday early morning
        assert!(!s.is_active(at(1, 7, 0)));
        assert!(!s.is_active(at(4, 23, 0))); // Friday night is free
        assert!(s.is_active(at(6, 23, 0))); // Sunday night…
        assert!(s.is_active(at(0, 3, 0))); // …wraps past the week's end into Monday
    }

    #[test]
    fn equal_times_cover_the_whole_day_and_empty_days_mean_every_day() {
        let sat = Schedule::compile(&[w(&["sat"], "00:00", "00:00")]).unwrap();
        assert!(sat.is_active(at(5, 0, 0)) && sat.is_active(at(5, 23, 59)));
        assert!(!sat.is_active(at(6, 0, 0)));

        let daily = Schedule::compile(&[w(&[], "12:00", "24:00")]).unwrap();
        for day in 0..7 {
            assert!(daily.is_active(at(day, 12, 0)));
            assert!(!daily.is_active(at(day, 11, 59)));
        }
    }

    #[test]
    fn broken_windows_say_which_and_why() {
        let err = Schedule::compile(&[
            w(&["mon"], "9:00", "10:00"),
            w(&["funday"], "09:00", "10:00"),
        ])
        .unwrap_err();
        assert!(err.contains("window 2") && err.contains("funday"), "{err}");
        assert!(Schedule::compile(&[w(&[], "24:00", "01:00")]).is_err());
        assert!(Schedule::compile(&[w(&[], "12:60", "13:00")]).is_err());
        assert!(Schedule::compile(&[w(&[], "noon", "13:00")]).is_err());
    }

    #[test]
    fn normalize_trims_lowercases_and_orders_days() {
        let mut win = w(&[" Sun", "MON", "mon", ""], " 21:00 ", "07:00");
        win.normalize();
        assert_eq!(win.days, vec!["mon", "sun"]);
        assert_eq!(win.from, "21:00");
    }

    #[test]
    fn local_clock_is_a_minute_of_the_week() {
        assert!(local_minute_of_week() < MINUTES_PER_WEEK);
        let off = local_utc_offset();
        assert!(off.starts_with('+') || off.starts_with('-'), "{off}");
    }
}
