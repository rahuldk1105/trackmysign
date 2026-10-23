// When to remind about an expiring DSC, and how to say it.

/** Days ahead the reminder starts; 0 turns it off. */
export type ReminderDays = 0 | 15 | 30 | 60;

export const REMINDER_CHOICES: { value: ReminderDays; label: string }[] = [
  { value: 0, label: "Off" },
  { value: 15, label: "15 days" },
  { value: 30, label: "30 days" },
  { value: 60, label: "60 days" },
];

/** From here on the reminder turns red. */
const URGENT_DAYS = 7;

/** Remembered certificates are no longer brought up this long after expiring. */
const REMIND_EXPIRED_DAYS = 30;

export type ExpiryTone = "soon" | "urgent" | "expired";

export function expiryTone(daysLeft: number, remind: ReminderDays): ExpiryTone | null {
  if (daysLeft < 0) return "expired";
  if (remind === 0 || daysLeft > remind) return null;
  return daysLeft <= URGENT_DAYS ? "urgent" : "soon";
}

/** Whether a certificate seen before, but not plugged in now, is worth a reminder. */
export function remindAbout(daysLeft: number, remind: ReminderDays): boolean {
  return remind !== 0 && daysLeft >= -REMIND_EXPIRED_DAYS && daysLeft <= remind;
}

const days = (n: number) => `${n} day${n === 1 ? "" : "s"}`;

/** "Expires in 12 days", "Expired 3 days ago". */
export function expiryText(daysLeft: number): string {
  if (daysLeft >= 1) return `Expires in ${days(daysLeft)}`;
  if (daysLeft === 0) return "Expires in less than a day";
  if (daysLeft === -1) return "Expired today";
  return `Expired ${days(-daysLeft - 1)} ago`;
}

/** Shorter form next to the date: "49 days left", "expired". */
export function daysLeftText(daysLeft: number): string {
  if (daysLeft < 0) return "expired";
  if (daysLeft === 0) return "less than a day left";
  return `${days(daysLeft)} left`;
}

/** Local calendar day, so "dismiss" lasts until tomorrow. */
export function today(): string {
  const d = new Date();
  return `${d.getFullYear()}-${d.getMonth() + 1}-${d.getDate()}`;
}
