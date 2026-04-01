# JustAJobApp

**An automated job application tracker that connects to your Gmail inbox.** Apply for jobs, receive confirmation emails, and your dashboard updates automatically. No browser extensions. No manual data entry. No spreadsheets.

<a href="https://youtu.be/xD-rX6zu2ds">
  <img src="https://github.com/user-attachments/assets/f6c0b8ae-bc3a-4a10-ad9f-fb3992195a1e" alt="JustAJobApp Demo" width="600" height="300">
</a>

---

## A Single Lost Email Cost Me $40,000

After being laid off by email in 2024, I managed 46 interview pipelines from 129 applications. During a 9-interview week, a manual tracking error led to a missed interview—for a role paying $40,000 more than the offers I received.

I built JustAJobApp so this never happens to you.

---

## How It Works

1. **Connect your Gmail** — Secure sign-in, takes 30 seconds
2. **Apply for jobs like normal** — No browser extensions, no copy-pasting
3. **Your dashboard updates automatically** — Confirmation emails become tracked applications

Unlike other job trackers that force you to manually "clip" every job with a browser extension, JustAJobApp is fully automated.

---

## Get Started — Free

**[JustAJobApp.com →](https://justajobapp.com?utm_source=github&utm_campaign=readme)**

Sign up, connect your Gmail, and start tracking in under 2 minutes. Free for jobseekers.

---

## Why Trust Us With Your Gmail?

For a tool that reads your inbox, trust is mandatory. We went through an independent security audit for Google's formal approval and share our open-source code here on GitHub for free inspection.

### Security Audit: 9.7 / 10

An independent security firm ([TAC Security](https://tacsecurity.com/), an App Defense Alliance authorized lab) audited the live production app. Nine findings total — all Low or Informational severity, all patched. No Critical, High, or Medium issues found at any stage. The full audit trail is public: [68 tasks tracked and closed on GitHub](https://github.com/JustAJobApp/jobseeker-analytics/issues/101).

### Google-Approved OAuth

Google's Third Party Data Safety Team formally verified and approved our app in March 2026. We recertify annually.

### We Don't Read Your Emails

We use a narrow search query for job-related messages only. If an email isn't from a known hiring platform or doesn't contain keywords like "application received," we ignore it entirely. Our filter list is public: [`applied_email_filter.yaml`](https://github.com/JustAJobApp/jobseeker-analytics/blob/main/backend/email_query_filters/applied_email_filter.yaml).

### Your Data Is Not for Sale

We use Google's paid Gemini API, which contractually forbids them from using your data to train their models. Google's API policy also prohibits us from selling, sharing, or transferring your data to third parties. Your data is yours.

### What We Store

Only the metadata necessary to build your dashboard: sender name and email, application status, timestamp, company name, and job title. Full email bodies are never stored. If our system determines an email is a false positive, we don't store anything about it.

### Why Open Source?

Because we handle sensitive data, we believe our code should be open for public audit. More eyeballs means higher security standards.

For the full breakdown, see our [Security page](https://justajobapp.com/security).

---

## What People Are Saying

> *"I receive so many emails a day that I mistook one for a rejection. Later, I saw a color-coded 'Hiring Freeze' status in JustAJobApp that caught my eye. It prompted me to go back and find the email—it wasn't a rejection, but an invitation to apply for a reopened position. I would have completely missed this opportunity."*
> — **CS & Engineering New Grad, F1-OPT**

> *"I get to see the entire picture on a single dashboard... and not have to continually update a spreadsheet."*
> — **Donal Murphy, MBA, Global Events Producer**

---

## As Seen On

🎬 **Featured twice on GitHub's official YouTube channel (586K subscribers)**

- **December 2025:** Named one of ["GitHub's Favorite Open Source Projects of 2025"](https://www.youtube.com/watch?v=1ckVnvo-qcw&t=9s)
- **July 2025:** [First feature on Open Source Friday](https://youtu.be/sbzKMVaYHZw?t=751)

---

## The Job Search Crisis

**2–3× More Applications:** Pre-pandemic research found job seekers sent ~12 applications per month. JustAJobApp users send 7–12 per *week*. That's 2× more confirmation emails, rejections, and interview threads flooding your inbox.

**7,800+ Applications Tracked:** That's 7,800+ confirmation emails, status updates, and interview requests our users no longer manage manually.

**Spreadsheets Aren't Helping:** 72% of surveyed job seekers use 3+ different apps to track their search. Moving data between emails, calendars, and spreadsheets manually is where the $40,000 mistakes happen.

---

## For Career Coaches

We offer a coach portal with real-time visibility into your clients' job searches — upcoming interviews, referrals, recruiter inbounds, and offers.

👉 **[Coach.JustAJobApp.com](https://coach.justajobapp.com?utm_source=github&utm_campaign=readme)**

---

## Self-Hosting

JustAJobApp is open source and you're welcome to run it on your own infrastructure. See [CONTRIBUTING.md](CONTRIBUTING.md) for full setup instructions, including Docker Compose and virtual environment options.

> **Don't have Gmail?** You can set up email forwarding from your primary inbox to a Gmail account, then connect that to JustAJobApp.

---

## Contributing & Project Status

JustAJobApp is maintained by a single developer with a full-time job. The project is in a launched-and-stabilizing phase, so **pull requests are paused** while I focus on keeping the production app reliable.

**What's welcome right now:**

- 🐛 **Bug reports** — [Open an issue](https://github.com/JustAJobApp/jobseeker-analytics/issues) with steps to reproduce
- 💡 **Feature requests** — [Open an issue](https://github.com/JustAJobApp/jobseeker-analytics/issues) describing your use case
- 🛍️ **Merch** — [Pick up a shirt](https://www.bonfire.com/store/justajobapp/) if you want to rep the project
- ⭐ **Upgrade to Pro** — A [$5/month subscription](https://justajobapp.com/pricing?utm_source=github&utm_campaign=readme) is the best way to keep this project alive
- 💬 **Share your story** — If JustAJobApp helped your search, [leave a testimonial](https://docs.google.com/forms/d/e/1FAIpQLSd87SM6K4w8McuX1iQ4-wtGI9OI_3P3lptN63JkwyZI6S42gw/viewform?usp=pp_url&entry.1591633300=%F0%9F%92%8C+Customer+Love+Testimonial&entry.408578562=Yes,+I+consent+to+you+publishing+this+Feedback+on+JustAJobApp.com+to+the+public&entry.795763982=Jane+Doe,+Software+Engineer) — real stories from real jobseekers are worth more than any ad

I'll revisit accepting PRs when bandwidth allows. Thank you for understanding.

---

## FAQ

<details>
<summary><strong>Are you going to read all my emails?</strong></summary>

No. We use a specific search query to identify only potential job-related threads before the application even looks at the content. Our filter list is public in [`applied_email_filter.yaml`](https://github.com/JustAJobApp/jobseeker-analytics/blob/main/backend/email_query_filters/applied_email_filter.yaml).
</details>

<details>
<summary><strong>I use my personal email for everything. Is that okay?</strong></summary>

Yes. We only access emails matching our pre-defined filters—specific sender domains (like greenhouse.io) and keywords (like "application received"). Everything else is ignored entirely.
</details>

<details>
<summary><strong>Do I have to use the web app?</strong></summary>

No. If you're technical, you can self-host by following the instructions in [CONTRIBUTING.md](CONTRIBUTING.md).
</details>

<details>
<summary><strong>Why is this open source?</strong></summary>

Transparency. Because we handle sensitive data, we believe our code should be open for public audit. Having "more eyeballs" ensures higher security standards.
</details>

---

## Sponsors

<a href="https://chat.zulip.org"><img src="https://github.com/zulip/zulip/blob/main/static/images/logo/zulip-icon-circle.svg" alt="Zulip logo" width="60" height="60"/></a>

Zulip is an organized team chat app designed for efficient communication.

---

## License

[MIT License](LICENSE)

Built with ❤️ by a jobseeker who lost $40,000 to a missed email—so you don't have to.
