## Table of Contents

1. [Welcome to Do-It-Yourself (DIY) Install](#welcome-to-do-it-yourself-diy-install)
    - [📹 Watch the Video](#-video-tutorial-diy-install)
    - [📖 Read the Text](#-written-tutorial-diy-install)
      - [How can I install the app directly on my computer?](#how-can-i-install-the-app-directly-on-my-computer-%EF%B8%8F-back-to-table-of-contents)
         - [Install the Prerequisites](#install-the-prerequisites)
         - [Clone the repo](#clone-the-repo)
         - [Get a Google AI API key](#get-a-google-ai-api-key)
         - [Create a Google OAuth App](#create-a-google-oauth-app)
         - [Set Up Environment Variables](#set-up-environment-variables)
         - [Run the App: Two options](#run-the-app-two-options)
               - [Option 1: Docker Compose (Preferred Option)](#option-1-docker-compose-preferred-option-%EF%B8%8F-back-to-table-of-contents)
               - [Option 2: Virtual Environment](#option-2-virtual-environment-%EF%B8%8F-back-to-table-of-contents)
         - [Inspect the Database with DBeaver](#inspect-the-database-with-dbeaver-%EF%B8%8F-back-to-table-of-contents)
         - [Troubleshooting Tips](#troubleshooting-tips-%EF%B8%8F-back-to-table-of-contents)
2. [How to Change the Database](#how-to-change-the-database)
3. [How to Submit Changes to GitHub](#submit-changes-%EF%B8%8F-back-to-table-of-contents)
    - The "One Diff, One Thesis" Principle
    - Keep Pull Requests Under 250 Lines of Code
    - Make your code testable
4. [Report a Bug](#report-a-bug-%EF%B8%8F-back-to-table-of-contents)
    - [How Do I Submit a (Good) Bug Report?](#how-do-i-submit-a-good-bug-report)
5. [Code of Conduct](#code-of-conduct-%EF%B8%8F-back-to-table-of-contents)
    - [Examples of positive behavior](#examples-of-behavior-that-contributes-to-positive-environment)
    - [Examples of unacceptable behavior](#examples-of-unacceptable-behavior)

---

# Welcome to Do-It-Yourself (DIY) Install

Whether this is your first time downloading code or the gazillionth time cloning a repo, we are happy to see you. 

Here you will learn how to install the app directly on your personal computer. 

Once the app is installed, you'll have full access to all the features.

Choose your path: Video [📹](#-video-tutorial-diy-install) or Manual [📖](#-written-tutorial-diy-install)

Note: If you are a current or aspiring developer, you can pick up [open issues](https://github.com/just-a-job-app/jobseeker-analytics/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22help%20wanted%22%20no%3Aassignee), write code to fix them, and get your work reviewed and merged. Comment on an issue if you'd like to try resolving it.

# 📹 Video Tutorial: DIY Install
- ⏺️ [Watch replay of guided tutorial](https://youtube.com/playlist?list=PL0ZEIUccq0tDV-gzv2GgjVr0Nwjpc2p-G&si=lccbmgSRxd9x8NeE )  
- If you run into issues, hop into [Discord](https://discord.gg/gsdpMchCam).
- Prefer live help? Get notified about upcoming guided tutorials, hosted online: https://lu.ma/justajobapp
- Changed your mind about DIY Install? [Get JAJA(Pro)](https://app.formbricks.com/s/cmagfwkuu3f8bug01e340supq)

# 📝 Written Tutorial: DIY Install
## How can I install the app directly on my computer? [⬆️ Back to Table of Contents](#table-of-contents)
**Estimated time to complete installation:** 25-50 minutes.
*This is an estimate and can vary depending on your internet speed and familiarity with the tools. The first-time setup with Docker will take the longest.*
### Install the Prerequisites
(everything is free to install)
- [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- [Visual Studio Code](https://code.visualstudio.com/)
- [git](https://git-scm.com/downloads)
- [DBeaver](https://dbeaver.io/download/)
  
### Clone the repo
_Estimated time: 2-5 minutes_

Note for **Windows** users: We recommend that you use WSL2. [Install here](https://learn.microsoft.com/en-us/windows/wsl/). Open the application when installed.
1. In [Github](https://github.com/just-a-job-app/jobseeker-analytics), fork the repository.
   
![CleanShot 2025-06-07 at 21 40 35](https://github.com/user-attachments/assets/9312b5ba-d491-49a1-9f04-218eefffceb6)

2. In Visual Studio Code, go to the Terminal > New Terminal.
3. Edit the clone command below with your actual username instead of `your-username`

   e.g. my username is `lnovitz`, so my clone command is: `git clone https://github.com/lnovitz/jobseeker-analytics.git`
5. Paste the command from Step 3 below into the terminal. Press Enter to download the app to your computer. 
```sh
git clone https://github.com/your-username/jobseeker-analytics.git
```
4. Paste the command below into the terminal. Press Enter to navigate to the app directory.
```sh
cd jobseeker-analytics
```

---

### Set Up Environment Variables
_Estimated time: 3-5 minutes_
1. Copy `backend\.env.example` to `backend\.env`:
   ```sh
   cp backend/.env.example backend/.env
   ```
   **🔒 Never share your `.env` file or commit it to Git!**
   - Open `backend/.env` and replace value for `DEV_USER_GMAIL` with your gmail address in quotes.
2. Copy `frontend\.env.sample` to `frontend\.env`:
   ```sh
   cp frontend/.env.sample frontend/.env
   ```
---

### Get a Google AI API key
_Estimated time: 2-3 minutes_
1. Go to [https://aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)
2. Click **Create and API Key**
3. Copy the API key value
4. Open `backend/.env` and replace value for `GOOGLE_API_KEY`
---

### Create a Google OAuth App
_Estimated time: 10-20 minutes_
1. Go to the [Google Cloud Console](https://console.cloud.google.com/) and create a new project (or use an existing one).  
2. Navigate to **APIs & Services** → **Credentials**.  
3. If this is your first time creating credentials with this project, you will have to configure the OAuth consent screen.
4. Click **Create Credentials** → **OAuth 2.0 Client IDs**.  
5. Set the application type to **Web Application**.  
6. Under "Authorized redirect URIs," add the following and save to update:  
   - http://localhost:8000/auth/google
7. Copy the **Client ID** under Additional information header
8. In `backend/.env`, paste value for `GOOGLE_CLIENT_ID`
9. Copy the **Client secret** under Client secrets header
10. In `backend/.env`, paste value for `GOOGLE_CLIENT_SECRET`
11. On the OAuth Consent Screen page, scroll to "Test Users" and add your gmail address.
12. Click **Data Access** and then **Add or remove scopes**. 
13. At the top of the list, check 
   - .../auth/userinfo.email  
   - openid

Don't forget to press **Save**. Twice.

![CleanShot 2025-05-20 at 23 11 20](https://github.com/user-attachments/assets/dd9f339e-7111-4aa5-8b77-b8900c62b2c4)
![CleanShot 2025-05-20 at 23 11 34](https://github.com/user-attachments/assets/82a60ab2-a4b1-412e-a5a5-75568900043e)

12. Search for "Gmail API" at the top search bar, click **Enable**
13. Click on **Data Access** again, **Add or remove scopes**
14. Click the filter field above those checkboxes, and enter "gmail". It will probably autocomplete so you can click "Gmail API" or press enter.
15. Check the box next to Gmail API | .../auth/gmail.readonly
16. Click **Update**
17. Click **Save**


### Run the App: Two options
_Estimated time: 10-25 minutes_
#### Option 1: Docker Compose (Preferred Option) [⬆️ Back to Table of Contents](#table-of-contents)

1. If this is your first time using Docker, install as below:
   - Install Docker. On Windows/Mac install [Docker Desktop](https://docs.docker.com/get-started/get-docker/). On Linux install [Docker Engine](https://docs.docker.com/engine/install/). 
   - Start Docker Desktop or Docker Engine
      - On Windows: make sure to select "Use the WSL 2 based engine" under Settings/general.
      - On Linux: you may need to take additional post-installation steps, see (here)[https://docs.docker.com/engine/install/linux-postinstall/]. 
   - Make sure to verify your email address in the Account Settings.
2. Start the app using Docker compose-up. The first time you run this locally it may take a few minutes to set up.
```
docker-compose up --build
```
3. Go to [http://localhost:3000](http://localhost:3000) and click the **Login with Google** button. After you grant access it will go to work scanning your emails for relevant emails.
4. Troubleshooting:
   - Attempted import error
      - `cd frontend`
      - `npm ci`

You can view logs from the app by finding your container in Docker Desktop/Docker Engine and clicking on it. The app will automatically refresh when you make changes. 

#### Option 2: Virtual Environment [⬆️ Back to Table of Contents](#table-of-contents) 

Once your `.env` file is set up, start the app by following the instructions below:
1. Create and activate virtual environment:
   ```sh
   # MAC/LINUX
   python3 -m venv .venv
   source .venv/bin/activate
   ```
   ```sh
   # WINDOWS (CMD)
   python -m venv .venv
   .venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r backend/requirements.txt
   cd frontend && npm install
   ```
3. Start the PostgreSQL database:
   - Ensure Docker is installed and running.
   - Use Docker to start the PostgreSQL database:
     ```bash
     docker run --name jobseeker-db -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=jobseeker_analytics -p 5433:5432 -d postgres:13
     ```
4. Run backend and frontend apps:
   In one terminal window, run:
   ```bash
   cd backend && uvicorn main:app --reload
   ```
   In another terminal window, run:
   ```bash
   cd frontend && npm run dev
   ```
5. Go to [http://localhost:3000](http://localhost:3000) and click the **Login with Google** button. After you grant access it will go to work scanning your emails for relevant emails.

---


### Inspect the Database with DBeaver [⬆️ Back to Table of Contents](#table-of-contents)

To inspect your PostgreSQL database running in Docker, follow these steps:

1. **Install DBeaver**:
   - Go to the [DBeaver download page](https://dbeaver.io/download/).
   - Download and install the appropriate version for your operating system (Windows, macOS, or Linux).

2. **Start Docker Services (choose one of the commands below to start it if you haven't already)**:
   - Ensure your Docker services are running using the following command:
     ```bash
     docker-compose -f docker-compose-dev.yaml up --build
     ```
   - Or use the following command to simulate a production build (useful if you do not need to test frontend changes and only want to test backend functionality changes - you won't need to wait for the frontend to compile every time you navigate to a different page):
     ```bash
     docker-compose up --build
     ```

3. **Create a New Database Connection in DBeaver (if this is your first time opening DBeaver for this project)**:
   - Open DBeaver.
   - - Note: you may need to Download SQLLite driver files - Driver settings window will prompt you.
   - Click on the `Database` menu and select `New Database Connection`.
   - Select `PostgreSQL` and click `Next`.

4. **Enter Connection Details**:
   - **Host**: `localhost`
   - **Port**: `5433` (as specified in your `docker-compose.yaml` file)
   - **Database**: `jobseeker_analytics`
   - **Username**: `postgres`
   - **Password**: `postgres`
   - Click on the `Test Connection` button to ensure the connection is successful.
   - Note: you may need to Download PostgreSQL driver files - Driver settings window will prompt you.

5. **Save the Connection**:
   - If the connection test is successful, click `Finish` to save the connection.
   - If the connection test fails, double-check the connection details and ensure that your Docker services are running.

6. **Inspect the Database**:
   - In the `Database Navigator` pane on the left side of DBeaver, expand the `PostgreSQL` node.
   - Expand the `jobseeker_analytics` node to see the available schemas and tables.
   - Right-click on a table (e.g., `test_table`) and select `View Data` to see the data in the table.


### Troubleshooting Tips [⬆️ Back to Table of Contents](#table-of-contents)
- **Not redirected after login?**  
  Double-check your `REDIRECT_URI` in both `.env` and Google Cloud settings.  
- **Invalid API key errors?**  
  Some Google APIs require API key restrictions—try generating a new unrestricted key for local testing.  
- **Cannot Build Docker Image?**
   Try option 2, with venv and FastAPI server instead. 

#### When do I need to rebuild Docker? 
- if you change `.env` variables, you'll need to `docker compose down` and `docker compose up --build`
---

### How to Change the Database

We use **SQLModel** to define our database schema and **Alembic** to manage migrations. Because our services run in Docker, all Alembic commands must be executed within the backend container.

#### Why We Use Migrations [⬆️ Back to Table of Contents](#table-of-contents)

Migrations allow us to update the database schema (adding columns, creating tables) across different environments without losing existing data. Our current schema includes a "Gatekeeper" system to manage beta access:

* **`is_active`**: A boolean flag determining if a user can log in. In production, this defaults to `False` to restrict access during our security review.
* **`stripe_customer_id`**: An optional field for future payment integration.

#### Common Commands

* **Check Migration Status**: See which version your local database is currently on.
```bash
docker compose exec backend alembic current

```


* **Update Your Database**: Run this after pulling new code to apply the latest schema changes.
```bash
docker compose exec backend alembic upgrade head

```


* **Roll Back**: Undo the last migration.
```bash
docker compose exec backend alembic downgrade -1

```



#### Workflow for Altering the Database

If you are implementing a feature or bug fix that requires a schema change:

1. **Modify the Model**: Update the relevant file in `backend/db/` (e.g., `backend/db/users.py`).
2. **Generate a Script**: Alembic will compare your code to the database and generate a migration file.
```bash
docker compose exec backend alembic revision --autogenerate -m "description of change"

```


3. **Review the Script**: Inspect the new file in `backend/alembic/versions/`. Ensure the `upgrade()` and `downgrade()` functions accurately reflect your changes.
4. **Apply Locally**: Run `upgrade head` as shown above to update your local DB.

#### Automation for Development

To make onboarding easier for contributors, we have automated the `is_active` flag in development environments.

* **Automated Activation**: New users created in a development environment are automatically set to `is_active = True`.
* **Lifespan Seed**: Every time the backend starts in dev mode, it ensures existing users are active so you aren't locked out of your own local environment.

#### Rules for Migration Maintenance

* **When to EDIT**: Only edit a migration file if it is local to your branch and has not been merged into `main`. Once shared, editing a file causes history desync for other developers.
* **When to DELETE**: Never delete a migration file that has been merged into `main`. This breaks the migration chain for everyone else. If you made a mistake in a merged migration, the correct fix is to create a **new** migration that reverses or corrects it.


### Submit Changes [⬆️ Back to Table of Contents](#table-of-contents)  
1. **Fork** this repository.  
2. **Clone** your fork:
   ```sh
   git clone https://github.com/your-username/jobseeker-analytics.git
   cd jobseeker-analytics
   ```
3. **Create a new branch** for your changes:
- use branch convention <feature|bugfix|hotfix|docs>/<issueNumber>-<issueDescription> e.g.
   ```sh
   git checkout -b docs/65-add-contribution-guidelines
   ```
4. **Make your changes** and commit them:
   ```sh
   git add .
   git commit -m "Add submission guidelines and env setup"
   ```
   Note: if you end up using a new Python library (e.g. I just added `ruff`) with `pip install`, be sure to do the following from the `backend` folder:
   `pip freeze > requirements.txt`

   You will need to add the `requirements.txt` file change as a commit, to ensure the environment has all its dependencies and production and local development environments run smoothly.
   ```sh
   git add requirements.txt
   git commit -m "add python library ruff"
   ```

5. **Format your changes** and commit them:

- If you're using Python, run:
   ```sh
   ruff format path/to/your/code
   git add .
   git commit -m "format with ruff"
   ```
(Please ensure your code passes all linting checks before submitting a pull request.)

6. **Push to your fork**:  
   ```sh
   git push origin docs/65-add-contribution-guidelines
   ```
7. **Open a Pull Request** on GitHub. See tips below. Credit to Taro ([warning: you will make me money if you sign up through this link](https://www.jointaro.com/r/liannan073/))

**Keeping Your Local Copy Up to Date**

After your feature has been accepted and merged, it's important to ensure your local copy is up to date before starting any new work. Especially if you're about to begin work on a different feature, follow these steps:
```sh
git checkout main             # Switch back to the main branch
git pull                      # Update your local copy with the latest changes
git checkout -b new_branch_name  # Create a new branch for your next feature
```
This ensures you're always working on the latest version of the codebase.

### Pull Request Methodology

#### 1. The "One Diff, One Thesis" Principle

- Each code change should focus on a single purpose or goal.

**What This Means:**
- Make each pull request about one specific improvement
- Address one feature, bug fix, or enhancement at a time
- Keep your changes focused and related to one objective

**Why It Matters:**
When your changes have a single purpose, they're easier to review, understand, and test. If something goes wrong, it's also easier to identify and fix the problem.

**Example:**
If you're working on a user profile page:
- ✅ GOOD PR: Add email validation to the registration form
- ❌ BAD PR: Add email validation, redesign the profile layout, and optimize database queries

Think of each PR as a single chapter in a book, not the entire story.

#### 2. Keep Pull Requests Under 250 Lines of Code

Smaller code changes are easier to review and less likely to introduce bugs.

**How to Stay Under the Limit:**
- Count only meaningful lines of code you've added or changed
- Break large features into a series of smaller, sequential changes
- Submit related changes in separate pull requests

**Breaking Down Large Features:**
When implementing something complex, try this approach:
1. First PR: Set up the basic structure
2. Second PR: Implement core functionality
3. Third PR: Add refinements and advanced features

**Example:**
Instead of one massive PR for a new search feature, create:
1. PR #1: Add search box to navigation
2. PR #2: Connect search box to backend
3. PR #3: Implement search results display
4. PR #4: Add filtering options

#### 3. Make Your Code Testable

Always include a way to verify your changes work correctly.

**Verification Methods:**
- **Automated tests:** Write code that checks your changes automatically
- **Screenshots/Videos:** For visual changes, show before and after
- **Test instructions:** Provide clear steps for others to test your changes

**What Good Testing Looks Like:**
- Tests cover both expected behavior and edge cases
- Instructions are specific enough that anyone could follow them
- Visual evidence clearly demonstrates the improvement

**Example:**
For a login form improvement:
```
Test Plan:
1. Try logging in with a correct username/password → Should succeed
2. Try logging in with an incorrect password → Should show error message
3. Try logging in with a blank password → Should prevent submission

[Screenshots attached showing each scenario]
```

Remember: Good pull requests aren't just about the code you write—they're about making changes that others can understand, verify, and maintain.

Lastly, do your best to follow the below coding style guides.
- Python: https://google.github.io/styleguide/pyguide.html
- TypeScript: https://google.github.io/styleguide/tsguide.html
- HTML/CSS: https://google.github.io/styleguide/htmlcssguide.html

---


### Report a Bug [⬆️ Back to Table of Contents](#table-of-contents)

This section guides you through submitting a bug report for Job Analytics. Following these guidelines helps maintainers and the community understand your report, reproduce the behavior and provide a proper solution.

Before creating a bug report, please check this [list](https://github.com/lnovitz/jobseeker-analytics/issues) as you might find out you don't need to create a new one. When you are creating a bug report, please include as many details as possible, including screenshots or clips.

#### How Do I Submit a (Good) Bug Report?

Bugs are tracked as [GitHub issues](https://docs.github.com/en/issues/tracking-your-work-with-issues/about-issues). Create an issue by providing the following information:

- Use a clear and descriptive title.
- Describe the exact steps which reproduce the problem. Include details on what you did and how you did it.
- Describe the behavior you observed after following the steps.
- Include screenshots and/or animated GIFs when possible.
- If the problem wasn't triggered by a specific action, describe what you were doing before the problem occurred.

## Code of Conduct [⬆️ Back to Table of Contents](#table-of-contents)

We aim to make participation in this project and in the community a harassment-free experience for everyone.

### Examples of behavior that contributes to positive environment

- Use welcoming and inclusive language
- Be respectful of other viewpoints and experiences
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards others

### Examples of unacceptable behavior

- Use of sexualized language or imagery
- Trolling, insulting, derogatory comments and political attacks
- Public or private harassment
- Publishing other's private information or illegal information/documents
- Other conduct which could be reasonably considered inappropriate

This Code of Conduct applies to both within project spaces and in public spaces when an individual is representing the project or its community. By participating, you are expected to uphold this code. Please report unacceptable behavior.

