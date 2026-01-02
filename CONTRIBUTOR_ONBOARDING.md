## 🎯 Your Mini-Quest: Join the Wall of Fame

By the end of this mini-quest, you will be able to:

1. ✅ Track your job search automatically
2. ✅ Add Git, GitHub, and Docker to your resume Skills section
3. ✅ Showcase yourself at https://www.app.justajobapp.com/contributors

<p align="left">
    <img width="400" alt="Wall of Fame" src="https://github.com/user-attachments/assets/b6f99068-fb59-4466-a93a-47b3580ad9e9" />
</p>

## 📋 Prerequisites

Before starting, make sure you have:
- [ ] [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed
- [ ] [Visual Studio Code](https://code.visualstudio.com/) (recommended)
- [ ] [Git](https://git-scm.com/downloads) installed
- [ ] A GitHub account
- [ ] A Google account (for API keys and OAuth setup)

## 🚀 Step-by-Step Instructions

### Step 1: Fork and Clone the Repository

1. **Fork the repository** on GitHub
   - Go to [https://github.com/just-a-job-app/jobseeker-analytics](https://github.com/just-a-job-app/jobseeker-analytics)
   - Click the "Fork" button in the top right

2. **Clone your fork locally**
   ```bash
   git clone https://github.com/YOUR_USERNAME/jobseeker-analytics.git
   cd jobseeker-analytics
   ```

3. **Add the upstream remote**
   ```bash
   git remote add upstream https://github.com/just-a-job-app/jobseeker-analytics.git
   ```

### Step 2: Set Up the Development Environment

1. **Install Docker Desktop**
   - Download and install [Docker Desktop](https://www.docker.com/products/docker-desktop/)
   - Start Docker Desktop
   - On Windows: make sure to select "Use the WSL 2 based engine" under Settings/general

2. **Set up environment variables**
   ```bash
   # Copy the example environment files
   cp backend/.env.example backend/.env
   cp frontend/.env.sample frontend/.env
   ```

3. **Get a Google AI API key**
   - Go to [https://aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)
   - Click **Create an API Key**
   - Copy the API key value
   - Open `backend/.env` and replace value for `GOOGLE_API_KEY`

4. **Create a Google OAuth App**
   - Go to the [Google Cloud Console](https://console.cloud.google.com/) and create a new project
   - Navigate to **APIs & Services** → **Credentials**
   - Configure the OAuth consent screen if prompted
   - Click **Create Credentials** → **OAuth 2.0 Client IDs**
   - Set application type to **Web Application**
   - Under "Authorized redirect URIs," add: `http://localhost:8000/auth/google`
   - Copy the **Client ID** and paste in `backend/.env` for `GOOGLE_CLIENT_ID`
   - Copy the **Client secret** and paste in `backend/.env` for `GOOGLE_CLIENT_SECRET`
   - On OAuth Consent Screen, add your gmail address to "Test Users"
   - Enable Gmail API and add scopes: `.../auth/userinfo.email`, `openid`, `.../auth/gmail.readonly`

5. **Start the app using Docker**
   ```bash
   docker-compose up --build
   ```

6. **Verify the app is running**
   - Frontend: http://localhost:3000
   - Backend: http://localhost:8000
   - Wall of Fame: http://localhost:3000/contributors

### Step 3: Add Yourself to the Wall of Fame

1. **Navigate to the contributors page**
   - Open http://localhost:3000/contributors in your browser
   - Take a **before screenshot** showing the current contributors

2. **Add your contributor data**
   - Open `frontend/data/contributors.json`
   - Add your information following this format:
   ```json
   {
     "name": "Your Name",
     "github": "your-github-username",
     "avatar": "https://github.com/your-github-username.png",
     "message": "Your Name was here! 🚀",
     "date": "2025-01-27"
   }
   ```

3. **Add your profile picture**
   - Option 1: Use your GitHub avatar (recommended)
     - URL format: `https://github.com/your-github-username.png`
   - Option 2: Add a custom image
     - Place your image in `frontend/public/contributors/`
     - Reference it as `/contributors/your-image.jpg`

4. **Test your changes**
   - Refresh http://localhost:3000/contributors
   - Verify your profile appears correctly
   - Take an **after screenshot** showing your addition

### Step 4: Submit Your Pull Request

1. **Create a new branch**
   ```bash
   git checkout -b contributors/add-your-name
   ```

2. **Commit your changes**
   ```bash
   git add .
   git commit -m "Add [Your Name] to Wall of Fame"
   ```

3. **Push to your fork**
   ```bash
   git push origin contributors/add-your-name
   ```

4. **Create a Pull Request**
   - Go to your fork on GitHub
   - Click "Compare & pull request"
   - **Important**: Include both screenshots in your PR description

## 📸 Required Screenshots

Your pull request **must** include these screenshots:

### Before Screenshot
- Show the contributors page before your addition
- Include the URL bar showing `localhost:3000/contributors`
- Example: "Before adding my profile to the Wall of Fame"

### After Screenshot
- Show the contributors page after your addition
- Include the URL bar showing `localhost:3000/contributors`
- Your profile should be visible
- Example: "After adding my profile - I'm now on the Wall of Fame! 🎉"

## 🎨 Customization Ideas

Feel free to personalize your contribution:

- **Creative messages**: "Lianna was here and she's excited to contribute! 🚀"
- **Custom avatars**: Use a fun, SFW image that represents you
- **Special dates**: Use your actual contribution date
- **Emojis**: Add personality with emojis in your message

## ✅ Success Criteria

Your contribution is complete when:

- [ ] The app runs locally without errors
- [ ] Your profile appears on the Wall of Fame page
- [ ] You've included both before/after screenshots
- [ ] Your pull request is submitted and approved
- [ ] Your profile is live on the deployed site

## 🆘 Need Help?

If you get stuck:

1. **Check the main contributing guide**: [CONTRIBUTING.md](../CONTRIBUTING.md)
2. **Check the main README**: [README.md](../README.md)
3. **Open an issue**: Describe what you're trying to do and where you're stuck
4. **Email for help**: help@justajobapp.com

### Troubleshooting Tips

- **Not redirected after login?**  
  Double-check your `REDIRECT_URI` in both `.env` and Google Cloud settings.  
- **Invalid API key errors?**  
  Some Google APIs require API key restrictions—try generating a new unrestricted key for local testing.  
- **Cannot Build Docker Image?**
   Check that Docker Desktop is running and you have sufficient disk space.
- **When do I need to rebuild Docker?**
   If you change `.env` variables, you'll need to `docker compose down` and `docker compose up --build`

## 🎉 Congratulations!

Once your PR is merged, you'll be officially part of our contributor community! Your profile will be live on our Wall of Fame for everyone to see.

---

**Remember**: This is just the beginning! After completing this onboarding, you'll be ready to tackle more complex issues and features. Welcome to the team! 🚀 
