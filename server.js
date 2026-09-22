require('dotenv').config();
const express = require('express');
const session = require('express-session');
const axios = require('axios');
const path = require('path');

const app = express();

// Session Configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'secret_key',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // Set to true if using HTTPS behind a proxy in production
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// HTML Template for Access Denied / Unauthorized Pages
const getAccessDeniedHTML = (message = "Your Discord account does not have authorization to view this page.") => `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AniTracker - Access Denied</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;800&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Plus Jakarta Sans', sans-serif; }
    </style>
</head>
<body class="bg-[#0b0f17] text-white min-h-screen flex items-center justify-center p-4">
    <div class="max-w-md w-full bg-[#131927] border border-red-500/20 rounded-2xl p-8 text-center shadow-2xl backdrop-blur-xl relative overflow-hidden">
        
        <!-- Glow Effect -->
        <div class="absolute -top-10 -right-10 w-32 h-32 bg-red-500/10 rounded-full blur-3xl"></div>
        <div class="absolute -bottom-10 -left-10 w-32 h-32 bg-purple-500/10 rounded-full blur-3xl"></div>

        <!-- Icon -->
        <div class="w-20 h-20 bg-red-500/10 border border-red-500/20 rounded-2xl flex items-center justify-center mx-auto mb-6">
            <svg class="w-10 h-10 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
            </svg>
        </div>

        <!-- Title & Subtitle -->
        <h1 class="text-2xl font-extrabold text-white mb-2">Access Denied</h1>
        <p class="text-gray-400 text-sm mb-6 leading-relaxed">
            The <span class="text-purple-400 font-semibold">AniTracker</span> dashboard is restricted exclusively to the bot owner. ${message}
        </p>

        <!-- Action Button -->
        <a href="/login" class="inline-flex items-center justify-center w-full gap-2 px-6 py-3 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold rounded-xl transition-all duration-200 shadow-lg shadow-indigo-600/30">
            <svg class="w-5 h-5 fill-current" viewBox="0 0 127.14 96.36">
                <path d="M107.7,8.07A105.15,105.15,0,0,0,81.47,0a72.06,72.06,0,0,0-3.36,6.83A97.68,97.68,0,0,0,49,6.83,72.37,72.37,0,0,0,45.64,0,105.89,105.89,0,0,0,19.39,8.09C2.79,32.65-1.71,56.6.54,80.21h0A105.73,105.73,0,0,0,32.71,96.36,77.7,77.7,0,0,0,39.6,85.25a68.42,68.42,0,0,1-10.85-5.18c.91-.66,1.8-1.34,2.66-2a75.57,75.57,0,0,0,64.32,0c.87.71,1.76,1.39,2.66,2a68.68,68.68,0,0,1-10.87,5.19,77,77,0,0,0,6.89,11.1,105.25,105.25,0,0,0,32.19-16.14c2.64-27.38-4.51-51.11-20.31-72.15ZM42.45,65.69C36.18,65.69,31,60,31,53s5-12.74,11.43-12.74S54,45.92,53.87,53,48.8,65.69,42.45,65.69Zm42.24,0C78.41,65.69,73.25,60,73.25,53s5-12.74,11.44-12.74S96.23,45.92,96.1,53,91,65.69,84.69,65.69Z"/>
            </svg>
            Sign in with Discord
        </a>
    </div>
</body>
</html>
`;

// Owner Authentication Guard Middleware
function requireOwner(req, res, next) {
    if (req.session.user && req.session.user.id === process.env.OWNER_ID) {
        return next();
    }
    return res.status(403).send(getAccessDeniedHTML());
}

// Root redirect
app.get('/', (req, res) => {
    res.redirect('/admin');
});

// 1. Discord OAuth2 Login Route
app.get('/login', (req, res) => {
    const redirectUri = encodeURIComponent(process.env.REDIRECT_URI);
    const discordAuthUrl = `https://discord.com/oauth2/authorize?client_id=${process.env.CLIENT_ID}&response_type=code&redirect_uri=${redirectUri}&scope=identify+email`;
    console.log('🔄 Redirecting user to Discord OAuth2...');
    res.redirect(discordAuthUrl);
});

// 2. OAuth2 Callback Route
app.get('/api/auth/callback', async (req, res) => {
    const { code } = req.query;

    if (!code) {
        console.log('❌ No code provided in query params');
        return res.status(400).send('No authorization code provided');
    }

    try {
        console.log('🔑 Exchanging code for access_token...');
        
        const tokenResponse = await axios.post('https://discord.com/api/oauth2/token', new URLSearchParams({
            client_id: process.env.CLIENT_ID,
            client_secret: process.env.CLIENT_SECRET,
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: process.env.REDIRECT_URI,
        }), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });

        const { access_token } = tokenResponse.data;
        console.log('✅ Access Token retrieved successfully!');

        const userResponse = await axios.get('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${access_token}` }
        });

        const userData = userResponse.data;
        console.log(`👤 User authenticated: ${userData.username} (${userData.id})`);

        if (userData.id !== process.env.OWNER_ID) {
            console.log(`⚠️ Access Denied: User ID ${userData.id} does not match OWNER_ID ${process.env.OWNER_ID}`);
            return res.status(403).send(getAccessDeniedHTML(`Account (${userData.username}) is not authorized.`));
        }

        req.session.user = userData;
        console.log('🎉 Owner authenticated! Redirecting to dashboard...');
        res.redirect('/admin');

    } catch (error) {
        console.error('❌ OAuth2 Error Details:', error.response ? error.response.data : error.message);
        const errData = error.response ? JSON.stringify(error.response.data) : error.message;
        res.status(500).send(`<h1>Authentication Failed</h1><p>Reason: ${errData}</p>`);
    }
});

// 3. Protected Admin Route
app.get('/admin', requireOwner, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// 4. Current User API Endpoint
app.get('/api/user', requireOwner, (req, res) => {
    res.json(req.session.user);
});

// 5. Logout Route
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 AniTracker Admin Dashboard running on http://localhost:${PORT}`);
});