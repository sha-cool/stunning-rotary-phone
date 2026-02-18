const express = require("express");
const bcrypt = require("bcrypt");
const path = require("path");
const session = require("express-session");

const app = express();
const PORT = 3000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(session({
    secret: "supersecretkey",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

// Temporary test user
const user = {
    email: "admin@example.com",
    passwordHash: bcrypt.hashSync("1234", 10)
};

// Store login attempts
const loginHistory = [];

// Login route
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    let match = false;

    if (email === user.email) {
        match = await bcrypt.compare(password, user.passwordHash);
    }

    const attempt = {
        email,
        time: new Date(),
        ip: req.ip,
        status: match ? "SUCCESS" : "FAILED"
    };

    loginHistory.push(attempt);

    // Risk detection
    const failedAttempts = loginHistory.filter(
        attempt => attempt.email === email && attempt.status === "FAILED"
    );

    if (failedAttempts.length >= 3) {
        console.log("ALERT: Multiple failed login attempts detected for:", email);
    }

    if (!match) {
        return res.status(401).send("Invalid credentials");
    }

    req.session.user = email;
    res.redirect("/home");
});

// Protected home route
app.get("/home", (req, res) => {
    if (!req.session.user) {
        return res.redirect("/index.html");
    }

    res.sendFile(path.join(__dirname, "public", "home.html"));
});

// API route to fetch login history
app.get("/api/logins", (req, res) => {
    if (!req.session.user) {
        return res.status(403).json({ error: "Unauthorized" });
    }

    res.json(loginHistory);
});

// Logout
app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/index.html");
    });
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
