const express = require("express");
const bcrypt = require("bcrypt");
const path = require("path");
const session = require("express-session");

const app = express();
const PORT = 3000;

/* =========================
   MIDDLEWARE
========================= */

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(session({
    secret: "supersecretkey",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // set true if using HTTPS
}));

/* =========================
   USERS (Temporary In-Memory)
========================= */

const users = [
    {
        email: "admin@example.com",
        passwordHash: bcrypt.hashSync("1234", 10)
    },
    {
        email: "user@example.com",
        passwordHash: bcrypt.hashSync("5678", 10)
    },
    {
        email:"shahulhameeddarvesh@gmail.com",
        passwordHash:bcrypt.hashSync("2218", 10)
    }
];

/* =========================
   LOGIN HISTORY STORAGE
========================= */

const loginHistory = [];

/* =========================
   LOGIN ROUTE
========================= */

app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    let match = false;

    const foundUser = users.find(u => u.email === email);

    if (foundUser) {
        match = await bcrypt.compare(password, foundUser.passwordHash);
    }

    const attempt = {
        email,
        time: new Date(),
        ip: req.ip,
        status: match ? "SUCCESS" : "FAILED"
    };

    loginHistory.push(attempt);

    // Risk detection: 3 failed attempts
    const failedAttempts = loginHistory.filter(
        a => a.email === email && a.status === "FAILED"
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

/* =========================
   PROTECTED HOME ROUTE
========================= */

app.get("/home", (req, res) => {
    if (!req.session.user) {
        return res.redirect("/index.html");
    }

    res.sendFile(path.join(__dirname, "public", "home.html"));
});

/* =========================
   API: LOGIN HISTORY
========================= */

app.get("/api/logins", (req, res) => {
    if (!req.session.user) {
        return res.status(403).json({ error: "Unauthorized" });
    }

    res.json(loginHistory);
});

/* =========================
   LOGOUT
========================= */

app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/index.html");
    });
});

/* =========================
   START SERVER
========================= */

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
