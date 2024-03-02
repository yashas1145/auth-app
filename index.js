import express from "express";
import path, { dirname } from "path";
import pg from "pg";
import { fileURLToPath } from "url";
import session from "express-session";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";
import  GoogleStrategy from "passport-google-oauth2"

env.config();

const __dirname = dirname(fileURLToPath(import.meta.url));
const port = 3000;
const saltRounds = 12;
const app = express();
const db = new pg.Client({user: process.env.PG_USER, database: process.env.PG_DATABASE, host: process.env.PG_HOST, password: process.env.PG_PASSWORD, port: process.env.PG_PORT});

db.connect();

app.use(session({secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: true, cookie: {maxAge: 1000*60*60*24}}));
app.use("/css", express.static(path.join(__dirname, "node_modules/bootstrap/dist/css")));
app.use("/js", express.static(path.join(__dirname, "node_modules/bootstrap/dist/js")));
app.use(express.static("public"));
app.use(express.urlencoded({extended: true}));
app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
    const data = {
        "userAdded": req.session.userAdded
    }
    res.render("index.ejs", data);
});

app.get("/secrets", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("secrets.ejs");
    } else {
        res.redirect("/");
    }
});

app.get("/auth/google", passport.authenticate("google", {
    scope: ["profile", "email"]
}));

app.get("/auth/google/secrets", passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/error",
}));

app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) throw err;
        res.redirect("/");
    });
});

app.get("/error", (req, res) => {
    res.render("error.ejs", {message: "Something went wrong."});
})

app.post("/user", async (req, res) => {
    const user = [req.body.email, req.body.password];
    var userAdded = false;
    try {
        const user = await db.query("SELECT * FROM users WHERE user_email = $1", [user[0]]);
        if (user.rows.length > 0) {
            userAdded = true;
            console.log("User already exists.");
            return userAdded;
        }
    } catch (exc) {
        console.log("Error fetching user from database.");
    }
    try {
        bcrypt.hash(user[1], saltRounds, async (err, hash) => {
            if (err) throw err;
            await db.query("INSERT INTO users (user_email, user_password) VALUES ($1, $2)", [user[0], hash]);
            userAdded = true;
        });
    } catch (exc) {
        console.log("Error adding user to database.");
    }
    if (userAdded) {
        req.session.userAdded = true;
        res.redirect("/");
    } else {
        req.session.userAdded = false;
        res.redirect("/");
    }
});

app.post("/login", passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/error",
}));

//Local auth strategy
passport.use("local", new Strategy({usernameField: "email", passwordField: "password"}, async function verify(username, password, cb) {
    try {
        const user = (await db.query("SELECT * FROM users WHERE user_email = $1", [username])).rows;
        if (user.length > 0) {
            bcrypt.compare(password, user[0].user_password, (err, result) => {
                if (err) {
                    console.log("Error comparing passwords -> ", err);
                    return cb(err);
                } else {
                    if (result) {
                        return cb(null, user[0]);
                    } else {
                        return cb(null, false);
                    }
                }
            });
        } else {
            return cb("User not found.");
        }
    } catch (exc) {
        console.log("Error fetching user from database.");
    }
}));

//Google OAuth strategy
passport.use("google", new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/ouath2/v3/userinfo",
}, async (accessToken, refreshToken, profile, cb) => {
    try {
        const result = await db.query("SELECT * FROM users WHERE user_email = $1", [profile.email]);
        if (result.rows.length === 0) {
            const newUser = await db.query("INSERT INTO users (user_email, user_password) VALUES ($1, $2)", [profile.email, "google"]);
            cb(null, newUser);
        } else {
            cb(null, result.rows[0]);
        }
    } catch (exc) {
        cb(exc);
    }
}));

passport.serializeUser((user, cb) => {
    cb(null, user);
});

passport.deserializeUser(async (user, cb) => {
    cb(null, user);
});

app.listen(port, (err) => {
    if (err) throw err;
    console.log(`Server running on port ${port}`);
});