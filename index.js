import express from "express";
import path, { dirname } from "path";
import pg from "pg";
import { fileURLToPath } from "url";
import session from "express-session";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";

const __dirname = dirname(fileURLToPath(import.meta.url));
const port = 3000;
const saltRounds = 12;
const app = express();
const db = new pg.Client({user: "postgres", database: "fs-apps", host: "localhost", password: "kjm40329", port: 5432});

db.connect();

app.use(session({secret: 'topsecret', resave: false, saveUninitialized: true, cookie: {maxAge: 1000*60*60*24}}));
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

app.get("/error", (req, res) => {
    res.render("error.ejs", {message: "Something went wrong."});
})

app.post("/user", (req, res) => {
    const user = [req.body.email, req.body.password];
    var userAdded = false;
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

passport.use(new Strategy({usernameField: "email", passwordField: "password"}, async function verify(username, password, cb) {
    try {
        const user = (await db.query("SELECT * FROM users WHERE user_email = $1", [username])).rows;
        console.log(user);
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