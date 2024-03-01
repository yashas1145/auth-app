import express from "express";
import path, { dirname } from "path";
import pg from "pg";
import { fileURLToPath } from "url";
import session from "express-session";
import bcrypt from "bcrypt";

const __dirname = dirname(fileURLToPath(import.meta.url));
const port = 3000;
const saltRounds = 12;
const app = express();
const db = new pg.Client({user: "postgres", database: "fs-apps", host: "localhost", password: "kjm40329", port: 5432});

db.connect();

app.use("/css", express.static(path.join(__dirname, "node_modules/bootstrap/dist/css")));
app.use("/js", express.static(path.join(__dirname, "node_modules/bootstrap/dist/js")));
app.use(express.static("public"));
app.use(express.urlencoded({extended: true}));
app.use(session({secret: 'mySecret', resave: false, saveUninitialized: false}));

app.get("/", (req, res) => {
    const data = {
        "userAdded": req.session.userAdded
    }
    res.render("index.ejs", data);
});

app.post("/user", (req, res) => {
    const user = [req.body.email, req.body.password];
    if (addUser(user)) {
        req.session.userAdded = true;
        res.redirect("/");
    } else {
        req.session.userAdded = false;
        res.redirect("/");
    }
});

app.post("/login", async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;
    const user = await getUserByEmail(email);
    if (user.length > 0) {
        bcrypt.compare(password, user[0].user_password, (err, result) => {
            if (err) {
                console.log("Error comparing passwords.");
            } else {
                if (result) {
                    res.render("secrets.ejs");
                } else {
                    res.render("error.ejs", {"message": "Incorrect password. User not authorized."});
                }
            }
        });
    } else {
        console.log("User not found.");
    }
});

app.listen(port, (err) => {
    if (err) throw err;
    console.log(`Server running on port ${port}`);
});

async function addUser(user) {
    try {
        bcrypt.hash(user[1], saltRounds, async (err, hash) => {
            if (err) {
                console.log("Error in hashing password ->", err);
            }
            await db.query("INSERT INTO users (user_email, user_password) VALUES ($1, $2)", [user[0], hash]);
        });
        return true;
    } catch (exc) {
        console.log("Error adding user to database ->", exc);
    }
}

async function getUserByEmail(email) {
    try {
        let user = await db.query("SELECT * FROM users WHERE user_email = $1", [email]);
        return user.rows;
    } catch (exc) {
        console.log("User with email", email, "not found.");
    }
}