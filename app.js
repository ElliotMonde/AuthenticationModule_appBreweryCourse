//jshint esversion:6

//module package (npm update in directory)
require("dotenv").config();
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
const express = require("express");
const app = express();
let PORT = 3000;
const db = mongoose.connect("mongodb://127.0.0.1:27017/secretsApp", { useNewUrlParser: true });
var user;

//schema and documents
//Secrets db
let secretSchema = new mongoose.Schema({
    content: {
        type: String,
        required: true
    }
});
let Secret = mongoose.model("Secret", secretSchema);
//Users db
let userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    secrets: [secretSchema]//User.secrets.content
});


//convenience long-string encryption; call plugin before compiling model; encrypts on save and decrypt on find
userSchema.plugin(encrypt, { secret: process.env.SECRETSTRING, encryptedFields: ['password'] }); //still unsafe, plain in app.js

let User = mongoose.model("User", userSchema);

//routing
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.listen(PORT, () => console.log(`Successfully listening to Port ${PORT}`));
app.get("/" || "/home", function (req, res) {
    res.render("home");
});

//when get secrets, check if logged in, find and loop print secrets from User

app.get("/logout", function (req, res) {
    user = "";
    res.render("home");
});

app.get("/secrets", function (req, res) {
    //get user, find secrets
    User.findOne({ email: user }, function (err, foundUser) {
        if (err) { console.log(err) }
        else {
            if (foundUser == null) {
                res.redirect("/home");
            };
            res.render("secrets", { foundUser: foundUser });
        }
    })
});
app.get("/:id", function (req, res) {
    res.render(`${req.params.id}`, { loginError: "visibility: hidden;height:0;" });
});
app.post("/register", function (req, res) {
    user = req.body.username;
    let password = req.body.password;
    // check if username exist and get id; check if password exist in the username, if true return home page
    User.findOne({ email: user }, function (err, foundUser) {
        if (err) {
            console.log(err)
        } else {
            if (foundUser == null) {
                let newUser = new User({
                    email: user,
                    password: password
                });
                newUser.save(function (err) {
                    if (err) {
                        console.log(err)
                    } else {
                        res.redirect("/secrets");
                    }
                });
            } else {
                res.render("register", { loginError: "visibility:visible;" });
            }
        }
    })
});
app.post("/login", function (req, res) {
    user = req.body.username;
    let password = req.body.password;
    User.findOne({ email: user }, function (err, foundDoc) {
        if (err) {
            console.log(err)
        } else {
            if (foundDoc != null && foundDoc.password == password) {
                res.redirect("/secrets");
            } else {
                let loginError = "visibility: visible";
                res.render("login", { loginError: loginError });
            };
        }
    })
});
app.post("/submit", function (req, res) {
    let secret = req.body.secret;
    let newSecret = new Secret({
        content: secret
    });
    newSecret.save();
    //how to push secret into secrets array in user, how to get the user (email)
    User.findOne({ email: user }, function (err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                foundUser.secrets.push(newSecret);
                foundUser.save(function (err) {
                    if (err) {
                        console.log(err);
                    } else {
                        res.redirect("/secrets");
                    }
                });
            }
        }
    })

});