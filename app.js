//jshint esversion:6

/* L1 & 2 : convenience long-string encryption; call plugin before compiling model; encrypts on save and decrypt on find
 * userSchema.plugin(encrypt, { secret: process.env.SECRETSTRING, encryptedFields: ['password'] }); //still unsafe, plain in app.js
 * L3 : hashing using md5
 * L4: OAuth & sessions cookies
 */

//module package (npm update in directory)
require("dotenv").config();
const ejs = require("ejs");
const mongoose = require("mongoose");
const findOrCreate = require("mongoose-findorcreate");
const express = require("express");
const app = express();

const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth2").Strategy;
//const encrypt = require("mongoose-encryption");
//const md5 = require("md5");
/*
const bcrypt = require("bcrypt");
const saltRounds = 10;
*/

app.use(session({//see express sessions
    secret: process.env.SESSION,
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());//use passport for auth
app.use(passport.session());//use passport for session, see passport configure

let secretSchema = new mongoose.Schema({
    content: {
        type: String,
        required: true
    }
});
let Secret = mongoose.model("Secret", secretSchema);
//Users db
let userSchema = new mongoose.Schema({
    username: String,
    password: String,
    secrets: [{ secretSchema }]
    //secrets: [secretSchema]//User.secrets.content
});
userSchema.plugin(findOrCreate);
userSchema.plugin(passportLocalMongoose);
let User = new mongoose.model("User", userSchema);


//google oauth
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,// process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,// process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    passReqToCallback: true
},
    function (request, accessToken, refreshToken, profile, done) {
        User.findOrCreate({ username: profile.email }, function (err, user) {
            if (!user) {
                user = new User({
                    username: profile.email
                });
                user.save();
            }
            return done(err, user);
        });
    }
));


let PORT = 3000;
const db = mongoose.connect("mongodb://127.0.0.1:27017/secretsApp", { useNewUrlParser: true });
//schema and documents
//Secrets db


//Seralise -> user data into cookie
passport.use(User.createStrategy());//create local login strategy after initializing in express
passport.serializeUser(User.serializeUser());//can only serialise after setting up session
passport.deserializeUser(User.deserializeUser());

//routing
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.listen(PORT, () => console.log(`Successfully listening to Port ${PORT}`));


//when get secrets, check if logged in, find and loop print secrets from User
app.get("/home", function (req, res) {
    if (req.isAuthenticated()) {
        res.redirect("/secrets");
    } else {
        res.render("home");
    }
})
app.get("/logout", function (req, res) {
    req.logout();
    res.redirect("/home");
});

app.get("/secrets", function (req, res) {
    //check if user is already authenticated -> render secrets page else redirect login page
    if (req.isAuthenticated()) {
        let secretsArray = [];
        req.user.secrets.forEach(secret => {
            Secret.findById(secret, function (err, secret) {
                if (err) {
                    console.log(err);
                }
                secretsArray.push(secret.content);
                if (secret.id == req.user.secrets[req.user.secrets.length - 1].id) {
                    res.render("secrets", { secrets: secretsArray });

                }
            })

        })
        if (req.user.secrets.length == 0) {
            res.render("secrets", { secrets: [] });
        };
    } else {
        res.redirect("/login");
    }
    //get user, find secrets
});
app.get("/register", function (req, res) {
    if (req.isAuthenticated()) {
        res.redirect("/secrets");
    } else {
        res.render("register", { loginError: "visibility: hidden;height:0;" });
    }
});
app.get("/login", function (req, res) {
    if (req.isAuthenticated()) {
        res.redirect("/secrets");
    } else {
        res.render("login", { loginError: "visibility: hidden;height:0;" });
    }
});
app.get("/auth/google", passport.authenticate("google", { scope: ['email', 'profile'] }));
app.get('/auth/google/secrets', passport.authenticate("google", { failureRedirect: '/login' }), function (req, res) {
    res.redirect("/secrets");
});
app.get("/", function (req, res) {
    if (req.isAuthenticated()) {
        res.redirect("/secrets");
    } else {
        res.redirect("/home");
    }
});
app.post("/register", function (req, res) {
    User.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.render("register", { loginError: "visibility: visible" });
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    })
    // check if username exist and get id; check if password exist in the username, if true return home page
    /*
    User.findOne({ email: user }, function (err, foundUser) {
        if (err) {
            console.log(err)
        } else {
            if (foundUser == null) {
                
                bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
                    let newUser = new User({
                        email: user,
                        password: hash
                    });
                    newUser.save(function (err) {
                        if (err) {
                            console.log(err)
                        } else {
                            res.redirect("/secrets");
                        }
                    });
                });  
            } else {
                res.redirect("login");
            }
        }
    })
    */
});
app.post("/login", function (req, res) {
    let user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.logIn(user, function (err) {
        if (err) {
            console.log(err);
            res.render("login", { loginError: "visibility:visibile" });
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");

            })
        }
    })
}

    /*passport.authenticate("local", {
        successRedirect: "/secrets",
        failureRedirect: "/login"
    })
    */
    /*
     user = req.body.username;
    let password = req.body.password;
    User.findOne({ email: user }, function (err, foundDoc) {
        if (err) {
            console.log(err)
        } else {
           
            bcrypt.compare(password, foundDoc.password, function (err, result) {
                if (err) {
                    console.log(err);
                }
                if (foundDoc != null && result === true) {
                    res.redirect("/secrets");
                } else {
                    let loginError = "visibility: visible";
                    res.render("login", { loginError: loginError });
                };
                //hash comparison
            });
            
        }
    })
    */
);
app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/home");
    }
})
app.post("/submit", function (req, res) {
    let newSecret = new Secret({
        content: req.body.secret
    });
    newSecret.save();
    req.user.secrets.push(newSecret);
    req.user.save(function (err) {
        if (err) {
            console.log(err);
            res.redirect("/submit");
        }
        res.redirect("/secrets");
    });
    /*
    //how to push secret into secrets array in user, how to get the user (email)
    User.findOne({ username: req.user }, function (err, foundUser) {
        if (err) {
            console.log(err);
            res.redirect("/submit");
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
    */

});