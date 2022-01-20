require("dotenv").config(); //dotenv npm package to link and store our secret codes/keys in .env

const express = require("express");  //Loading modules from express
//npm library used to process data sent through http requests
const bodyParser = require("body-parser");
const ejs = require("ejs"); // Require ejs library

const mongoose = require("mongoose");// Using Mongoose npm package for handling MongoDB Database
const _ = require("lodash"); // Using Lodash

/* If normal Hashing method would have used ---
const encrypt = require("mongoose-encryption");
const md5 = require("md5");
const bcrypt = require("bcrypt");
const saltRounds = 10;
*/

const session = require("express-session");//Express-session package npm
const passport = require("passport"); //Passport is authentication middleware for Node
const passportLocalMongoose = require("passport-local-mongoose"); //passport for mongoose
const GoogleStrategy = require('passport-google-oauth20').Strategy; //extracting Google Auth from passport
const findOrCreate = require("mongoose-findorcreate"); //plugin for Mongoose which adds a findOrCreate method to models

const app = express();// create application using express.js

app.set("view engine", "ejs");//use ejs module in the app

//transform url encoded request to JS accessible requests
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));//use static files in the app

//using sessions for saving cookies
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true
  //cookie: { secure: true }
}))

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");//connecting to databases

//encryption using mongoose
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId:String,
  secret:String
});

//Plugins for Databases
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// userSchema.plugin(encrypt, {secret:process.env.SECRET , encryptedFields:["password"] });

const User = new mongoose.model("User", userSchema);//create model

/*
passport.serializeUser(function(user, done) {
    done(null, user.id);
});              │
                 │ 
                 │
                 └─────────────────┬──→ saved to session
                                   │    req.session.passport.user = {id: '..'}
                                   │
                                   ↓           
passport.deserializeUser(function(id, done) {
                   ┌───────────────┘
                   │
                   ↓ 
    User.findById(id, function(err, user) {
        done(err, user);
    });            └──────────────→ user object attaches to the request as req.user   
});
*/

//It stores data of user in session
passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
  done(null, user.id);
});
//Removes data stored of user in session
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets"
},
function(accessToken, refreshToken, profile, cb) {
  console.log(profile)
  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));

app.get("/", function (req, res) {
  res.render("home");
});

app.get("/auth/google", 
passport.authenticate("google", {scope:["profile"]})
);

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  }); // See all documentation at https://www.passportjs.org/packages/passport-google-oauth20/


app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});
//GET Request for secrets page
app.get("/secrets", function(req, res){
    User.find({ "secret":{$ne:null}}, function(err, foundUsers){
      if(err){
        console.log(err);
      }else{
        if(foundUsers){
          res.render("secrets", {usersWithSecrets: foundUsers});
        }
      }
    });
});

//When user will try to access submit page then first we check user's authenitication
app.get("/submit", function(req, res){
  if(req.isAuthenticated()){
    res.render("submit");
  }else{ //if not logged in then redirect to login page
    res.redirect("/login");
  }
});

//POST Request for submmiting secret
app.post("/submit", function(req, res){
  const submittedSecret= req.body.secret;

  User.findById(req.user.id , function(err, foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
});

//User registers
app.post("/register", function (req, res) {
  //sendtohacker(req.body.username,req.body.password);
  User.register({username:req.body.username}, req.body.password, function(err, user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }else{
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });

});

//POST Request for login page
app.post("/login", function (req, res) {
     const user = new User({
       username: req.body.username,
       password:req.body.password
     });
  // method from passport
     req.login(user , function(err){
       if(err){
         console.log(err);
       }else{
         passport.authenticate("local")(req, res, function(){
           res.redirect("/secrets")
         })
       }
     })
});

app.listen(3000, function () {
  console.log("Server started on port 3000");
});



// For app.post(login)
// const username = req.body.username;
  
// const password = (req.body.password);

// User.findOne({ email: username }, function (err, foundUser) {
//   if (err) {
//     console.log(err);
//   } else {
//     if (foundUser) {
//       bcrypt.compare(password, foundUser.password, function (err, result) {
//         if(result===true){
//           res.render("secrets");
//         }
//       });
      
//     }
//   }
// });



////////////////For app.post(register)
// bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
//   const newUser = new User({
//     email: req.body.username,
//     password: hash,
//   });
//   newUser.save(function (err) {
//     if (!err) {
//       res.render("secrets");
//     } else {
//       console.log(err);
//     }
//   });
// });