# Authentication & Security


### Table of Contents

1.  [Express](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#express)</br>
    1.1 [Installation](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#installation)</br>
    1.2 [Other Packages Installation](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#other-packages-installation)</br>
2.  [Security Level 1 - The Lowest Level](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#security-level-1---the-lowest-level)</br>
    2.1. [HTTP POST Request/POST Route Code Example](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#http-post-requestpost-route-code-example)</br>
      2.1.1. [POST Request to Register Route Code Example](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#post-request-to-register-route-code-example)</br>
      2.1.2. [POST Request to Login Route Code Example](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#post-request-to-login-route-code-example)</br>
3.  [Security Level 2 - mongoose-encryption](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#security-level-2---mongoose-encryption)</br>
      3.1 [How it Works](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#how-it-works)</br>
      3.2 [Installation](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#installation-1)</br>
      3.3 [Usage](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#usage)</br>
            3.1.1 [Basic](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#basic)</br>
            3.1.2 [Encrypt Only Certain Fields](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#encrypt-only-certain-fields)</br>
            3.1.3 [Secret String Instead of Two Keys](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#secret-string-instead-of-two-keys)</br>
      3.4 [Mongoose Encryption Code Example](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#mongoose-encryption-code-example)</br>
      3.5 [Environment Variables to Keep Secrets Safe](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#environment-variables-to-keep-secrets-safe)</br>
            3.5.1 [dotenv](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#dotenv)</br>
            3.5.2 [Installation](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#installation-2)</br>
            3.5.3 [Usage](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#usage-1)</br>
            3.5.4 [Environment Variables to Keep Secrets Safe Code Example](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#environment-variables-to-keep-secrets-safe-code-example)</br>
            3.5.5 [.gitignore](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#gitignore)</br>
4.  [Security Level 3 - Hash](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#security-level-3---hash)</br>
    4.1 [MD5](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#md5)</br>
    4.2 [Installation](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#installation-3)</br>
    4.3 [Usage](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#usage-2)</br>
    4.4 [Hash Function (MD5) Code Example](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#hash-function-md5-code-example)</br>
5.  [Security Level 4 - Salting and Hashing Passwords with bcryptjs](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#security-level-4---salting-and-hashing-passwords-with-bcryptjs)</br>
    5.1 [bcryptjs Hashing Algorithm (replaces MD5)](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#bcryptjs-hashing-algorithm-replaces-md5)</br>
    5.2 [Salting](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#salting)</br>
          5.2.1 [Salt Rounds](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#salt-rounds)</br>
    5.3 [Installation](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#installation-4)</br>
    5.4 [Usage](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#usage-3)</br>
    5.5 [Basic](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#basic-1)</br>
    5.6 [bcryptjs and Salting Code Example](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#bcryptjs-and-salting-code-example)</br>
6.  [Security Level 5 - Cookies and Sessions](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#security-level-5---cookies-and-sessions)</br>
        6.1 [Implementation with Passport.js](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#implementation-with-passportjs)</br>
        6.2 [Passport.js and Other Packages Installation](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#passportjs-and-other-packages-installation)</br>
        6.3 [express-session and Usage](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#express-session-and-passport-local-mongoose-usage)</br>
              6.3.1 [Setup Express Session](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#setup-express-session)</br>
              6.3.2 [Initialize and Start Using passport.js](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#initialize-and-start-using-passportjs)</br>
              6.3.3 [Setup passport-local-mongoose](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#setup-passport-local-mongoose)</br>
              6.3.4 [passport-local Configuration](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#passport-local-configuration)</br>
              6.3.5 [Fixing Deprecation Warning](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#fixing-deprecation-warning)</br>
        6.4 [GET Request to Secrets Route Code Example](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#get-request-to-secrets-route-code-example)</br>
        6.5 [GET Request to Logout Route Code Example](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#get-request-to-logout-route-code-example)</br>
        6.6 [POST Request to Register Route Code Example](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#post-request-to-register-route-code-example-1)</br>
        6.7 [POST Request to Login Route Code Example](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#post-request-to-login-route-code-example-1)</br>
7.  [Security Level 6 - OAuth2.0 (Open Authorisation) & How to Implement Sign In with Google](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#security-level-6---oauth20-open-authorisation--how-to-implement-sign-in-with-google)</br>
      7.1 [Why OAuth?](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#why-oauth)</br>
              7.1.1 [1. Granular Access Levels](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#1--granular-access-levels)</br>
              7.1.2 [2. Read/Read+Write Access](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#2--readreadwrite-access)</br>
              7.1.3. [3. Revoke Access](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#3--revoke-access)</br>
      7.2 [OAuth Steps](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#oauth-steps)</br>
              7.2.1 [First Step - Set Up The App](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#first-step---set-up-the-app)</br>
              7.2.2 [Second Step - Redirect to Authenticate](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#second-step---redirect-to-authenticate)</br>
              7.2.3 [Third Step - User Logs In](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#third-step---user-logs-in)</br>
              7.2.4 [Fourth Step - User Grants Permissions](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#fourth-step---user-grants-permissions)</br>
              7.2.5 [Fifth Step - Receive Authorisation Code](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#fifth-step---receive-authorisation-code)</br>
              7.2.6 [Sixth Step - Exchange AuthCode for Access Token](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#sixth-step---exchange-authcode-for-access-token)</br>
      7.3 [Passport Strategy for Authenticating with Google Using the OAuth 2.0 API](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#passport-strategy-for-authenticating-with-google-using-the-oauth-20-api)</br>
              7.3.1 [passport-google-oauth20 Installation](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#passport-google-oauth20-installation)</br>
              7.3.2 [passport-google-oauth20 Usage](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#passport-google-oauth20-usage)</br>
                  7.3.2.1 [passport-google-oauth20 Create an Application](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#passport-google-oauth20-create-an-application)</br>
                      7.3.2.2.1 [Inside Google Console](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#inside-google-console)</br>
                  7.3.2.3 [passport-google-oauth20 Configure Strategy](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#passport-google-oauth20-configure-strategy)</br>
                  7.3.2.4 [passport-google-oauth20 Configure Strategy Code Example](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#passport-google-oauth20-configure-strategy-code-example)</br>
                      7.3.2.5.1 [mongoose-findorcreate Installation](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#mongoose-findorcreate-installation)</br>
                      7.3.2.5.2 [mongoose-findorcreate Usage](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#mongoose-findorcreate-usage)</br>
                      7.3.2.5.3 [Now the last step is to add it as a plugin to our schema](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#now-the-last-step-is-to-add-it-as-a-plugin-to-our-schema)</br>
                  7.3.2.6 [passport-google-oauth20 Authenticate Requests](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#passport-google-oauth20-authenticate-requests)</br>
                  7.3.2.7 [passport-google-oauth20 Authenticate Requests Code Example](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#passport-google-oauth20-authenticate-requests-code-example)</br>
8.  [Letting Users Submit Secrets](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#letting-users-submit-secrets)</br>
    8.1 [secrets.ejs](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#secretsejs)</br>
    8.2 [Secrets GET Route](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#secrets-get-route)</br>
    8.3 [Create Submit GET Route](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#create-submit-get-route)</br>
    8.4 [Create Submit POST Route](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#create-submit-post-route)</br>
    8.5 [Amend mongoose userSchema](https://github.com/SchmidtRichard/Authentication-Security/blob/master/README.md#amend-mongoose-userschema)</br>


* * *

# [Express](https://expressjs.com/en/starter/installing.html)

`Express.js`, or simply `Express`, is a _back end web application framework_ for `Node.js`, released as free and open-source software under the MIT License. It is designed for building web applications and APIs. It has been called the de facto standard server framework for `Node.js`.

`Express` is the _back-end component_ of popular development stacks like the `MEAN`, `MERN` or `MEVN stack`, together with the `MongoDB` database software and a `JavaScript` front-end framework or library.

The primary use of `Express` is to _provide server-side logic_ for web and mobile applications, and as such it's used all over the place.

## Installation

Use the npm init command to create a `package.json` file for your application.

```express
npm init -y
```

## Other Packages Installation

Install some packages(`express`, `ejs`, `body-parser` and `mongoose`)

```express
npm i express ejs body-parser mongoose
```

* * *

# Security Level 1 - The Lowest Level

Simply creating an account for the user to store the email & password into mongoDB (users collection)

## HTTP POST Request/POST Route Code Example

### POST Request to Register Route Code Example

```js
//POST request (register route) to post the username and password the user enter when registering
app.post("/register", function(req, res) {
  //Create the new user using the User model
  const newUser = new User({
    //Values from the userSchema checked against the register.ejs variables
    email: req.body.username,
    password: req.body.password
  });
  //Save the new user
  newUser.save(function(err) {
    if (err) {
      console.log(err);
    } else {
      /*
      Only render the secrets page if the user is logged in
      that is why there is no app.get("/secrets")... route
      */
      res.render("secrets");
    }
  });
});
```

### POST Request to Login Route Code Example

```js
//POST request (login route) to login the user
app.post("/login", function(req, res) {
  //Check in mongoDB if the credentials entered exist in the DB
  const username = req.body.username;
  const password = req.body.password;

  /*
  Check the details entered above (username & password)
  if the details exist in the DB and match what is in the DB
  Look through the collection of Users (User)
  */
  User.findOne({
    email: username
  }, function(err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      /*
      If the user has been found in the DB
      Check if the password is correct, if correct render to the secrets page
      */
      if (foundUser) {
        if (foundUser.password === password) {
          res.render("secrets");
        }
      }
    }
  });
});
```

* * *

# Security Level 2 - [mongoose-encryption](https://www.npmjs.com/package/mongoose-encryption)

Simple encryption and authentication for mongoose documents. Relies on the Node `crypto` module. Encryption and decryption happen transparently during save and find. Rather than encrypting fields individually, this plugin takes advantage of the BSON nature of mongoDB documents to encrypt multiple fields at once.

## How it Works

Encryption is performed using `AES-256-CBC` with a random, unique initialization vector for each operation. Authentication is performed using `HMAC-SHA-512`.

## Installation

`npm install mongoose-encryption`

## Usage

Generate and store keys separately. They should probably live in environment variables, but be sure not to lose them. You can either use a single `secret` string of any length; or a pair of base64 strings (a 32-byte `encryptionKey` and a 64-byte `signingKey`).

```js
var mongoose = require('mongoose');
var encrypt = require('mongoose-encryption');
```

### Basic

By default, all fields are encrypted except for `_id`, `__v`, and fields with indexes

```js
var mongoose = require('mongoose');
var encrypt = require('mongoose-encryption');

var userSchema = new mongoose.Schema({
    name: String,
    age: Number
    // whatever else
});

// Add any other plugins or middleware here. For example, middleware for hashing passwords

var encKey = process.env.SOME_32BYTE_BASE64_STRING;
var sigKey = process.env.SOME_64BYTE_BASE64_STRING;

userSchema.plugin(encrypt, { encryptionKey: encKey, signingKey: sigKey });
// This adds _ct and _ac fields to the schema, as well as pre 'init' and pre 'save' middleware,
// and encrypt, decrypt, sign, and authenticate instance methods

User = mongoose.model('User', userSchema);
```

And you're all set. `find` works transparently (though you cannot query fields that are encrypted) and you can make New documents as normal, but you should not use the `lean` option on a `find` if you want the document to be authenticated and decrypted. `findOne`, `findById`, etc..., as well as `save` and `create` also all work as normal. `update` will work fine on unencrypted and unauthenticated fields, but will not work correctly if encrypted or authenticated fields are involved.

### Encrypt Only Certain Fields

You can also specify exactly which fields to encrypt with the `encryptedFields` option. This overrides the defaults and all other options.

```js
// encrypt age regardless of any other options. name and _id will be left unencrypted
userSchema.plugin(encrypt, { encryptionKey: encKey, signingKey: sigKey, encryptedFields: ['age'] });
```

### Secret String Instead of Two Keys

For convenience, you can also pass in a single secret string instead of two keys.

```js
var secret = process.env.SOME_LONG_UNGUESSABLE_STRING;
userSchema.plugin(encrypt, { secret: secret });
```

## Mongoose Encryption Code Example

```js
/*Replace the simple version of the schema above to the below one
The userSchema is no longer a simple javascript object,
it is now an object create from the mongoose.Schema class
*/
const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

/*
Mongoose Encryption Secret String
It defines a secret (a long unguessable string) then uses this secret to encrypt the DB
*/
const secret = "Thisisourlittlesecret.";
/*
Use the secret to above to encrypt the DB by taking the userSchema and add
mongoose.encrypt as a plugin to the schema and pass over the secret as a JS object

It is important to add the plugin before the mongoose.model

Encrypt Only Certain Fields (password) -> encryptedFields: ['password']
*/
userSchema.plugin(encrypt, {
  secret: secret,
  encryptedFields: ['password']
});
```

## Environment Variables to Keep Secrets Safe

### [dotenv](https://www.npmjs.com/package/dotenv)

Dotenv is a zero-dependency module that loads environment variables from a `.env` file into `process.env`.

### Installation

```js
npm install dotenv
```

### Usage

As early as possible in your application, require and configure dotenv.

```js
require('dotenv').config()
```

Create a `.env` file in the root directory of your project. Add environment-specific variables on new lines in the form of `NAME=VALUE`. For example:

```js
DB_HOST=localhost
DB_USER=root
DB_PASS=s1mpl3
```

`process.env` now has the keys and values you defined in your `.env` file.

```js
    const db = require('db')
    db.connect({
      host: process.env.DB_HOST,
      username: process.env.DB_USER,
      password: process.env.DB_PASS
    })
```

### Environment Variables to Keep Secrets Safe Code Example

.env file

```js
# Add the enviroment variables

# Mongoose Encryption Secret String
# It defines a secret (a long unguessable string) then uses this secret to encrypt the DB

SECRET=Thisisourlittlesecret.
```

Back in the `app.js` file, you need to delete and update the the below (check against previous code)

```js
/*
Mongoose Encryption Secret String
It defines a secret (a long unguessable string) then uses this secret to encrypt the DB
*/

//Move to below code to the .env file


//const secret = "Thisisourlittlesecret."; <- Delete this (Environment Variables to Keep Secrets Safe)


/*
Use the secret above to encrypt the DB by taking the userSchema and add
mongoose.encrypt as a plugin to the schema and pass over the secret as a JS object

It is important to add the plugin before the mongoose.model

Encrypt Only Certain Fields (password) -> encryptedFields: ['password']
*/
userSchema.plugin(encrypt, {
  secret: process.env.SECRET, //Enviroment variables -> .env file
  encryptedFields: ['password']
});
```

### [.gitignore](https://github.com/github/gitignore/blob/master/Node.gitignore)

Tell git which files and folders it should ignore when uploading to GitHub, the `.env` file should always be kept hidden from GitHub and any other public place in order to keep the secrets safe.

1.  From the Hyper terminal stop `nodemon app.js` and type in `touch .gitignore`, this will create the `.gitignore` file that you can configure to ignore all the files and folders you want to

Examples:

```js
# Dependency directories
node_modules/
jspm_packages/

# dotenv environment variables file
.env
.env.test
```

* * *

# Security Level 3 - Hash

Hashing takes away the need for an encryption key. Hashing does not decrypt the password back into plain text. Hash functions turns the password the user has chosen into a hash, and store the hash into the DB.

Hash functions are mathematical equations designed to make it almost impossible to go backwards, in other words, it is almost impossible to turn a hash back into a password.

## [(MD5)](https://www.npmjs.com/package/md5)

A JavaScript function for hashing messages with MD5.

## Installation

You can use this package on the server side as well as the client side.

Node.js:

```js
npm install md5
```

## Usage

```js
var md5 = require('md5');

console.log(md5('message'));
```

This will print the following

```js
78e731027d8fd50ed642340b7c9a63b3
```

## Hash Function (MD5) Code Example

```js
//POST request (register route) to post the username and password the user enter when registering
app.post("/register", function(req, res) {
  //Create the new user using the User model
  const newUser = new User({
    //Values from the userSchema checked against the register.ejs variables
    email: req.body.username,

    /*
    Instead of saving the password, we will use the hash function (md5)
    to turn the password into an inrreversabel hash
    */
    password: md5(req.body.password)
  });
  //Save the new user
  newUser.save(function(err) {
    if (err) {
      console.log(err);
    } else {
      /*
      Only render the secrets page if the user is logged in
      that is why there is no app.get("/secrets")... route
      */
      res.render("secrets");
    }
  });
});

//POST request (login route) to login the user
app.post("/login", function(req, res) {
  //Check in mongoDB if the credentials entered exist in the DB
  const username = req.body.username;

  /*
  Instead of saving the password, we will use the hash function (md5)
  to turn the password into an inrreversabel hash

  Hash the password the password the user type in using the same hash function (md5)
  and compare the outcome of this with the hash that has being stored in our database (registration)
  */
  const password = md5(req.body.password);

  /*
  Check the details entered above (username & password)
  if the details exist in the DB and match what is in the DB
  Look through the collection of Users (User)
  */
  User.findOne({
    email: username
  }, function(err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      /*
      If the user has been found in the DB
      Check if the password is correct, if correct render to the secrets page
      */
      if (foundUser) {

        /*
        Hash function - now compare the hash inside the DB with the
        hashed version of the user's password
        */
        if (foundUser.password === password) {
          res.render("secrets");
        }
      }
    }
  });
});
```

* * *

# Security Level 4 - Salting and Hashing Passwords with [bcryptjs](https://www.npmjs.com/package/bcryptjs)

## bcryptjs Hashing Algorithm (replaces MD5)

Optimized `bcrypt` in JavaScript with zero `dependencies`. Compatible to the `C++ bcrypt` binding on `node.js` and also working in the browser.

> :warning: **WARNING**</br></br>
> [(node.bcrypt.js)](https://www.npmjs.com/package/bcrypt) installation did not work for Windows, so bcrypt.js was used instead

## Salting

Salting takes the hashing a little bit further. In addition to the password, it also generates a random set of characters and those characters along with the user's password gets combined and then put through the hash function. So the resulting hash is created from both the password as well as the random unique `salt`. So adding the `salt` increases the number of characters which makes the database a lot more secure.

The latest computers (2019) can calculate about 20 billion MD5 hashes per second, however, they can only calculate about 17 thousand `bcrypt` hashes per second which makes it dramatically harder for a hacker to generate those pre-compiled hash tables.

### Salt Rounds

How many `rounds` will you `salt` the password with, the more `rounds` the more secure the password is from hackers.

_Example:_ to have two `rounds` of salting, we take the `hash` that was generated in `round` 1 and we add the same `salt` from before. And now run it through `bcrypt hash function` again and we end up with a different `hash`. And the number of times you do this is the number of `salt rounds`.

When it comes to checking the user's password when they login, we will take the password that they entered and combine it with the `salt` that is stored in the database and run it through the same number of salting rounds until we end up with the final `hash` and we compare the `hash` against the one that is stored in the database to see if the user entered the correct password.

## Installation

```js
npm install bcryptjs
```

## Usage

```js
const bcrypt = require("bcryptjs");
```

## Basic

Auto-gen a salt and hash:

```js
bcrypt.hash('bacon', 8, function(err, hash) {
});
```

To check a password:

```js
// Load hash from your password DB.
bcrypt.compare("B4c0/\/", hash, function(err, res) {
    // res === true
});
```

## bcryptjs and Salting Code Example

```js
//POST request (register route) to post the username and password the user enter when registering
app.post("/register", function(req, res) {
  /*
  bcrypt.hash('bacon', 8, function(err, hash) {
  });

    use the hash function passing in the password that the user has typed in when
    they registered and also the number of rounds of salting we want to do and bcryptjs
    will automatically genereate the random salt and also hash our password with the
    number of salt rounds that we designed
  */
  bcrypt.hash(req.body.password, 15, function(err, hash) {

    //Create the new user using the User model
    const newUser = new User({
      //Values from the userSchema checked against the register.ejs variables
      email: req.body.username,

      password: hash // replace the previous code with the hash that has being generated
    });
    //Save the new user
    newUser.save(function(err) {
      if (err) {
        console.log(err);
      } else {
        /*
        Only render the secrets page if the user is logged in,
        that is why there is no app.get("/secrets")... route
        */
        res.render("secrets");
      }
    });
  });
});

//POST request (login route) to login the user
app.post("/login", function(req, res) {
  //Check in mongoDB if the credentials entered exist in the DB
  const username = req.body.username;

  //Get the password entered by the user
  const password = req.body.password;

  /*
  Check the details entered above (username & password)
  if the details exist in the DB and match what is in the DB
  Look through the collection of Users (User)
  */
  User.findOne({
    email: username
  }, function(err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      /*
      If the user has been found in the DB
      Check if the password is correct, if correct render to the secrets page
      */
      if (foundUser) {
        /*
        bcryptjs Hash function - now compare the hash inside the DB with the
        hashed version of the user's password entered by the user

        // Load hash from your password DB.
        bcrypt.compare("B4c0/\/", hash, function(err, res) {
          // res === true
        });

        compare the password ("B4c0/\/") entered by the user against the
        hash (hash) one stored in the DB

        Rename the res to result inside the call back function so it does not get
        confused with the res we are trying to use
        */
        bcrypt.compare(password, foundUser.password, function(err, result) {
          /*
          if the result of the comparison is equals to true,
          then the password after hashing with the salt is equal to
          the hash we get stored the DB, then it means the user got the
          correct login password, then res.render the secrets page
          */
          if (result === true) {
            res.render("secrets");
          }
        });
      }
    }
  });
});
```

* * *

# Security Level 5 - Cookies and Sessions

There are lots of different types of cookies but the types we are going to be looking at for this project are the ones that are used to establish and maintain a session. A session is a period of time when a browser interacts with a server.

Usually when the user log into a website that is when the session starts and that is when the cookie gets created, and inside that cookie there will be the user's credentials that says this user is logged in and has been successfully authenticate, which means as the user continues to browse the website he will not be asked to login again when he tries to access a page that requires authentication because they can always check against that active cookie that is on the browser and it maintains the authentication for this browsing session until the point when the user log out, which is when the session ends and the cookie that is related to the session gest **destroyed**.

## Implementation with [Passport.js](http://www.passportjs.org/docs/)

The **cookies** and **sessions** will be implemented into the website using `Passport.js`.

Passport.js is an authentication middleware for `Node.js`. Extremely flexible and modular, Passport.js can be unobtrusively dropped in to any `Express-based` web application. A comprehensive set of strategies support authentication using a **username** and a **password**, **Facebook**, **Twitter**, and **more**.

## Passport.js and Other Packages Installation

The packages to install are: `passport`, `passport-local`, `passport-local-mongoose`, and `express-session`.

```js
npm i passport passport-local passport-local-mongoose express-session
```

`express-session` is the first package that needs to be configured.

It is extremely important to place the parts of the new code exactly where it is shown placed in the examples to follow.

## [express-session](https://www.npmjs.com/package/express-session) and [passport-local-mongoose](https://www.npmjs.com/package/passport-local-mongoose) Usage

```js
const session = require('express-session')
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
```

> :warning: **WARNING**</br></br>
> We don't need to require passport-local because it's one of those dependencies that will be needed by passport-local-mongoose

### Setup Express Session

```js
//Set up express session
app.use(session({
  //js object with a number of properties (secret, resave, saveUninitialized)
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));
```

### Initialize and Start Using passport.js

```js
//Initialize and start using passport.js
app.use(passport.initialize());
//Tell the app to use passport to also setup the sessions
app.use(passport.session());
```

### Setup passport-local-mongoose

In order to set up the passport-local-mongoose, it needs to be added to the mongoose schema as a plugin.

That is what we will use now to hash and salt the passwords and to save the users into the mongoDB database.

```js
userSchema.plugin(passportLocalMongoose);
```

### passport-local Configuration

Create a strategy which is going to be the **local** strategy to authenticate users' by using their username and password and also to `serialize` and `deserialize` the user.

**Serialize** the user is to basically create the cookie and add inside the message - which is namely the users' identification - into the cookie.

**Deserialize** the user is to basically allow passport to be able to crumble the cookie and discover the message inside which is who the user is all of the users' identification so that we can **authenticate** the user on the server.

```js
passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());
```

#### [Fixing Deprecation Warning](https://github.com/Automattic/mongoose/issues/6890#issuecomment-416218953)

```js
mongoose.set("useCreateIndex", true);
```

> :warning: **WARNING**</br></br>
> After running nodemon app.js we may get the error below:</br>
> DeprecationWarning: collection.ensureIndex is deprecated. Use createIndexes instead

## GET Request to Secrets Route Code Example

```js
//Target the secrets route to render the secrets page
app.get("/secrets", function(req, res) {

  /*
  Course code was allowing the user to go back to the secrets page after loggin out,
  that is because when we access a page, it is cached by the browser, so when the user is accessing a
  cached page (like the secrets one) you can go back by pressing the back button on the browser,
  the code to fix it is the one below so the page will not be cached
  */

  res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate, max-stal e=0, post-check=0, pre-check=0');

  /*
  Check if the user is authenticated and this is where we are relying on
  passport.js, session, passport-local and passport-local-mongoose to make sure
  that if the user is already logged in then we should simply render the secrets page
  but if the user is not logged in then we are going to redirect the user to the login page
  */
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.render("login");
  }
});
```

## GET Request to Logout Route Code Example

```js
//Target the logout route
app.get("/logout", function(req, res) {
  //deauthenticate the user and end the user session
  req.logout();
  //redirect the user to the root route (home page)
  res.redirect("/");
});
```

## POST Request to Register Route Code Example

Now we will incorporate `hashing`, `salting` and `authentication` using `passport.js` and the packages just added (`passport` `passport-local` `passport-local-mongoose` `express-session`).

```js
//POST request (register route) to post the username and password the user enter when registering
app.post("/register", function(req, res) {

  /*
  Now we will incorporate hashing and salting and authentication using passport.js and the packages
  just added (passport passport-local passport-local-mongoose express-session)
  */

  /*
  Tap into the User model and call the register method, this method comes from
  passport-local-mongoose package which will act as a middle-man to create and save the new user
  and to interact with mongoose directly

  js object -> {username: req.body.username}
  */
  User.register({
    username: req.body.username
  }, req.body.password, function(err, user) {
    if (err) {
      consolo.log(err);
      //Redirect the user back to the register page if there are any error
      res.redirect("/register");
    } else {
      /*
      Authentica the user using passport if there are no errors
      the callback (function()) below is only triggered if the authentication
      is successfull and we managed to successfully setup a cookie that saved
      their current logged in session
      */
      passport.authenticate("local")(req, res, function() {
        /*
        As we are authenticating the user and setting up a logged in session for him
        then the user can go directly to the secret page, they should automatically
        be able to view it if they are still logged in - so now we need to create a secrets route
        */
        res.redirect("/secrets");
      });
    }
  });
});
```

## POST Request to Login Route Code Example

Now we will incorporate `hashing`, `salting` and `authentication` using `passport.js` and the packages just added (`passport` `passport-local` `passport-local-mongoose` `express-session`).

```js
//POST request (login route) to login the user

/*
passport.authenticate("local")

Course code was allowing the user to enter the right username (email) and wrong password
and go to the secrets page by typing in http://localhost:3000/secrets in the browser after getting
the Unauthorized page message, now the addition of passport.authenticate("local")to the
app.post... route fixes this issue
*/

app.post("/login", passport.authenticate("local"), function(req, res) {

  /*
  Now we will incorporate hashing and salting and authentication using passport.js and the packages
  just added (passport passport-local passport-local-mongoose express-session)
  */

  //Create a new user from the mongoose model with its two properties (username, password)
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  //Now use passport to login the user and authenticate him - take the user created from above
  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      //Authenticate the user if there are no errors
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});
```

* * *

# Security Level 6 - OAuth2.0 (Open Authorisation) & How to Implement Sign In with Google

Simply, it is an open standard for **token** based authorization. [OAuth 2](https://www.digitalocean.com/community/tutorials/an-introduction-to-oauth-2) is an authorization framework that enables applications to obtain limited access to user accounts on an HTTP service, such as Facebook, GitHub, and DigitalOcean. It works by delegating user authentication to the service that hosts the user account, and authorizing third-party applications to access the user account. OAuth 2 provides authorization flows for web and desktop applications, and mobile devices.

A big benefit of using it involves delegating the task of managing passwords securely to these companies (Facebook, Google, and so on).

## Why OAuth?

### 1.  Granular Access Levels

That means that when a user logs in with Facebook, Google, etc, you can request specific things from their Facebook, Google, etc, account, for example if for your app you only need their profile and email address then you can only request these info, however, if the app is similar to Tinder, then you can also request their list of friends so the app does not accidently match them with their friends.

### 2.  Read/Read+Write Access

In the case of Facebook for example, you can either ask them to just retrieve pieces of information about their Facebook account like their name, email, etc, or you can ask for write access as well, for example WordPress wanted to be able to post to Facebook on this user's account then they would need to ask for read and write access.

### 3.  Revoke Access

The third party you are using (OAuth 2.0) should be able to revoke access at any point on their website. That means if the user is authenticating with Facebook for example, the user should be able to go into their Facebook account and deauthorize the access that they granted to your website (Secrets website for example), and the user does not need to go to the Secrets page where the page may be less keen to give up this access for example.

## OAuth Steps

### First Step - Set Up The App

The first step is to actually tell the third party app (Facebook, Google, etc) about our web application because they don't know about us. We have to set up our app in their developer console and in return we get what is called an `APP ID`or a `Client ID` and our web application is then the client which will make their request to Facebook, etc, to authenticate our user.

### Second Step - Redirect to Authenticate

After setting up the app, the next step happens when the user tries to log on to our web application, so when the user hits up secrets.com and they want to authenticate, we give them an option to log in with Facebook, etc.

### Third Step - User Logs In

So once they click on that option then we will take them to the actual Facebook, etc, website so that they will see a familar interface, a trustworthy interface and they'll log into Facebook using their Facebook credentials. And without OAuthh what we would have to do is to ask the user, "Hey, what is your login credentials for Facebook? Can you give me your Facebook password?" **And nobody want to do that.** as that seems sketchy and insecure.

### Fourth Step - User Grants Permissions

Once the user logs in on this third party then they have to review the permissions that our website is asking for, for example our application may want the profile and email address and the user review that and if they ok with that they will grant that permission.

### Fifth Step - Receive Authorisation Code

After the user grantting permission and they have successfully logged in on Facebook then our web application will receive an authorization code from Facebook and this allows us to check, to make sure the user actually successfully signed on to Facebook (they had the right username and password).

### Sixth Step - Exchange AuthCode for Access Token

But if we want to go a step further, we can also exchange our **authentication code** for an **access token**. And when we receive that **access token** from Facebook we would save it into our database because this is the token that we can use if we want to request for pieces of information subsequently. This **access token** is valid for a lot longer than the **authentication token**.

The way to see it is that the **authentication code** or the **OAuth code** is kind of like a ticket, a ticket that you are going to use once to enter the cinema. But the **access token** is kind of more like a year pass and it comes with benefits like backstage access where you get to request pieces of data from Facebook including their friends list or that username or their password, whatever it may be that they granted you permission to access.

So the **OAuth code** is what we need to authenticate a user that they successfully managed to log in through Facebook, and the **access token** is what we'll use to access pieces of information that are stored on that user's account on these third parties websites (emails, friends list, etc).

## [Passport Strategy for Authenticating with Google Using the OAuth 2.0 API](http://www.passportjs.org/packages/passport-google-oauth20/)

Now lets go ahead and implement **login** with **Google** using a `passport` and `Google OAuth` into our web application.

### passport-google-oauth20 Installation

```js
$ npm install passport-google-oauth20
```

### passport-google-oauth20 Usage

#### passport-google-oauth20 Create an Application

Before using `passport-google-oauth20`, you must register an application with Google. If you have not already done so, a new project can be created in the [Google Developers Console](https://console.developers.google.com/). Your application will be issued a **client ID** and **client secret**, which need to be provided to the strategy. You will also need to configure a redirect URI which matches the route in your application.

##### Inside Google Console

**OAuth consent screen**

1.  Click on **Cloud Project**
2.  Click on **New Project**
3.  Name the project (example **Secret**)
4.  Click on **Credentials** to setup the credentials for **Google OAuth**
5.  Select **OAuth consent screen** to configure the screen that the user sees when they login through Google and grant the Secrets application access to their data
6.  Ignore the **project type (external or internal)**
7.  Type the app name in **App name** (Secrets) field
8.  Add your email to the **User support email** and **Developer contact information** fields
9.  Click **Save and Continue**

**Scopes**

Scopes are the fields that you will receive once the user logs in through Google (in this case, we are probably only interested in the **email** and **profile ID**).

1.  Click on **ADD OR REMOVE SCOPES**
2.  Select **.../auth/userinfo.email**, **.../auth/userinfo.profile** and **openid** and click on **UPUDATE**. These 3 scopes are the default ones without the user needing to see a **permissions page** because these 3 scopes are transmitted every time you authenticate with Google.
3.  Click on **SAVE AND CONTINUE**

**Test users**

1.  Just click on **SAVE AND CONTINUE**

**Summary**

1.  Review your chosen options and click on **BACK TO DASHBOARD**
2.  Click on **Credentials**
3.  Click on **+ CREATE CREDENTIALS** to create our **API Credentials** and choose **OAuth client ID**, and this is going to allow us to authenticate them using **Google**
4.  Choose **Web application** as the **Application type**
5.  Add the name of the app(Secrets) to the **name** field
6.  There are 2 other fields we have to fill in: **Authorised JavaScript origins** - where is that request to Google going to come from, and in this case it is going to come from our localhost - and **Authorised redirect URIs** - this is a route that we are going to plan out our server when Google has authenticated our user to return to, so that we can then locally authenticate them and save the session and cookies and all of that.
    6.1. Authorised JavaScript origins: Click on **+ ADD URI** and add `http://localhost:3000`, and this is obviously for when we are testing, and once the website is live we can come back here and change it anytime.
    6.2. Authorised redirect URIs: Click on **+ ADD URI** and add `http://localhost:3000/auth/google/secrets>`
7.  Click on **CREATE**
8.  Now we get an **OAuth client created** message with the **Client ID** and **Client Secret**. These are super important pieces of information and they will be stored in our `.env` (check out `.env`file) file for security reasons.

#### passport-google-oauth20 Configure Strategy

The Google authentication strategy authenticates users using a Google account and OAuth 2.0 tokens. The client ID and secret obtained when creating an application are supplied as options when creating the strategy. The strategy also requires a `verify` callback, which receives the access token and optional refresh token, as well as `profile` which contains the authenticated user's Google profile. The `verify` callback must call `cb` providing a user to complete authentication.

The first we need to do is to **require** the package `passport-google-oauth20` and use it as a `passport strategy`.

```js
var GoogleStrategy = require('passport-google-oauth20').Strategy;
```

And the next part is where we set up the `Google Strategy` and **configure** it using all of those details we received when we **created the passport-google-oauth20 application** such as the **Client ID** and **Client Secret** that we stored in our `.env` (check out `.env`file) file for security reasons, as well the **Authorised redirect URIs**.

```js
passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: "http://www.example.com/auth/google/callback"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
```

> :warning: **WARNING**</br></br>
>      There is just one more thing we need to [add](https://github.com/jaredhanson/passport-google-oauth2#readme) to this configuration because Google is sunsetting the **Google+ API (deprecated)** and all things related to Google+, previously this package relied on [Google+](https://github.com/jaredhanson/passport-google-oauth2/issues/50#issuecomment-449188012) to obtain user information so they got the user's Google+ profile and we need to [fix the deprecation of the Google+ API](https://github.com/jaredhanson/passport-google-oauth2/pull/51) by adding `userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'` to the **strategy options ((use the oauth userinfo endpoint instead of G+)**.
>     So now when we use `passport` to **authenticate** our users using **Google OAuth** we are no longer gonna be retrieving their profile information from their **Google+** account but instead we are going to retrieve it from their info which is simply another **endpoint** on Google.
>     It is very likely that at some point if the **Google+ API** deprecates then the code might not work and we are probably going to get some warnings down the line in the console telling something like: **"Google+ API deprecated. Fix it by doing this..."**
>     So now the code looks like the below:

#### passport-google-oauth20 Configure Strategy Code Example

```js
        passport.use(new GoogleStrategy({
            clientID: process.env.CLIENT_ID,
            clientSecret: process.env.CLIENT_SECRET,
            callbackURL: "http://localhost:3000/auth/google/secrets",
            userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
          },
          /*
          In this callback function is where Google sends back an access token (accessToken), which
          is the thing that allows us to get data related to that user which allows us to access the
          user's data for a longer period of time

          We also get their profile which is essentially what we are interested in because that is
          what will contain their email, Google ID, and anything else that we have access to
          */
          function(accessToken, refreshToken, profile, cb) {
            /*
            And finally we use the data that we get back, namely their Google ID to either find a
            user with that ID in our database of users or to create them if they don't exist

            _________________________________________________________________________________________

            User.findOrCreate is not actually a function, it is something that passport came up with
            as a pseudo code(fake code) and they are basically trying to tell you to implement some
            sort of functionality to find or create the user, and we can use [mongoose-findorcreate]
            (https://stackoverflow.com/a/41355218) to do it as this [Mongoose Plugin]
            (https://www.npmjs.com/package/mongoose-findorcreate) essentially allows us to make that
            pseudo code work as **Mongoose Plugin's** team created that function in
            the package and it does exactly what the pseudo code was supposed to do.

            We only need to install the `mongoose-findorcreate` package, require it, and add it as a
            plugin to our schema to make it work.

            Now the last step is to add it as a **plugin** to our **schema**

            Now the code should work and we should be able to tap into our **User model** and
            call the `findOrCreate` function that previously did not exist
            */
        User.findOrCreate({
          googleId: profile.id
        }, function(err, user) {
          return cb(err, user);
        });
      }
    ));
```

##### mongoose-findorcreate Installation

```js
npm install mongoose-findorcreate
```

##### mongoose-findorcreate Usage

```js
var findOrCreate = require('mongoose-findorcreate')
```

##### Now the last step is to add it as a **plugin** to our **schema**

```js
ClickSchema.plugin(findOrCreate);
```

#### passport-google-oauth20 Authenticate Requests

Use `passport.authenticate()`, specifying the `'google'` strategy, to authenticate requests.

For example, as route middleware in an **Express** application.

> :warning: **WARNING**</br></br>
>      In order to fix the `Cannot GET /auth/google/secrets` error message we get after trying to login/register to the **Secrets** page using **Google**, we need to add this route to be able to authenticate them `locally` on our website and to save their **login session** using **sessions** and **cookies**.

```js
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/');
  });
```

> :warning: **WARNING**</br></br>
>      Error: Failed to serialize user into session</br>
>      In order to fix the error above we need to replace our [serialize and deserialize](http://www.passportjs.org/docs/configure/) code to work for all **different strategies**, not just for the **local strategy**.</br>

```js
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
```

#### passport-google-oauth20 Authenticate Requests Code Example

```js
/*
GET request for the button the user clicks when trying to
login/register with Google (login.ejs - register.ejs)
*/
app.get('/auth/google',
  /*
  Use passport to authenticate our user using the strategy (google strategy)
  that we want to authenticate our user with
  */
  passport.authenticate('google', {
    /*
    Then we are saying when we hit up Google, we are goint to tell
    them that what we want is the user 's profile and this includes
    their email address as well as their user ID on Google which
    we will be able to use and identify them in the future. Once that's
    been successful, Google will redirect the user back to our website
    and make a GET request to "/auth/google/secrets" (next app.get... code below)
    and that is where will authenticate them locally and save their login session
    */
    scope: ["profile"]
    /*
    passport.authenticate('google', { scope: ['profile'] })
    should be enough to bring up a pop up that allows the user
    to sign into their Google account
    */
  }));

/*
This GET request gets made by Google when they try to redirect the user back
to our website and this string "/auth/google/callback" has to match what
we specified to Google previously
*/
app.get("/auth/google/secrets",
  /*
  authenticate the user locally and if there were any
  problems send them back to the login page again
  */
  passport.authenticate('google', {
    failureRedirect: "/login"
  }),
  function(req, res) {
    /*
    Successful authentication

    But if there are no problems then we can redirect them to the /secrets page
    or any other sort of privileged page we may have
    */
    res.redirect("/secrets");
  });
```

At the moment when we get the data back from **Google**, we not only log their profile but we also try to find it in our database or create them on our database and that is all based off a field called googleId, which is supposed to exist in our mongoDB users collection but at the moment our users collection only have two fields (`email` and `password`) from when we were logging users only through the local authentication methods.
So we need to add a new field (`googleId`) to our users collection and now the user registers on our website we are going to find and see if we already have a record of their **GoogleID** in **user** mongoDB database in which case we are going to **save** all the new data associated with that **ID**, or otherwise we are going to **create** it in our database and **save** this information for future

Because we are authenticating the users using their Google we only get what is equivalent to their user name on the Google user database, we don't get their password and this is great because it means we don't have to save and take care of it, and if it gets lost or it gets **leaked** that is all on Google and they have a lot more engineers and resources to keep their users' passwords or whatever other pieces of information safe, and all we need to do is just to retrieve it when we need it (`googleId`).

* * *

# Letting Users Submit Secrets

## secrets.ejs

```html
<!--
add the secrets we get from our DB from the code in the
app.get("/secrets"...) code (usersWithSecrets)

loop through the userWithSecrets variable/array, and the callback
function will pick up all of the users inside the usersWithSecrets array
and for each of these users we are going to render the value of the
user.secret field inside a paragraph element
-->
<% usersWithSecrets.forEach(function(user){ %>
      <p class="secret-text"><%= user.secret %></p>
<% }) %>
```

## Amend Secrets GET Route

```js
//Target the secrets route to render the secrets page
app.get("/secrets", function(req, res) {

  /*
  secrets will no longer be a privileged page, anybody logged in or
  not logged in will now be able to see the secrets that have been
  submitted anonymously by the users of the page, so we are only going
  to trawl through mongoDB and find all the secrets that have been
  submitted on the mongoDB, we are going to use our model of Users (User)
  and use find and look through the collection users and find all
  ({$ne: null})the places where the secret field actually has a value stored
  */
  User.find({
    "secret": {
      $ne: null
    }
  }, function(err, foundUsers) {
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", {
          usersWithSecrets: foundUsers
        });
      }
    }
  });
});
```

## Create Submit GET Route

```js
//Target the submit route
app.get("/submit", function(req, res) {
  //Check to see if the user is logged in, then render the submit page
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});
```

## Create Submit POST Route

```js
//POST request (submit route) to submit a secret
app.post("/submit", function(req, res) {
  //Save the secret the user typed in the form
  const submittedSecret = req.body.secret;

  /*
  Find the current user in the DB and save the secret into their file
  Passport saves the users details because when we initiate a new login session
  it will save that user's details into the request (req) variable
  test it by console.log(req.user); to output the current logged in
  user (id and username) into the terminal
  */
  console.log(req.user);

  //Add the secret the user submitted to the secret field created in the schema
  User.findById(req.user.id, function(err, foundUser) {
    if (err) {
      console.log(err);
    } else {

      if (foundUser) {
        /*
        If the (foundUser) user exists then we are going to set the foundUser's secret
        field to equals the submittedSecret (variable value)
        */
        foundUser.secret = submittedSecret;
        /*
        Save the foundUser with their newly updated secret
        */
        foundUser.save(function() {
          res.redirect("/secrets");
        });
      }
    }
  });
});
```

## Amend mongoose userSchema

```js
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});
```

* * *
