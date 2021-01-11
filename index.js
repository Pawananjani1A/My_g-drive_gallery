const fs = require('fs');
const readline = require('readline');
const { google } = require('googleapis');
const express = require('express');
const ejs = require('ejs');
const cors = require('cors');
const dotenv = require('dotenv');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const methodOverride = require('method-override');
const credentials = require('./credentials3_NITP.json');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const multer = require('multer');
const async = require('async');

var name, pic, email;

const app = express();

app.set('view engine', 'ejs');

var authed = false;

dotenv.config({ path: './config/config.env' });
const TOKEN_PATH = 'token.json';

var client_secret = credentials.web.client_secret;
var client_id = credentials.web.client_id;
var redirect_uris = credentials.web.redirect_uris[0];
const oAuth2Client = new google.auth.OAuth2(client_id, client_secret, redirect_uris);
const SCOPES = "https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/userinfo.profile";








// create application/x-www-form-urlencoded parser
var urlencodedParser = bodyParser.urlencoded({ extended: true })

app.use(express.static("public"));

app.use(urlencodedParser);

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

// app.use(passport.initialize());
// app.use(passport.session());

var Storage = multer.diskStorage({
    destination: function(req, file, callback) {
        callback(null, "./uploadedImages");
    },
    filename: function(req, file, callback) {
        callback(null, file.fieldname + "_" + Date.now() + "_" + file.originalname);
    },
});

var My_Images = '1hyyibn8SOArYxLNcEn-8tsA8quABrd12';
var Shared_Images = '1S3pH8WuQPW3tj0-mbqV3XiggukrhnmfN';
var bin = '1Iy4-KZOpJ5iBmFG1CSNJUJpEm0vXNC84';
var hidden = '1Ag2aPQeWVrMgSMRCzt5fn6vaEvaK2qJ1';
var archived = '1sWgt6hb0sdwM9Ugpjre3YauYLpOq2m2w';

var upload = multer({
    storage: Storage,
}).single("file"); //Field name and max count

// use static serialize and deserialize of model for passport session support
// passport.serializeUser(function (user, done) {
//     done(null, user);
// });

// passport.deserializeUser(function (user, done) {
//     done(null,user)
// });


// passport.use(new GoogleStrategy({
//     clientID: process.env.CLIENT_ID,
//     clientSecret: process.env.CLIENT_SECRET,
//     callbackURL: "http://localhost:3000/auth/google/callback",
//     userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
// },
//     function (accessToken, refreshToken, profile, cb) {
//         // console.log(profile);
//         // User.findOrCreate({ googleId: profile.id }, function (err, user) {
//         //     return cb(err, user);
//         // });
//         let userAccessToken = accessToken;
//         let userRefreshToken = refreshToken;
//         userProfile = profile;
//         return cb(null,userProfile);
//     }
// ));

app.get("/", (req, res) => {

    if (!authed) {
        // fs.readFile('credentials.json', (err, content) => {
        //     if (err) {
        //         console.log('Error loading client secret file:', err);

        //     }
        //     else
        //     {
        //         oAuth2Client.setCredentials(token);
        //     }
        //     // Authorize a client with credentials, then call the Google Drive API.
        //     authorize(JSON.parse(content), listFiles);
        //     //authorize(JSON.parse(content), getFile);
        //     // console.log(JSON.parse(content));
        //     // authorize(JSON.parse(content), uploadFile);
        // });

        const authUrl = oAuth2Client.generateAuthUrl({
            access_type: 'offline',
            scope: SCOPES,
        });

        // console.log(authUrl);
        res.render('signIn', { authUrl: authUrl });

    } else {
        var oauth2 = google.oauth2({
            auth: oAuth2Client,
            version: "v2",
        });
        oauth2.userinfo.get(function(err, response) {
            if (err) {
                console.log(err);
            } else {
                // console.log(response.data);
                name = response.data.name;
                pic = response.data.picture;
                email = response.data.email;
                res.render("upload", {
                    name: response.data.name,
                    pic: response.data.picture,
                    success: false
                });
            }
        });
    }

});

// app.get('/auth/google',
//     passport.authenticate('google', { 
//         scope: ['profile','email'],
//         accessType: 'offline'
//      }));
var TOKEN;
app.get('/google/callback', function(req, res) {
    // passport.authenticate('google', { failureRedirect: '/signIn' }),
    // function (req, res) {
    //     // Successful authentication, redirect secrets.
    //     res.redirect('/upload');

    const code = req.query.code;
    if (code) {
        // Get an access token based on our OAuth code
        oAuth2Client.getToken(code, function(err, tokens) {
            if (err) {
                console.log("Error authenticating");
                console.log(err);
            } else {
                console.log("Successfully authenticated");
                // console.log(tokens)
                TOKEN = tokens;
                oAuth2Client.setCredentials(tokens);
                authed = true;
                res.redirect('/upload');
            }
        });


    } else {
        console.log("Error retrieving code");
        res.redirect('/error');
    }
});