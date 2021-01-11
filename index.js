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
var redirect_uris = credentials.web.redirect_uris[2];
const oAuth2Client = new google.auth.OAuth2(client_id, client_secret, redirect_uris);
const SCOPES = "https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/userinfo.profile";



//////////////////////////////////////////////API DOCS/////////////////////////////////////////////

function authorize(credentials, callback) {
    var client_secret = credentials.web.client_secret;
    var client_id = credentials.web.client_id;
    var redirect_uris = credentials.web.redirect_uris[0];
    const oAuth2Client = new google.auth.OAuth2(client_id, client_secret, redirect_uris);

    // Check if we have previously stored a token.
    fs.readFile(TOKEN_PATH, (err, token) => {
        if (err) {
            console.log("Error Reading Token : ", err);
            return false;
        }
        oAuth2Client.setCredentials(JSON.parse(token));
        callback(oAuth2Client); //list files and upload file
        //callback(oAuth2Client, '0B79LZPgLDaqESF9HV2V3YzYySkE');//get file
        return true;
    });

}

var MyImages = [];
var ArchivedImages = [];
var HiddenImages = [];
var DeletedImages = [];

function listFiles(auth, folderId, flag) {
    const drive = google.drive({ version: 'v3', auth });
    getList(drive, '', folderId, flag);

}

async function getList(drive, pageToken, folderId, flag) {
    await drive.files.list({
        corpora: 'user',
        pageSize: 10,
        q: `'${folderId}' in parents and trashed=false`,
        pageToken: pageToken ? pageToken : '',
        fields: 'nextPageToken, files(*)',
    }, (err, res) => {
        if (err) return console.log('The API returned an error: ' + err);
        const files = res.data.files;
        if (files.length) {
            // console.log('Files:');
            processList(files, flag);
            if (res.data.nextPageToken) {
                getList(drive, res.data.nextPageToken, folderId, flag);
            }

            files.map((file) => {
                // console.log(`${file.name} (${file.id})`);
            });
        } else {
            console.log('No files found.');
        }
    });
}

function processList(files, flag) {
    // console.log('Processing....');
    let mySet = new Set();
    files.forEach(file => {
        mySet.add(file);
        // console.log(file.name + '|' + file.size + '|' + file.createdTime + '|' + file.modifiedTime);
        // console.log(file);
    });
    // console.log("Should Be empty : ",storage);
    // console.log(flag);
    if (flag == "MI") MyImages = Array.from(mySet);
    else if (flag == "AI") ArchivedImages = Array.from(mySet);
    else if (flag == "HI") HiddenImages = Array.from(mySet);
    else if (flag == "DI") DeletedImages = Array.from(mySet);
    // console.log("Should have appropriate content : ",storage);
}

function moveFileToNewFolder(fileId, newFolderId, auth) {
    const drive = google.drive({ version: 'v3', auth });
    try {
        // Retrieve the existing parents to remove

        drive.files.get({
            fileId: fileId,
            fields: 'parents'
        }, function(err, file) {
            if (err) {
                // Handle error
                console.log("File Not found ", err);
            } else {
                // Move the file to the new folder
                //   console.log("File : ",file);
                var previousParents = file.data.parents.join(',');
                drive.files.update({
                    fileId: fileId,
                    addParents: newFolderId,
                    removeParents: previousParents,
                    fields: 'id, parents'
                }, function(err, file) {
                    if (err) {
                        // Handle error
                        console.log(`Couldn't Move file ${file.id} to the new folder : `, err);
                    } else {
                        // File moved.
                        // console.log(`File ${file.id} Moved to new folder ${newFolderId}`);

                    }
                });
            }
        });
    } catch (err) {
        console.log("Error in moving files : ", err);
    } finally {
        //Do nothing
    }

}
//////////////////////////////////////////////////////////////////API DOCS////////////////////////////////////





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
                // console.log("Successfully authenticated");
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

app.get('/fileList', (req, res) => {
    if (authed) {
        if (MyImages) {
            // console.log(MyImages);
            res.render('fileList', { name: name, pic: pic, files: MyImages, success: true })
        } else res.render('fileList', { name: name, pic: pic, files: MyImages, success: false })
    } else {
        res.redirect('/');
    }
});




app.get('/upload', (req, res) => {
    if (req.isAuthenticated()) {
        //  console.log(userProfile);
        res.render('upload', { name: name, pic: pic, success: false });
    } else {
        res.redirect('/');
    }
});



app.post('/fileList', (req, res) => {

    if (authed) {
        if (TOKEN) {

            oAuth2Client.setCredentials(TOKEN);

            listFiles(oAuth2Client, My_Images, flag = "MI");
            // console.log(MyImages);
            res.redirect('/fileList');
        } else res.redirect('/');
    } else {
        res.redirect('/');
    }
});



app.post('/upload', (req, res) => {
    if (authed) {

        // console.log(req.user);
        upload(req, res, function(err) {
            if (err) {
                console.log(err);
                res.redirect('/error');
            } else {
                // console.log("File Path : ",req.file.path);
                const ftype = req.file.mimetype;
                if (ftype == 'image/jpeg' || ftype == 'image/png' || ftype == 'image/gif') {
                    const drive = google.drive({ version: "v3", auth: oAuth2Client });
                    const fileMetadata = {
                        'name': req.file.filename,
                        'parents': ['1hyyibn8SOArYxLNcEn-8tsA8quABrd12'],
                        'appProperties': {
                            'hidden': false,
                            'archived': false,
                            'bin': false,
                            'myImages': true,
                            'origin': email
                        }
                    };
                    const media = {
                        mimeType: req.file.mimetype,
                        body: fs.createReadStream(req.file.path),
                    };
                    drive.files.create({
                            resource: fileMetadata,
                            media: media,
                            fields: "id",
                        },
                        (err, file) => {
                            if (err) {
                                // Handle error
                                console.error(err);
                            } else {
                                fs.unlinkSync(req.file.path)
                                    // console.log(req.user);
                                res.render("upload", { name: name, pic: pic, success: true })
                            }
                        });
                } else {
                    console.log("User Didn't select an image file");
                    res.redirect("/error");
                }
            }


        });
    } else { res.redirect('/'); }

});


app.get('/archived', (req, res) => {

    if (authed) {
        if (TOKEN) {
            oAuth2Client.setCredentials(TOKEN);
            listFiles(oAuth2Client, archived, flag = "AI");
            if (ArchivedImages) {

                res.render('archived', { files: ArchivedImages, success: true });
                // console.log(ArchivedImages);
            } else res.render('archived', { files: ArchivedImages, success: false });
        } else {
            res.redirect('/');
        }
    } else {
        res.redirect('/');
    }
});
app.get('/hidden', (req, res) => {

    if (authed) {
        if (TOKEN) {
            oAuth2Client.setCredentials(TOKEN);
            listFiles(oAuth2Client, bin, flag = "HI");
            if (HiddenImages) {

                res.render('hidden', { files: HiddenImages, success: true });
                // console.log(HiddenImages);
            } else res.render('hidden', { files: HiddenImages, success: false });
        } else {
            res.redirect('/');
        }
    } else {
        res.redirect('/');
    }
});

app.get('/deleted', (req, res) => {

    if (authed) {
        if (TOKEN) {
            oAuth2Client.setCredentials(TOKEN);
            listFiles(oAuth2Client, bin, flag = "DI");
            if (DeletedImages) {

                res.render('deleted', { files: DeletedImages, success: true });
                // console.log(DeletedImages);
            } else res.render('deleted', { files: DeletedImages, success: false });
        } else {
            res.redirect('/');
        }
    } else {
        res.redirect('/');
    }
});



app.post('/file/archive/:id', (req, res) => {

    if (authed) {
        if (TOKEN) {
            var fileId = req.params.id;
            oAuth2Client.setCredentials(TOKEN);
            moveFileToNewFolder(fileId, archived, oAuth2Client);
            listFiles(oAuth2Client, archived, flag = "AI");
            if (ArchivedImages) {

                res.render('archived', { files: ArchivedImages, success: true });
                // console.log(ArchivedImages);
            } else res.render('archived', { files: ArchivedImages, success: false });
        } else {
            res.redirect('/');
        }
    } else {
        res.redirect('/');
    }
});

app.post('/file/hide/:id', (req, res) => {
    if (authed) {
        if (TOKEN) {
            var fileId = req.params.id;
            oAuth2Client.setCredentials(TOKEN);
            moveFileToNewFolder(fileId, hidden, oAuth2Client);
            listFiles(oAuth2Client, hidden, flag = "HI");
            if (HiddenImages) {

                res.render('hidden', { files: HiddenImages, success: true });
                // console.log(HiddenImages);
            } else res.render('hidden', { files: HiddenImages, success: false });
        } else {
            res.redirect('/');
        }
    } else {
        res.redirect('/');
    }
});

app.post('/file/delete/:id', (req, res) => {
    if (authed) {
        if (TOKEN) {
            var fileId = req.params.id;
            oAuth2Client.setCredentials(TOKEN);
            moveFileToNewFolder(fileId, bin, oAuth2Client);
            listFiles(oAuth2Client, bin, flag = "DI");
            if (DeletedImages) {

                res.render('deleted', { files: DeletedImages, success: true });
                // console.log(DeletedImages);
            } else res.render('deleted', { files: DeletedImages, success: false });
        } else {
            res.redirect('/');
        }
    } else {
        res.redirect('/');
    }
});

app.get('/logout', (req, res) => {
    authed = false;
    TOKEN = null;
    MyImages = [];
    ArchivedImages = [];
    DeletedImages = [];
    HiddenImages = [];
    res.redirect('/');
});

app.get('/error', (req, res) => {
    res.render('error');
});


// Logging
if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'));
}

const PORT = process.env.PORT;
app.listen(
    PORT,
    console.log(`Server is running in ${process.env.NODE_ENV} mode on port ${PORT}`)
);