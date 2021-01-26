const fs = require('fs');
const { google } = require('googleapis');
const express = require('express');
const dotenv = require('dotenv');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const credentials = require('./credentials3_NITP.json');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const cookieParser = require('cookie-parser');
// const redis = require('redis');
// const redisStore = require('connect-redis')(session);
// const client = redis.createClient();


var name, pic, email;

const app = express();

app.set('view engine', 'ejs');

var authed = false;

dotenv.config({ path: './config/config.env' });

// var my_redirect_uris = ["http://localhost:3000/google/callback", "http://localhost:5000/google/callback", "https://aqueous-thicket-67471.herokuapp.com/google/callback"];
var client_secret = credentials.web.client_secret;
var client_id = credentials.web.client_id;
var redirect_uris = credentials.web.redirect_uris[0];
// var client_id = process.env.CLIENT_ID;
// var client_secret = process.env.CLIENT_SECRET;
// var redirect_uris = my_redirect_uris[0];
const oAuth2Client = new google.auth.OAuth2(client_id, client_secret, redirect_uris);
const SCOPES = "https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/userinfo.profile";



//////////////////////////////////////////////API DOCS/////////////////////////////////////////////

/*
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
*/

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

            files.map(() => {
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



function uploadAfileToSomeFolder(fileName, filePath, folderId, auth) {
    const drive = google.drive({ version: "v3", auth: auth });
    const fileMetadata = {
        'name': fileName,
        'parents': [folderId],
        'appProperties': {
            'hidden': false,
            'archived': false,
            'bin': false,
            'myImages': true,
            'origin': email
        }
    };
    const media = {
        mimeType: "image/jpeg",
        body: fs.createReadStream(filePath),
    };
    drive.files.create({
            resource: fileMetadata,
            media: media,
            fields: "id",
        },
        (err) => {
            if (err) {
                // Handle error
                console.error("Error in uploading to drive", err);
            } else {
                // fs.unlinkSync(filePath); //This has already been done in the upload.post route
                // console.log("Successfully uploaded : ", file);

            }
        });
}
//////////////////////////////////////////////////////////////////API DOCS////////////////////////////////////





// create application/x-www-form-urlencoded parser
var urlencodedParser = bodyParser.urlencoded({ extended: true })

app.use(express.static("public"));

app.use(urlencodedParser);

//15 minutes
var maxTime = 900000;
app.use(cookieParser());
var mySession = {
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false,
    // store: new redisStore({ host: 'localhost', port: 3000, client: client, ttl: 260 }),
    cookie: {
        expires: new Date(Date.now() + maxTime),
        maxAge: maxTime
    }
}

// Logging
if (process.env.NODE_ENV === 'production') {
    mySession.cookie.secure = true;
}
app.use(session(mySession));



// app.use(passport.initialize());
// app.use(passport.session());

var Storage = multer.diskStorage({
    // destination: function(req, file, callback) {
    //     callback(null, "./uploadedImages");
    // },
    filename: function(req, file, callback) {
        callback(null, file.fieldname + "_" + Date.now() + "_" + file.originalname);
    },
});

var My_Images = '1hyyibn8SOArYxLNcEn-8tsA8quABrd12';
var bin = '1Iy4-KZOpJ5iBmFG1CSNJUJpEm0vXNC84';
var hidden = '1Ag2aPQeWVrMgSMRCzt5fn6vaEvaK2qJ1';
var archived = '1sWgt6hb0sdwM9Ugpjre3YauYLpOq2m2w';

var upload = multer({
    storage: Storage,
    limits: {
        fileSize: 100000000
    },
    fileFilter: function(req, file, cb) {
        checkFileType(file, cb);
    }
}).array("files", 51); //Field name and max count

// Check File Type
function checkFileType(file, cb) {
    // Allowed ext
    // console.log(file);
    const filetypes = /jpeg|jpg|png|gif/;
    // Check ext
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    // Check mime
    const mimetype = filetypes.test(file.mimetype);

    if (mimetype && extname) {
        return cb(null, true);
    } else {
        cb('Error: Images Only!');
    }
}

// use static serialize and deserialize of model for passport session support
// passport.serializeUser(function(user, done) {
//     done(null, user);
// });

// passport.deserializeUser(function(user, done) {
//     done(null, user)
// });


var user = null;

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
                console.log("Error while retriving userinfo", err);
            } else {
                // console.log(response);
                // console.log("oauth2 : ", oauth2);
                // console.log("oAuth2Client : ", oAuth2Client);
                // name = response.data.name;
                // pic = response.data.picture;
                // email = response.data.email;
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
    console.log(req);
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
                var oauth2 = google.oauth2({
                    auth: oAuth2Client,
                    version: "v2",
                });
                oauth2.userinfo.get(function(err, response) {
                    if (err) {
                        console.log("Error while retriving userinfo", err);
                    } else {
                        // console.log(response);
                        // console.log("oauth2 : ", oauth2);
                        // console.log("oAuth2Client : ", oAuth2Client);
                        name = response.data.name;
                        pic = response.data.picture;
                        email = response.data.email;
                        // console.log(req);

                    }
                });
                authed = true;
                res.redirect('/upload');
            }
        });


    } else {
        console.log("Error retrieving code");
        res.redirect('/error');
    }
});

// passport.use(new GoogleStrategy({
//         clientID: oAuth2Client._clientId,
//         clientSecret: oAuth2Client._clientSecret,
//         callbackURL: oAuth2Client.redirectUri,
//         userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
//     },
//     function(accessToken, refreshToken, profile, cb) {
//         // console.log(profile);
//         // User.findOrCreate({ googleId: profile.id }, function (err, user) {
//         //     return cb(err, user);
//         // });
//         // let userAccessToken = accessToken;
//         // let userRefreshToken = refreshToken;
//         userProfile = profile;
//         return cb(null, userProfile);
//     }
// ));

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
    if (authed) {
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

//Size comparision for SJF implementation while upload
function compareSize(fileA, fileB) {
    return fileA.size - fileB.size;
}

app.post('/upload', (req, res) => {
    if (authed) {

        if (TOKEN) {
            upload(req, res, async function(err) {
                if (err) {
                    console.log("Multer caused some error", err);
                    res.redirect('/error');
                } else {
                    // console.log("File Path : ",req.file.path);
                    oAuth2Client.setCredentials(TOKEN);


                    const filesArray = req.files;
                    // console.log(filesArray);
                    filesArray.sort(compareSize);

                    // for (var i = 0; i < filesArray.length; i++) {
                    //     var fileName = filesArray[i].filename;

                    //     await Sharp(filesArray[i].path)
                    //         .resize(720, 480)
                    //         .toFile("optimizedImages/" + fileName, function(err) {
                    //             console.log("Error in optimizing image ", err);
                    //         });

                    // }

                    for (var i = 0; i < filesArray.length; i++) {
                        var fileName = filesArray[i].filename;

                        var filePath = filesArray[i].path;
                        await uploadAfileToSomeFolder(fileName, filePath, My_Images, oAuth2Client);
                        4
                        try {
                            fs.unlinkSync(filesArray[i].path);
                            //file removed
                            // console.log("FileRemoved from uploadedImages Folder");
                        } catch (err) {
                            console.error("Error in removing file from uploadedImagesFolder", err);
                        }
                    }
                    res.render("upload", { name: name, pic: pic, success: true });
                    // if (ftype == 'image/jpeg' || ftype == 'image/png' || ftype == 'image/gif') {
                    //     uploadAfileToSomeFolder(req, My_Images, oAuth2Client);
                    //     res.render("upload", { name: name, pic: pic, success: true });
                    // } else {
                    //     console.log("User Didn't select an image file");
                    //     res.redirect("/error");
                    // }
                    // res.redirect('/');
                }


            });
        }
    }
    // console.log(req.user);
    else { res.redirect('/'); }

});


app.get('/archived', (req, res) => {

    if (authed) {
        if (TOKEN) {
            // console.log(req);
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
    // console.log(req);
    // console.log(user);
    // console.log("Session : ", req.session);
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

const PORT = process.env.PORT || 3000;
app.listen(
    PORT,
    console.log(`Server is running in ${process.env.NODE_ENV} mode on port ${PORT}`)
);