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
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const localStrategy = require('passport-local');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo')(session);
const User = require("./sessionDB/user");


dotenv.config({ path: "./config/config.env" });
const app = express();

app.set('view engine', 'ejs');

const connectDB = async() => {
    try {
        const conn = await mongoose.connect(process.env.MONGO_URI, {
            useNewUrlParser: true,
            useFindAndModify: false,
            useUnifiedTopology: true,
            useCreateIndex: true
        });

        console.log(`MongoDB Connected: ${conn.connection.host}`);

    } catch (err) {
        console.log("DB CONNECTION FAILED ", err);
        process.exit(1);
    }
};

connectDB();





var authed = false;



// var my_redirect_uris = ["http://localhost:3000/google/callback", "http://localhost:5000/google/callback", "https://aqueous-thicket-67471.herokuapp.com/google/callback"];
var client_secret = credentials.web.client_secret;
var client_id = credentials.web.client_id;
var redirect_uris = credentials.web.redirect_uris[2];
const oAuth2Client = new google.auth.OAuth2(client_id, client_secret, redirect_uris);
const SCOPES = "https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/userinfo.profile";



//////////////////////////////////////////////API DOCS/////////////////////////////////////////////


function getAuthUrl() {
    return oAuth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: SCOPES,
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


function getUser(Client) {
    var oauth2 = google.oauth2({
        auth: Client,
        version: "v2",
    });

    oauth2.userinfo.get(function(err, response) {
        if (err) {
            console.log("Error while retriving userinfo", err);
            return -1;
        } else {
            // console.log(response.data); //id,name
            return response.data;

        }
    });


}

function findUserInDB(currUser) {
    if (mongoose.connection !== undefined) {
        User.findOrCreate({ googleId: currUser.googleId, displayName: currUser.displayName }, function(err, user) {
            if (err) return -1;
            else return user;
        });
    } else {
        return -1;
    }
}

/////////////////////////////////////////////////////////////API DOCS////////////////////////////////////





// create application/x-www-form-urlencoded parser
var urlencodedParser = bodyParser.urlencoded({ extended: true })

app.use(express.static("public"));

app.use(urlencodedParser);


app.use(cookieParser());

// Logging
// if (process.env.NODE_ENV === 'production') {
//     mySession.cookie.secure = true;
// }
app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: true,
    // cookie: {
    //     expires: new Date(Date.now() + 900000),
    //     maxAge: 900000
    // },
    store: mongoose.connection ? new MongoStore({ mongooseConnection: mongoose.connection }) : null
}));

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());


passport.use(User.createStrategy());
/*,
    async(accessToken, refreshToken, profile, done) => {
        //    console.log(profile);

        const newUser = {
            googleId: profile.id,
            displayName: profile.displayName,
            firstName: profile.name.givenName,
            lastName: profile.name.familyName,
            image: profile.photos[0].value
        };

        try {
            let user = await User.findOne({ googleId: profile.id });

            // The user already has an account
            if (user) {
                done(null, user);
            }
            // New user
            else {
                user = await User.create(newUser);
                done(null, user);
            }
        } catch (err) {
            console.log(err);
        }
    }
));
*/

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// Set global variable
app.use(function(req, res, next) {
    res.locals.currentUser = req.user;
    next();
});






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




app.get("/", (req, res) => {

    if (req.isAuthenticated()) {
        res.redirect("/upload");
    } else {
        const authUrl = getAuthUrl();
        res.render('signIn', { authUrl: authUrl });
    }

});




// app.get('/google',
//     passport.authenticate('google', {
//         scope: SCOPES,
//         accessType: 'offline'
//     }));


var TOKEN;
// passport.authenticate('google', { failureRedirect: '/error' }),
app.get('/google/callback', function(req, res) {

    // console.log(req);
    const code = req.query.code;
    if (code) {
        // Get an access token based on our OAuth code
        oAuth2Client.getToken(code, function(err, tokens) {
            if (err) {
                console.log("Error authenticating");
                console.log(err);
                res.redirect('/error');
            } else {
                // console.log("Successfully authenticated");
                // console.log(tokens)
                TOKEN = tokens;
                oAuth2Client.setCredentials(tokens);

                user = getUser(oAuth2Client);
                if (user === -1) {
                    console.log("Error Authenticating user");
                    res.redirect("/error");
                } else {
                    const CurrUser = new User({
                        googleId: user.id,
                        displayName: user.name,
                    });

                    resultUser = findUserInDB(CurrUser);
                    if (resultUser === -1) {
                        console.log("Error finding or Creating user in DB");
                        res.redirect("/error");
                    } else {
                        req.login(resultUser, function(err) {
                            if (err) {
                                console.log("Error logging the user in", err);
                                res.redirect("/error");
                            } else {
                                passport.authenticate("local")(req, res, function() {
                                    console.log(req.user);
                                    authed = true;
                                    res.redirect("/upload");
                                });
                            }
                        });
                    }

                }

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
    console.log(req.isAuthenticated());
    if (authed) {
        //  console.log(userProfile);
        res.render('upload', { name: req.user.displayName });
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

    authed = false;
    TOKEN = null;
    MyImages = [];
    ArchivedImages = [];
    DeletedImages = [];
    HiddenImages = [];
    req.logout();
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
app.listen(PORT, () => {
    console.log(`Server is running in ${process.env.NODE_ENV} mode on port ${PORT} at ${new Date().toISOString()}`);
});