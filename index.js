const fs = require('fs');
const { google } = require('googleapis');
const express = require('express');
const dotenv = require('dotenv');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const credentials = require('./credentials3_NITP.json');
const credentials2 = require('./credentials4_NITP.json');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const cookieParser = require('cookie-parser');
const passport = require('passport');

require("./passport");

dotenv.config({ path: "./config/config.env" });
const app = express();

const TOKEN_PATH = 'token_NITP.json';

app.set('view engine', 'ejs');



var client_secret = credentials2.web.client_secret;
var client_id = credentials2.web.client_id;
var redirect_uris = credentials2.web.redirect_uris[2];
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
            'origin': auth
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

function getToken() {
    fs.readFile(TOKEN_PATH, (err, token) => {
        if (err) return -1;

        // callback(oAuth2Client);//list files and upload file
        // //callback(oAuth2Client, '0B79LZPgLDaqESF9HV2V3YzYySkE');//get file
        // console.log(JSON.parse(token));
        oAuth2Client.setCredentials(JSON.parse(token));
        return 1;

    });

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
    secret: "how_can You Change the COOKKEE",
    resave: false,
    saveUninitialized: true,
    // cookie: {
    //     expires: new Date(Date.now() + 900000),
    //     maxAge: 900000
    // },

}));

// Auth middleware that checks if the user is logged in
const isLoggedIn = (req, res, next) => {
    if (req.user) {
        next();
    } else {
        res.sendStatus(401);
    }
}

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());






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

    if (req.user) {
        res.redirect("/upload");
    } else {
        const authUrl = getAuthUrl();
        res.render('signIn');
    }

});




app.get('/google',
    passport.authenticate('google', {
        scope: SCOPES,
        accessType: 'offline'
    }));



// 
app.get('/google/callback', passport.authenticate('google', { failureRedirect: '/error' }), (req, res) => {


    res.redirect("/upload");
});



app.get('/fileList', (req, res) => {


    if (req.isAuthenticated()) {
        if (MyImages) {
            // console.log(MyImages);
            res.render('fileList', { name: req.user.displayName, pic: req.user.photos[0], files: MyImages, success: true })
        } else res.render('fileList', { name: req.user.displayName, pic: req.user.photos[0], files: MyImages, success: false })
    } else {
        res.redirect('/');
    }
});




app.get('/upload', (req, res) => {
    console.log(req.isAuthenticated());
    if (req.user) {
        //  console.log(userProfile);
        res.render('upload', { name: req.user.displayName, pic: req.user.photos[0], success: true });
    } else {
        res.redirect('/error');
    }
});



app.post('/fileList', (req, res) => {
    var TOKEN = getToken();
    if (req.isAuthenticated()) {
        if (TOKEN !== -1 || !TOKEN) {

            // oAuth2Client.setCredentials(TOKEN);

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
    if (req.isAuthenticated()) {
        var TOKEN = getToken();
        console.log(TOKEN);
        if (TOKEN !== -1 || !TOKEN) {
            upload(req, res, async function(err) {
                if (err) {
                    console.log("Multer caused some error", err);
                    res.redirect('/error');
                } else {
                    // console.log("File Path : ",req.file.path);



                    const filesArray = req.files;
                    // console.log(filesArray);
                    filesArray.sort(compareSize);



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
                    res.render("upload", { name: req.user.displayName, pic: req.user.photos[0], success: true });

                }


            });
        }
    }
    // console.log(req.user);
    else { res.redirect('/'); }

});


app.get('/archived', (req, res) => {

    if (req.isAuthenticated()) {
        var TOKEN = getToken();
        if (TOKEN !== -1 || !TOKEN) {
            // console.log(req);

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

    if (req.isAuthenticated()) {
        var TOKEN = getToken();
        if (TOKEN !== -1 || !TOKEN) {

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

    if (req.isAuthenticated()) {
        var TOKEN = getToken();
        if (TOKEN !== -1 || !TOKEN) {

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

    if (req.isAuthenticated()) {
        var TOKEN = getToken();
        if (TOKEN !== -1 || !TOKEN) {
            var fileId = req.params.id;

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
    if (req.isAuthenticated()) {
        var TOKEN = getToken();
        if (TOKEN !== -1 || !TOKEN) {
            var fileId = req.params.id;

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
    if (req.isAuthenticated()) {
        var TOKEN = getToken();
        if (TOKEN !== -1 || !TOKEN) {
            var fileId = req.params.id;

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
    // console.log(req.session);
    TOKEN = null;
    MyImages = [];
    ArchivedImages = [];
    DeletedImages = [];
    HiddenImages = [];
    req.session = null;
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