const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const keys = require('./config/keys');
const User = require('./models/User');
const {ObjectId} = require("mongodb");
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const port = 4000;

const app = express();
app.use('/public', express.static('public'));
const upload = multer({ dest: 'uploads/' });

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

//db connection
mongoose.set('strictQuery', false);
mongoose.connect(keys.mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });
const db = mongoose.connection;

db.on('connected', function() {
    console.log('Mongoose connected to ' + keys.mongoURI);
});

db.on('error', function(err) {
    console.log('Mongoose connection error: ' + err);
});

db.on('disconnected', function() {
    console.log('Mongoose disconnected');
});

process.on('SIGINT', function() {
    db.close(function() {
        console.log('Mongoose disconnected through app termination');
        process.exit(0);
    });
});




app.post("/register", async (req, res) => {
    try {
        // Check if email is already in use
        const existingUser = await User.findOne({
            $or: [{ username: req.body.username }, { email: req.body.email }],
        });
        if (existingUser) {
            return res.status(400).json({
                msg: "A user with that email or username already exists.",
            });
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(req.body.password, salt);

        // Create a new user
        const newUser = new User({
            _id: new ObjectId(),
            name: req.body.name,
            username: req.body.username,
            email: req.body.email,
            password: hashedPassword,
        });



        // Save the user to the database
        await newUser.save();

        // Return the saved user
        return res.json(newUser);
    } catch (error) {
        console.error(error);
        return res.status(500).json({ msg: "An error occurred." });
    }
});

// @route   POST api/login
// @desc    Login a user
// @access  Public

app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    // Find user by username
    User.findOne({ username: username }).then(user => {
        // Check if user exists
        if (!user) {
            return res.status(404).json({ msg: 'Username not found' });
        }

        // Check password
        bcrypt.compare(password, user.password).then(isMatch => {
            if (isMatch) {
                // User matched
                // Create JWT Payload
                const payload = {
                    id: user.id,
                    name: user.name,
                    username: user.username,
                    email: user.email
                };

                // Sign token
                jwt.sign(
                    payload,
                    keys.secretOrKey,
                    {
                        expiresIn: 31556926 // 1 year in seconds
                    },
                    (err, token) => {
                        res.json({
                            success: true,
                            token: 'Bearer ' + token
                        });
                    }
                );
                return res.json(payload);
            } else {
                return res
                    // .status(400)
                    .json({ msg: 'Password incorrect' });
            }
        });
    });
});

app.get("/current-user", (req, res) => {
    const userId = req.query.userId;
    User.findOne({_id: userId})
        .select("-password")
        .then(user => {
            if (!user) {
                return res.status(400).send({
                    message: "User not found"
                });
            }
            res.send(user);
        })
        .catch(() => {
            return res.status(400).send({
                msg: "Error retrieving user information"
            });
        });
});

app.get("/user/:id", async (req, res) => {
    const { id } = req.params;

    try {
        const user = await User.findById(id).select("-password");
        res.json(user);
    } catch (error) {
        res.status(400).json({ msg: "User not found" });
    }
});

app.post('/api/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).send({ error: 'No file uploaded' });
    }

    const collection = db.collection("images");

    // Check if file is an image or gif
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (!allowedTypes.includes(req.file.mimetype)) {
        fs.unlinkSync(req.file.path);
        return res.status(400).send({ error: 'Invalid file type' });
    }


    // Move file to public folder
    const extension = path.extname(req.file.originalname);
    const fileName = `${Date.now()}${extension}`;
    const newPath = path.join(__dirname, 'public', fileName);

    const image = {
        from: req.body.from,
        name: fileName,
        type : req.body.type,
        timestamp: new Date(),
    };

    fs.rename(req.file.path, newPath, (err) => {
        if (err) {
            console.error(err);
            return res.status(500).send({ error: 'Internal Server Error' });
        }
        collection.insertOne(image, (err) => {
            if (err) {
                console.error(err);
                return res.status(500).send("Error storing the image");
            }
        });
        res.send({ success: true, fileUrl: `http://localhost:3000/${fileName}` });
    });
});

function readImages(imageFiles) {
    // const imageFiles = fs.readdirSync('public/');

    const images = [];
    imageFiles.forEach((file) => {
        try {
            const imageUrl = `http://localhost:4000/public/${file}`;
            images.push({ url: imageUrl, name: file });
        } catch (e) {
            console.log(e);
        }
    });
    return images;
}

// Route to get all uploaded images
app.get('/images/:id', (req, res) => {
    const userId = req.params.id;
    const collection = db.collection("images");
    collection.find({ from: `${userId}` },{name:1}).toArray(function(err, docs) {
        if (err) throw err;

        const names = docs.map(doc => doc.name);
        // console.log(names);

        const images = readImages(names);
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        res.setHeader('Content-Type', 'application/json');
        res.json(images);
        // prints an array of all the names where from = 123
    });

});

app.delete('/images/:filename', (req, res) => {
    const filename = req.params.filename;
    const path = `public/${filename}`;
    const collection = db.collection("images");

    // Check if file exists
    if (fs.existsSync(path)) {
        // Delete file
        fs.unlinkSync(path);
        console.log(`${filename} deleted successfully.`);
        collection.deleteOne({name : `${filename}`}, (err) => {
            if (err) {
                console.error(err);
                return res.status(500).send("Error deleting the image");
            }
        });
        res.status(200).send(`${filename} deleted successfully.`);
    } else {
        console.log(`${filename} does not exist.`);
        res.status(404).send(`${filename} does not exist.`);
    }
});



app.listen(port,() => {
    console.log("Server is running on port 4000");
});