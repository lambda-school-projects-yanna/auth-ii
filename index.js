require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'); // installed this library

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');

const secret = process.env.JWT_SECRET || 'add a third table for many to many relationships';

const server = express();
server.use(helmet());
server.use(express.json());
server.use(cors());

server.get('/api', (req, res) => {
res.send("API running");
});


server.post('/api/register', (req, res) => {
    let user = req.body;
    // generate hash from user's password
    const hash = bcrypt.hashSync(user.password, 10); 
    // override user.password with hash
    user.password = hash;

    Users.add(user)
    .then(newUser => {
      res.status(201).json(newUser);
    })
    .catch(error => {
        res.status(500).json(error);
    });
});

generateToken = (user) => {
    const payload = {
        subject: user.id,
        username: user.username,
        roles: ['Admin']
    };
    const options = {
        expiresIn: '1d'
    };

    return jwt.sign(payload, secret, options);
};

server.post('/api/login', (req, res) => {
    let {username, password} = req.body;
    Users.findBy({username})
    .first()
    .then(user => {
      req.session.user = user;
      if (user && bcrypt.compareSync(password, user.password)) {
        const token = generateToken(user); // new
        res.status(200).json({ 
            message: `Welcome ${user.username}! We've got a token for you.`,
            token,
            secret,
            roles: token.roles
        });
      } else {
        res.status(401).json({ message: 'You shall NOT pass with THOSE credentials!' });
      }
    })
    .catch(error => {
        res.status(500).json(error);
    });
});





const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n**** Running on port ${port} ****\n`));

//