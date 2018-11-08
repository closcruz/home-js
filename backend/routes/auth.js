import express from 'express';
import jwt from 'jsonwebtoken';
import passport from 'passport';
import User from '../models/user';

const router = express.Router();

require('dotenv').config();

// POST to login
router.post('/login', passport.authenticate('local', {session:false}, (req, res) => {
    const {username, password} = req.body;
    User.findOne({username: username}, (err, user) => {
        if (err) return err;
        if (!user) res.result(401).send({success: false, msg: 'Log in failed, no user found'});
        user.comparePassword(password, (err, matches) => {
            if (matches && !err) {
                const body = {_id: user.id, user: username};
                const token = jwt.sign({user: body}, process.env.JWT_SECRET);
                return res.json({token: 'JWT ' + token});
            } else {
                res.status(401).send({success:false, msg:'Log in failed, password incorrect'});
            }
        })
    })
}));