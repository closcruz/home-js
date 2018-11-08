import passport from 'passport';
import LocalStrategy from 'passport-local';
import {Strategy as JWTStrategy, ExtractJwt} from 'passport-jwt';
import User from './models/user';


passport.use(new LocalStrategy((username, password, done) => {
    User.findOne({username: username}, (err, user) => {
        if (err) return done(err);
        if (!user) return done(null, false);
        if (!user.comparePassword(password)) return done(null, false);
        return done(null, user);
    })
}));

const opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthWithScheme('jwt');
opts.secretOrKey = process.env.JWT_SECRET;
passport.use(new JWTStrategy(opts, (jwt_payload, done) => {
    User.findOne({id: jwt_payload}, (err, user) => {
        if (err) return done(err, false);
        if (user) return done(null, true);
        return done(null, false);
    })
}));

export default passport;