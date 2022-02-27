const passport = require('passport'),
    JwtStrategy = require('passport-jwt').Strategy,
    ExtractJwt = require('passport-jwt').ExtractJwt,
    opts = {};
// uncomment fromAuthHeaderWithScheme to use auth header and token. comment out fromAuthHeaderAsBearerToken
// opts.jwtFromRequest = ExtractJwt.fromAuthHeaderWithScheme('jwt');
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = process.env.SECRET_KEY;

    passport.use(new JwtStrategy(opts,
    function(jwt_payload, done){
        let user = db.find(jwt_payload.id);
        if(user){
            return done(null, user);
        }else{
            return done(null, false);
        }
    }
));

exports.isAuthenticated = passport.authenticate('jwt', {session: false});
exports.secret = opts.secretOrKey;