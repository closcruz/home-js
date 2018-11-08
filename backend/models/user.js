import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
const Schema = mongoose.Schema;


const UsersSchema = new Schema({
    username: {
        type: String,
        unique: true,
        required: true
    },
    password: {
        type: String,
        required: true
    },
}, {timestamps: true});

UsersSchema.pre('save', next => {
    if (this.isModified('password') || this.isNew) {
        bcrypt.genSalt(8, (err, salt) => {
            if (err) return next(err);
            bcrypt.hash(user.password, salt, (err, hash) => {
                if (err) return next(err);
                this.password = hash;
                next();
            })
        })
    } else {
        return next();
    }
});

UsersSchema.methods.comparePassword = function (pswrd, cb) {
    bcrypt.compare(pswrd, this.password, (err, isMatch) => {
        if (err) return cb(err);
        return cb(null, isMatch);
    })
};

export default mongoose.model('User', UsersSchema);