import passport, { use } from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import argon2 from "argon2";
import { UserModel } from "../models/userModel";


passport.use(
    new LocalStrategy(
        {usernameField: "email", passwordField: "password" },
        async (email, password, done) => {
            try{
                const user = await UserModel.findByEmail(email)
                if (!user) return done(null, false, {message: "User not found"})
                
                const userFound = await argon2.verify(user.paswordHash, password)
                if (!userFound) return done(null, false, {message: "Invalid password"})

                return done (null, user)
            } catch(err) {
                return done(err)
            }
        }
    )
)

passport.serializeUser((user, done) => {
    done(null,user._id)
})

passport.deserializeUser(async (id, done) => {
    try {
        const user = await UserModel.findById(id);
        done (null,user || false)
    } catch(err) {
        done(err)
    }
});

export default passport