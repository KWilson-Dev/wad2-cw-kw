import { Router } from "express";
import argon2 from "argon2";
import passport from "../auth/passport.js";
import { UserModel } from "../models/userModel.js";

const router = Router();

router.get("/login", (req, res) => {
    res.render("login");
});

router.get("/register", (req, res) => {
    res.render("register");
});

router.post("/register", async (req, res) => {
    try {
        const {name, email, password} = req.body

        if (!name || !email || !password) {
            return res.status(400).send("Please enter all fields")
        }

        const existingEmail = await UserModel.findByEmail(email)
        if (existingEmail) {
             return res.status(400).send("Account already exists")
        }

        const passwordHash = await argon2.hash(password)

        const user = await UserModel.create({
            name,
            email,
            role: "student",
            passwordHash
        });

        req.login(user,(err) => {
            if (err) return res.status(500).send("Auto-login failed, please try again");
            return res.redirect("/");
        }); 
    } catch (err) {
        return res.status(500).send("Registration Failed")
    } 
});

router.post(
    "/login", 
    passport.authenticate ("local", {
        failureRedirect: "/login"
    }),
    (req,res) => {
         res.redirect("/")
    }     
);

router.post("/logout", (res, req, next) => {
    req.logout((err) => {
    if (err) return next(err);
    req.session.destroy(() => {
        res.redirect("/")
        });
    });
});

export default router