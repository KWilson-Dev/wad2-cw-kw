export function requireAuth(req, res, next){
    if (req.isAuthenticated && req.isAuthenticated()) return next();
    return res.redirect("/login");
}

export function requireOrganiser(req,res,next) {
    if (
        req.isAuthenticated &&
        req.isAuthenticated() &&
        req.user &&
        req.user.role === "organiser"
    ) {
        return next();
    }
    return res.status(403).send("FORBIDDEN");
}