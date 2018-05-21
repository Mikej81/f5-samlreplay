const passport = require('passport');
const SamlStrategy = require('passport-saml').Strategy;

passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((user, done) => {
    done(null, user);
});

function initPassportSamlStrategy(strategyOptions, fieldsToExtactFromOkta) {
    passport.use(new SamlStrategy(
        strategyOptions,
        (profile, done) => {
            var user = {};
            fieldsToExtactFromOkta.forEach((paramName) => {
                user[paramName] = profile[paramName];
            });
            return done(null, user);
        }
    ));
}

function initApp(app, passportOptions, appRoutes) {
    app.use(passport.initialize());
    app.use(passport.session());
    const loginRoutePassportMiddleware = passport.authenticate('saml', passportOptions);

    app.post(appRoutes.loginPath, loginRoutePassportMiddleware, (req,res) => {
        res.redirect(passportOptions.successRedirect);
    });

    app.get(appRoutes.loginPath, loginRoutePassportMiddleware);

    app.get(appRoutes.logoutPath, (req, res) => {
        req.session.destroy();
        res.redirect(options.accessDeniedPath);
    });

    app.get(appRoutes.accessDeniedPath, (req, res) => {
        res.status(401);
        res.type('text/html');
        res.end(`You don't have access to this app.<br>Please <a href="${appRoutes.loginPath}">login</a> using Okta.`);
    });
}

module.exports = (app, options) => {
    initPassportSamlStrategy(
        options.SAML.passportOptions,
        options.SAML.propertiesToExtract
        );
    initApp(app, options.passport.options, options.appRoutes);
    return {
        secured: (req, res, next) => {
            if (req.isAuthenticated()) {
                return next();
            }
            console.log('woops, not logged in, go to', options.passport.options.failureRedirect);
            res.redirect(options.passport.options.failureRedirect);
        }
    }
};
