const jwt = require('jsonwebtoken');

const secret = "mysecretshhhhhh";

const expiration = "2h";

module.exports = {
    signToken: function ({ username, email, _id }) { // expects user object and will add these properties to the token
        const payload = { username, email, _id }; 

        return jwt.sign({ data: payload }, secret, { expiresIn: expiration }); 
    },

    authMiddleware: function({ req }) {
        let token = req.body.token || req.query.token || req.headers.authorization; 

        // seperate 'bearer' from <tokenvalue>
        if (req.headers.authorization) {
            token = token 
            .split(' ')
            .pop()
            .trim();
        }

        // if no token, return object as is 
        if (!token) {
            return req;
        }

        //if secret on jwt.verify doesnt match the secret that was used with jwt.sign(), object won't be decoded
        try {
            // decode and attach user data to request object 
            const { data } = jwt.verify(token, secret, { maxAge: expiration }); 
            req.user = data; 
        } 
        catch {
            console.log('Invalid token'); 
        }
        // return updated request object 
        return req; 
    }
}