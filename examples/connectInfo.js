const udgerParser = require('../')('test/db/udgerdb_v3_test.json');
const http = require('http');

var app = require('connect')();

http.createServer(app).listen(8082, '127.0.0.1');

app.use(function (req, res, next) {

    udgerParser.set({
        ua:req.headers['user-agent'],
        ip:req.headers['x-forwarded-for'] || req.connection.remoteAddress
    });

    const result = udgerParser.parse();

    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(result, null, 4));

    next();
});
