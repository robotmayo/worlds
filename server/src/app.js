const {resolve} = require('path');
const nconf = require('nconf');
nconf.file(resolve(__dirname, '../../config.json'));

const express = require('express');
const hbs = require('express-hbs');
const bodyParser = require('body-parser');
const morgan = require('morgan');

const auth = require('./auth');

const app = express();


app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));
app.engine('hbs', hbs.express4({
  partialsDir: resolve(__dirname, '../views/partials')
}));
app.set('view engine', 'hbs');
app.set('views', resolve(__dirname, '../views'));

app.get('/', function(req, res){
  res.render('unauthed-index');
});

auth.init(app);
app.listen(8000);
console.log('App listening at 8000');
